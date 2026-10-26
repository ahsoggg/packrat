//! Recovery data for `.prat`: Reed-Solomon parity over everything before it (header, blocks, index), so that
//! damaged areas of the file can be rebuilt. The protected bytes are cut into equal shards, every shard has a CRC,
//! and parity shards can replace as many damaged shards as there are intact parity shards.
//!
//! Layout, between the index and the footer:
//!
//! ```text
//! HeaderA (104)   magic, version, shard size, K, M, protected length, copy of the footer, CRC
//! TableA          K data CRCs, M parity CRCs, CRC of the table
//! TableB          the same again
//! parity          M shards
//! HeaderB (104)   a copy of HeaderA, at a fixed distance from the end of the file
//! ```
//!
//! An older reader skips it: the footer still says where the index is, and the index ends before this section.

use super::format::*;
use crate::error::{Error, Result};
use crate::source::FileSource;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const REC_MAGIC: [u8; 8] = *b"PRATREC\x01";
const REC_HEADER_LEN: usize = 104;
const REC_VERSION: u32 = 1;
const MAX_DATA_SHARDS: u64 = 16384;
const MIN_SHARD: u64 = 4 << 10;
const MAX_SHARD: u64 = 64 << 10;
/// Repair holds the protected bytes and the decoder's work area in memory; refuse what clearly cannot fit.
const MAX_REPAIR_BYTES: u64 = 3 << 30;

fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Corrupt(msg.into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub shard: u32,
    pub data_shards: u32,
    pub parity_shards: u32,
    pub protected: u64,
}

impl Plan {
    /// `percent` of the protected size is spent on parity (1..=100, rounded up to whole shards).
    pub fn new(protected: u64, percent: u32) -> Result<Self> {
        if !(1..=100).contains(&percent) {
            return Err(Error::Other(
                "the recovery amount must be between 1 and 100 percent".into(),
            ));
        }
        // about 256 shards for a small archive (so the percentage means something), 64 KiB for most, and
        // never so small that there are more than MAX_DATA_SHARDS of them
        let shard = (protected / 256)
            .clamp(MIN_SHARD, MAX_SHARD)
            .max(protected.div_ceil(MAX_DATA_SHARDS))
            .next_multiple_of(64);
        let data = protected.div_ceil(shard).max(1);
        let parity = (data * u64::from(percent)).div_ceil(100).clamp(1, 32768);
        if !ReedSolomonEncoder::supports(data as usize, parity as usize) {
            return Err(Error::Other("this archive is too large for recovery data".into()));
        }
        Ok(Self {
            shard: u32::try_from(shard)
                .map_err(|_| Error::Other("this archive is too large for recovery data".into()))?,
            data_shards: data as u32,
            parity_shards: parity as u32,
            protected,
        })
    }

    fn table_len(&self) -> u64 {
        4 * (u64::from(self.data_shards) + u64::from(self.parity_shards)) + 4
    }

    /// Bytes the whole recovery section takes.
    pub fn section_len(&self) -> u64 {
        REC_HEADER_LEN as u64
            + 2 * self.table_len()
            + u64::from(self.parity_shards) * u64::from(self.shard)
            + REC_HEADER_LEN as u64
    }
}

fn encode_header(plan: &Plan, footer: &[u8; FOOTER_LEN]) -> [u8; REC_HEADER_LEN] {
    let mut h = [0u8; REC_HEADER_LEN];
    h[..8].copy_from_slice(&REC_MAGIC);
    h[8..12].copy_from_slice(&REC_VERSION.to_le_bytes());
    h[12..16].copy_from_slice(&plan.shard.to_le_bytes());
    h[16..20].copy_from_slice(&plan.data_shards.to_le_bytes());
    h[20..24].copy_from_slice(&plan.parity_shards.to_le_bytes());
    h[24..32].copy_from_slice(&plan.protected.to_le_bytes());
    h[32..32 + FOOTER_LEN].copy_from_slice(footer);
    let crc = crc32fast::hash(&h[..REC_HEADER_LEN - 4]);
    h[REC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    h
}

fn decode_header(h: &[u8]) -> Result<(Plan, [u8; FOOTER_LEN])> {
    if h.len() < REC_HEADER_LEN || h[..8] != REC_MAGIC {
        return bad("no recovery data here");
    }
    let crc = u32::from_le_bytes(h[REC_HEADER_LEN - 4..REC_HEADER_LEN].try_into().unwrap());
    if crc != crc32fast::hash(&h[..REC_HEADER_LEN - 4]) {
        return bad("the recovery header is damaged");
    }
    if u32::from_le_bytes(h[8..12].try_into().unwrap()) != REC_VERSION {
        return Err(Error::Unsupported("recovery data of a newer version".into()));
    }
    let plan = Plan {
        shard: u32::from_le_bytes(h[12..16].try_into().unwrap()),
        data_shards: u32::from_le_bytes(h[16..20].try_into().unwrap()),
        parity_shards: u32::from_le_bytes(h[20..24].try_into().unwrap()),
        protected: u64::from_le_bytes(h[24..32].try_into().unwrap()),
    };
    // the numbers must be ones a writer could have produced, whatever the file says
    let sane = plan.shard >= 64
        && plan.shard.is_multiple_of(64)
        && plan.data_shards >= 1
        && u64::from(plan.data_shards) <= MAX_DATA_SHARDS * 2
        && plan.parity_shards >= 1
        && plan.parity_shards <= 32768
        && u64::from(plan.data_shards) * u64::from(plan.shard) >= plan.protected
        && u64::from(plan.data_shards) * u64::from(plan.shard) - plan.protected < u64::from(plan.shard);
    if !sane {
        return bad("the recovery header has impossible numbers");
    }
    Ok((plan, h[32..32 + FOOTER_LEN].try_into().unwrap()))
}

fn encode_table(data: &[u32], parity: &[u32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(4 * (data.len() + parity.len()) + 4);
    for c in data.iter().chain(parity) {
        t.extend_from_slice(&c.to_le_bytes());
    }
    let crc = crc32fast::hash(&t);
    t.extend_from_slice(&crc.to_le_bytes());
    t
}

fn decode_table(t: &[u8], plan: &Plan) -> Option<(Vec<u32>, Vec<u32>)> {
    if t.len() as u64 != plan.table_len() {
        return None;
    }
    let (body, crc) = t.split_at(t.len() - 4);
    if u32::from_le_bytes(crc.try_into().unwrap()) != crc32fast::hash(body) {
        return None;
    }
    let all: Vec<u32> = body.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
    let (d, p) = all.split_at(plan.data_shards as usize);
    Some((d.to_vec(), p.to_vec()))
}

fn read_footer(f: &mut File, len: u64) -> Result<Footer> {
    if len < HEADER_LEN + FOOTER_LEN as u64 {
        return bad("the file is too short to be a .prat archive");
    }
    let mut b = [0u8; FOOTER_LEN];
    f.seek(SeekFrom::Start(len - FOOTER_LEN as u64))?;
    f.read_exact(&mut b)?;
    Footer::decode(&b)
}

/// Appends recovery data (`percent` of the archive size) to a finished `.prat` file.
pub fn add_recovery(path: &Path, percent: u32) -> Result<Plan> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    let len = f.metadata()?.len();
    let footer = read_footer(&mut f, len)?;
    let protected = footer
        .index_offset
        .checked_add(footer.index_clen)
        .filter(|&p| p + FOOTER_LEN as u64 == len)
        .ok_or_else(|| Error::Other("this archive already has recovery data (or an unexpected layout)".into()))?;
    let plan = Plan::new(protected, percent)?;
    let footer_bytes = footer.encode();

    let (k, m, s) = (
        plan.data_shards as usize,
        plan.parity_shards as usize,
        plan.shard as usize,
    );
    let mut enc = ReedSolomonEncoder::new(k, m, s).map_err(|e| Error::Other(format!("recovery: {e}")))?;
    let mut data_crcs = Vec::with_capacity(k);
    let mut buf = vec![0u8; s];
    f.seek(SeekFrom::Start(0))?;
    let mut left = protected;
    for _ in 0..k {
        let n = left.min(s as u64) as usize;
        f.read_exact(&mut buf[..n])?;
        buf[n..].fill(0);
        left -= n as u64;
        data_crcs.push(crc32fast::hash(&buf));
        enc.add_original_shard(&buf)
            .map_err(|e| Error::Other(format!("recovery: {e}")))?;
    }
    let result = enc.encode().map_err(|e| Error::Other(format!("recovery: {e}")))?;
    let parity: Vec<&[u8]> = result.recovery_iter().collect();
    let parity_crcs: Vec<u32> = parity.iter().map(|p| crc32fast::hash(p)).collect();

    let header = encode_header(&plan, &footer_bytes);
    let table = encode_table(&data_crcs, &parity_crcs);
    f.seek(SeekFrom::Start(protected))?;
    f.write_all(&header)?;
    f.write_all(&table)?;
    f.write_all(&table)?;
    for p in &parity {
        f.write_all(p)?;
    }
    f.write_all(&header)?;
    f.write_all(&footer_bytes)?;
    f.set_len(protected + plan.section_len() + FOOTER_LEN as u64)?;
    f.flush()?;
    Ok(plan)
}

/// Where the recovery section starts, found without trusting the footer when necessary.
fn locate(f: &mut File, len: u64) -> Result<(u64, Plan, [u8; FOOTER_LEN])> {
    let try_at = |f: &mut File, at: u64| -> Option<(u64, Plan, [u8; FOOTER_LEN])> {
        let mut h = [0u8; REC_HEADER_LEN];
        f.seek(SeekFrom::Start(at)).ok()?;
        f.read_exact(&mut h).ok()?;
        let (plan, foot) = decode_header(&h).ok()?;
        // The section must end where the footer starts. Header A sits where the protected bytes end, header B
        // sits in front of the footer; either one tells us where the section is.
        let is_a = plan.protected == at;
        let is_b = at + (REC_HEADER_LEN + FOOTER_LEN) as u64 == len;
        ((is_a || is_b) && plan.protected + plan.section_len() + FOOTER_LEN as u64 == len).then_some((
            plan.protected,
            plan,
            foot,
        ))
    };
    // 1. through the footer
    if let Ok(footer) = read_footer(f, len)
        && let Some(p) = footer.index_offset.checked_add(footer.index_clen)
        && let Some(found) = try_at(f, p)
    {
        return Ok(found);
    }
    // 2. through the copy of the header in front of the footer
    if len >= (REC_HEADER_LEN + FOOTER_LEN) as u64
        && let Some(found) = try_at(f, len - (REC_HEADER_LEN + FOOTER_LEN) as u64)
    {
        return Ok(found);
    }
    // 3. scan for the magic
    let mut pos = 0u64;
    let mut win = vec![0u8; (4 << 20) + 8];
    while pos < len {
        f.seek(SeekFrom::Start(pos))?;
        let n = f.read(&mut win)?;
        if n == 0 {
            break;
        }
        let mut from = 0;
        while let Some(i) = win[from..n].windows(8).position(|w| w == REC_MAGIC) {
            if let Some(found) = try_at(f, pos + (from + i) as u64) {
                return Ok(found);
            }
            from += i + 1;
        }
        if n <= 8 {
            break;
        }
        pos += (n - 8) as u64;
    }
    bad("no usable recovery data was found in this archive")
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairReport {
    pub shards: u32,
    /// Damaged shards that were rebuilt.
    pub repaired: u32,
    /// The footer was rewritten from its copy.
    pub footer_rewritten: bool,
    /// The recovery data itself was damaged and has been generated again.
    pub recovery_rewritten: bool,
    pub shard_bytes: u32,
}

/// Does the archive have recovery data, and how much? `None` for archives without any.
pub fn recovery_info(path: &Path) -> Option<Plan> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    locate(&mut f, len).ok().map(|(_, plan, _)| plan)
}

/// Writes a repaired copy of `src` to `dst` (which must not exist); `src` is never changed.
pub fn repair(src: &Path, dst: &Path) -> Result<RepairReport> {
    if dst.exists() {
        return Err(Error::Other(format!("'{}' already exists", dst.display())));
    }
    let result = repair_into(src, dst);
    if result.is_err() {
        let _ = fs::remove_file(dst);
    }
    result
}

fn repair_into(src: &Path, dst: &Path) -> Result<RepairReport> {
    let len = fs::metadata(src)?.len();
    {
        let mut probe = File::open(src)?;
        let (_, plan, _) = locate(&mut probe, len)?;
        if plan.protected > MAX_REPAIR_BYTES {
            return Err(Error::Unsupported(format!(
                "repairing an archive this large ({} GiB) needs more memory than is safe to use",
                plan.protected >> 30
            )));
        }
    }
    fs::copy(src, dst)?;
    let mut f = OpenOptions::new().read(true).write(true).open(dst)?;
    let (start, plan, footer_copy) = locate(&mut f, len)?;
    let (k, m, s) = (
        plan.data_shards as usize,
        plan.parity_shards as usize,
        plan.shard as usize,
    );

    // the CRC tables: either copy will do
    let tab_len = plan.table_len();
    let mut ta = vec![0u8; tab_len as usize];
    let mut tb = vec![0u8; tab_len as usize];
    f.seek(SeekFrom::Start(start + REC_HEADER_LEN as u64))?;
    f.read_exact(&mut ta)?;
    f.read_exact(&mut tb)?;
    let (data_crcs, parity_crcs) = decode_table(&ta, &plan)
        .or_else(|| decode_table(&tb, &plan))
        .ok_or_else(|| Error::Corrupt("both copies of the recovery checksums are damaged".into()))?;

    // find the damaged shards of the protected area
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k);
    let mut damaged: Vec<usize> = Vec::new();
    f.seek(SeekFrom::Start(0))?;
    let mut left = plan.protected;
    for (i, &want) in data_crcs.iter().enumerate() {
        let n = left.min(s as u64) as usize;
        let mut buf = vec![0u8; s];
        let got = f.read(&mut buf[..n]).unwrap_or(0);
        let mut filled = got;
        while filled < n {
            match f.read(&mut buf[filled..n]) {
                Ok(0) | Err(_) => break,
                Ok(x) => filled += x,
            }
        }
        left -= n as u64;
        if crc32fast::hash(&buf) != want {
            damaged.push(i);
        }
        shards.push(buf);
    }

    let mut report = RepairReport {
        shards: k as u32,
        shard_bytes: plan.shard,
        ..Default::default()
    };
    // intact parity shards (every one is checked: a damaged one means the recovery data needs refreshing)
    let parity_at = start + REC_HEADER_LEN as u64 + 2 * tab_len;
    let mut good_parity: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut parity_damaged = false;
    for (j, &want) in parity_crcs.iter().enumerate() {
        let mut p = vec![0u8; s];
        f.seek(SeekFrom::Start(parity_at + (j * s) as u64))?;
        if f.read_exact(&mut p).is_ok() && crc32fast::hash(&p) == want {
            if good_parity.len() < damaged.len() {
                good_parity.push((j, p));
            }
        } else {
            parity_damaged = true;
        }
    }
    if !damaged.is_empty() {
        if good_parity.len() < damaged.len() {
            return Err(Error::Corrupt(format!(
                "{} damaged areas of {} KiB, but only {} intact repair blocks: this archive cannot be repaired",
                damaged.len(),
                s >> 10,
                good_parity.len()
            )));
        }
        let mut dec = ReedSolomonDecoder::new(k, m, s).map_err(|e| Error::Other(format!("recovery: {e}")))?;
        for (i, sh) in shards.iter().enumerate() {
            if !damaged.contains(&i) {
                dec.add_original_shard(i, sh)
                    .map_err(|e| Error::Other(format!("recovery: {e}")))?;
            }
        }
        for (j, p) in &good_parity {
            dec.add_recovery_shard(*j, p)
                .map_err(|e| Error::Other(format!("recovery: {e}")))?;
        }
        let restored = dec.decode().map_err(|e| Error::Other(format!("recovery: {e}")))?;
        for (i, data) in restored.restored_original_iter() {
            if crc32fast::hash(data) != data_crcs[i] {
                return Err(Error::Corrupt("the rebuilt data does not match its checksum".into()));
            }
            let at = (i * s) as u64;
            let n = (plan.protected - at).min(s as u64) as usize;
            f.seek(SeekFrom::Start(at))?;
            f.write_all(&data[..n])?;
            shards[i].copy_from_slice(data);
            report.repaired += 1;
        }
        if report.repaired as usize != damaged.len() {
            return Err(Error::Corrupt("not every damaged area could be rebuilt".into()));
        }
    }

    // the recovery data: generate it again when a parity shard, a table or a header is damaged
    let header = encode_header(&plan, &footer_copy);
    let mut header_a = [0u8; REC_HEADER_LEN];
    let mut header_b = [0u8; REC_HEADER_LEN];
    f.seek(SeekFrom::Start(start))?;
    f.read_exact(&mut header_a)?;
    f.seek(SeekFrom::Start(len - (REC_HEADER_LEN + FOOTER_LEN) as u64))?;
    f.read_exact(&mut header_b)?;
    let tables_ok = ta == tb && decode_table(&ta, &plan).is_some();
    if parity_damaged || !tables_ok || header_a != header || header_b != header {
        let mut enc = ReedSolomonEncoder::new(k, m, s).map_err(|e| Error::Other(format!("recovery: {e}")))?;
        for sh in &shards {
            enc.add_original_shard(sh)
                .map_err(|e| Error::Other(format!("recovery: {e}")))?;
        }
        let result = enc.encode().map_err(|e| Error::Other(format!("recovery: {e}")))?;
        let parity: Vec<&[u8]> = result.recovery_iter().collect();
        let new_parity_crcs: Vec<u32> = parity.iter().map(|p| crc32fast::hash(p)).collect();
        let table = encode_table(&data_crcs, &new_parity_crcs);
        f.seek(SeekFrom::Start(start))?;
        f.write_all(&header)?;
        f.write_all(&table)?;
        f.write_all(&table)?;
        for p in &parity {
            f.write_all(p)?;
        }
        f.write_all(&header)?;
        report.recovery_rewritten = true;
    }

    // the footer: rewrite it from the copy when it does not read
    let mut cur = [0u8; FOOTER_LEN];
    f.seek(SeekFrom::Start(len - FOOTER_LEN as u64))?;
    f.read_exact(&mut cur)?;
    if cur != footer_copy {
        f.seek(SeekFrom::Start(len - FOOTER_LEN as u64))?;
        f.write_all(&footer_copy)?;
        report.footer_rewritten = true;
    }
    f.flush()?;
    drop(f);

    // the result must open as an archive
    let src_check = std::sync::Arc::new(FileSource::open(dst)?);
    super::read::PratArchive::from_source(src_check)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_cover_the_data_and_stay_within_the_codec_limits() {
        for (protected, percent) in [
            (1u64, 1u32),
            (1000, 5),
            (64 << 10, 10),
            (10 << 20, 3),
            (5 << 30, 10),
            (100 << 30, 100),
        ] {
            let p = Plan::new(protected, percent).unwrap();
            assert!(u64::from(p.data_shards) * u64::from(p.shard) >= protected);
            assert!(u64::from(p.data_shards) <= MAX_DATA_SHARDS);
            assert!(p.parity_shards >= 1 && p.parity_shards <= 32768);
            assert_eq!(p.shard % 64, 0);
            assert!(ReedSolomonEncoder::supports(
                p.data_shards as usize,
                p.parity_shards as usize
            ));
        }
        assert!(Plan::new(1000, 0).is_err());
        assert!(Plan::new(1000, 101).is_err());
    }

    #[test]
    fn parity_grows_with_the_percentage() {
        let a = Plan::new(100 << 20, 2).unwrap();
        let b = Plan::new(100 << 20, 10).unwrap();
        assert!(b.parity_shards > a.parity_shards);
        // roughly the asked share, never less
        assert!(u64::from(b.parity_shards) * 100 >= u64::from(b.data_shards) * 10);
    }

    #[test]
    fn headers_and_tables_roundtrip_and_reject_damage() {
        let plan = Plan::new(5 << 20, 5).unwrap();
        let foot = Footer {
            index_offset: 5 << 20,
            index_clen: 0,
            index_ulen: 0,
            index_hash: [4; 32],
        }
        .encode();
        let h = encode_header(&plan, &foot);
        assert_eq!(decode_header(&h).unwrap(), (plan, foot));
        let mut bad_h = h;
        bad_h[13] ^= 1;
        assert!(decode_header(&bad_h).is_err());
        // impossible numbers with a valid CRC are still refused
        let mut crazy = plan;
        crazy.data_shards = 1;
        assert!(decode_header(&encode_header(&crazy, &foot)).is_err());

        let d: Vec<u32> = (0..plan.data_shards).collect();
        let p: Vec<u32> = (100..100 + plan.parity_shards).collect();
        let t = encode_table(&d, &p);
        assert_eq!(decode_table(&t, &plan), Some((d, p)));
        let mut t2 = t.clone();
        t2[5] ^= 1;
        assert!(decode_table(&t2, &plan).is_none());
        assert!(decode_table(&t[..t.len() - 1], &plan).is_none());
    }
}
