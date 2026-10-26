//! Recovery data for ordinary ZIP files. The result is still a ZIP that WinRAR, 7-Zip, Explorer and every other
//! reader opens: those read a ZIP through the central directory at the end and never look at what lies between the
//! last file and that directory, so the recovery section goes there.
//!
//! ```text
//! [ file data ... ][ HeaderA | tail copy | TableA | TableB | parity | HeaderB ][ central directory ... EOCD ]
//!   protected                  recovery section (80-byte headers)                tail, offsets moved
//! ```
//!
//! The protected bytes are everything in front of the section. The tail (central directory and the end records)
//! is kept as a copy inside the section, so a damaged directory can be rebuilt too. Moving the directory back by
//! the size of the section changes the offsets in the end records (`patch_tail`), nothing else: the entries point
//! at local headers, and those do not move.

use super::recover::{
    Plan, RepairReport, decode_table, encode_parity, encode_shards, encode_table, read_good_parity, read_shards,
    reconstruct,
};
use crate::error::{Error, Result};
use crate::source::FileSource;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const ZMAGIC: [u8; 8] = *b"PRATZRC\x01";
const ZHDR: usize = 80;
const ZVERSION: u32 = 1;
const EOCD_SIG: [u8; 4] = *b"PK\x05\x06";
const Z64_LOCATOR_SIG: [u8; 4] = *b"PK\x06\x07";
const Z64_EOCD_SIG: [u8; 4] = *b"PK\x06\x06";
/// The end records of a ZIP are never larger than this (a 64 KiB comment plus the fixed parts).
const END_WINDOW: u64 = 65535 + 22 + 20 + 56 + 64;
const MAX_TAIL: u64 = 256 << 20;
const MAX_REPAIR_BYTES: u64 = 3 << 30;

fn bad<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Corrupt(msg.into()))
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Position of the end-of-central-directory record in `b`, which must end exactly at the end of the file.
fn find_eocd(b: &[u8]) -> Option<usize> {
    let last = b.len().checked_sub(22)?;
    (0..=last).rev().take(65535 + 1).find(|&i| {
        b[i..i + 4] == EOCD_SIG && i + 22 + usize::from(u16::from_le_bytes([b[i + 20], b[i + 21]])) == b.len()
    })
}

/// Moves the offsets stored in the end records by `delta`. `tail` starts at the central directory, and
/// `tail_start` is where that directory is in the file whose offsets the tail currently holds.
fn patch_tail(tail: &mut [u8], tail_start: u64, delta: i64) -> Result<()> {
    let eocd = find_eocd(tail).ok_or_else(|| Error::Corrupt("the end of the ZIP archive is damaged".into()))?;
    let shift = |v: u64| -> Result<u64> {
        v.checked_add_signed(delta)
            .ok_or_else(|| Error::Corrupt("an offset in the ZIP end records is out of range".into()))
    };
    let off32 = le32(tail, eocd + 16);
    if off32 != u32::MAX {
        let moved = u32::try_from(shift(u64::from(off32))?)
            .ok()
            .filter(|&v| v != u32::MAX)
            .ok_or_else(|| {
                Error::Unsupported("this ZIP archive needs ZIP64 before recovery data can be added to it".into())
            })?;
        tail[eocd + 16..eocd + 20].copy_from_slice(&moved.to_le_bytes());
    }
    if eocd >= 20 && tail[eocd - 20..eocd - 16] == Z64_LOCATOR_SIG {
        let loc = eocd - 20;
        let record_abs = le64(tail, loc + 8);
        let in_tail = record_abs
            .checked_sub(tail_start)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|&v| v + 56 <= loc && tail[v..v + 4] == Z64_EOCD_SIG)
            .ok_or_else(|| Error::Corrupt("the ZIP64 end record is not where the locator says".into()))?;
        let cd_off = shift(le64(tail, in_tail + 48))?;
        tail[in_tail + 48..in_tail + 56].copy_from_slice(&cd_off.to_le_bytes());
        tail[loc + 8..loc + 16].copy_from_slice(&shift(record_abs)?.to_le_bytes());
    }
    Ok(())
}

/// Absolute offset of the central directory, read from the end records of the file.
fn central_directory_offset(f: &mut File, len: u64) -> Result<u64> {
    let take = len.min(END_WINDOW);
    let mut win = vec![0u8; take as usize];
    f.seek(SeekFrom::Start(len - take))?;
    f.read_exact(&mut win)?;
    let eocd = find_eocd(&win).ok_or_else(|| Error::Corrupt("this is not a ZIP archive (no end record)".into()))?;
    let off32 = le32(&win, eocd + 16);
    if off32 != u32::MAX {
        return Ok(u64::from(off32));
    }
    if eocd < 20 || win[eocd - 20..eocd - 16] != Z64_LOCATOR_SIG {
        return bad("the ZIP64 locator is missing");
    }
    let record = le64(&win, eocd - 20 + 8);
    let mut rec = [0u8; 56];
    f.seek(SeekFrom::Start(record))?;
    f.read_exact(&mut rec)?;
    if rec[..4] != Z64_EOCD_SIG {
        return bad("the ZIP64 end record is damaged");
    }
    Ok(le64(&rec, 48))
}

#[derive(Clone, Copy, Debug)]
struct ZHeader {
    plan: Plan,
    tail_len: u64,
    /// CRC-32 of the tail in its original form (offsets as they were before the section was inserted).
    tail_crc: u32,
}

impl ZHeader {
    fn encode(&self) -> [u8; ZHDR] {
        let mut h = [0u8; ZHDR];
        h[..8].copy_from_slice(&ZMAGIC);
        h[8..12].copy_from_slice(&ZVERSION.to_le_bytes());
        h[12..16].copy_from_slice(&self.plan.shard.to_le_bytes());
        h[16..20].copy_from_slice(&self.plan.data_shards.to_le_bytes());
        h[20..24].copy_from_slice(&self.plan.parity_shards.to_le_bytes());
        h[24..32].copy_from_slice(&self.plan.protected.to_le_bytes());
        h[32..40].copy_from_slice(&self.tail_len.to_le_bytes());
        h[40..44].copy_from_slice(&self.tail_crc.to_le_bytes());
        let crc = crc32fast::hash(&h[..ZHDR - 4]);
        h[ZHDR - 4..].copy_from_slice(&crc.to_le_bytes());
        h
    }

    fn decode(h: &[u8]) -> Option<Self> {
        if h.len() < ZHDR || h[..8] != ZMAGIC || le32(h, ZHDR - 4) != crc32fast::hash(&h[..ZHDR - 4]) {
            return None;
        }
        if le32(h, 8) != ZVERSION {
            return None;
        }
        let plan = Plan {
            shard: le32(h, 12),
            data_shards: le32(h, 16),
            parity_shards: le32(h, 20),
            protected: le64(h, 24),
        };
        let tail_len = le64(h, 32);
        (plan.is_sane() && (22..=MAX_TAIL).contains(&tail_len)).then_some(Self {
            plan,
            tail_len,
            tail_crc: le32(h, 40),
        })
    }

    /// Bytes between the protected data and the (moved) central directory.
    fn blob_len(&self) -> u64 {
        2 * ZHDR as u64
            + self.tail_len
            + 2 * self.plan.table_len()
            + u64::from(self.plan.parity_shards) * u64::from(self.plan.shard)
    }

    fn parity_at(&self) -> u64 {
        self.plan.protected + ZHDR as u64 + self.tail_len + 2 * self.plan.table_len()
    }
}

/// The recovery section, ready to write: everything that goes in front of the moved central directory.
fn build_blob(zh: &ZHeader, tail: &[u8], data_crcs: &[u32], parity: &[Vec<u8>]) -> Vec<u8> {
    let parity_crcs: Vec<u32> = parity.iter().map(|p| crc32fast::hash(p)).collect();
    let table = encode_table(data_crcs, &parity_crcs);
    let header = zh.encode();
    let mut blob = Vec::with_capacity(zh.blob_len() as usize);
    blob.extend_from_slice(&header);
    blob.extend_from_slice(tail);
    blob.extend_from_slice(&table);
    blob.extend_from_slice(&table);
    for p in parity {
        blob.extend_from_slice(p);
    }
    blob.extend_from_slice(&header);
    blob
}

/// Adds recovery data (`percent` of the size) to a finished ZIP file.
pub fn add_recovery(path: &Path, percent: u32) -> Result<Plan> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    let len = f.metadata()?.len();
    let cd = central_directory_offset(&mut f, len)?;
    if cd == 0 || cd >= len {
        return Err(Error::Other("this ZIP archive has no files to protect".into()));
    }
    if cd >= ZHDR as u64 {
        let mut probe = [0u8; 8];
        f.seek(SeekFrom::Start(cd - ZHDR as u64))?;
        f.read_exact(&mut probe)?;
        if probe == ZMAGIC {
            return Err(Error::Other("this archive already has recovery data".into()));
        }
    }
    let tail_len = len - cd;
    if tail_len > MAX_TAIL {
        return Err(Error::Unsupported(
            "the central directory of this ZIP archive is too large".into(),
        ));
    }
    let mut tail = vec![0u8; tail_len as usize];
    f.seek(SeekFrom::Start(cd))?;
    f.read_exact(&mut tail)?;

    let plan = Plan::new(cd, percent)?;
    let (data_crcs, parity) = encode_shards(&mut f, &plan)?;
    let zh = ZHeader {
        plan,
        tail_len,
        tail_crc: crc32fast::hash(&tail),
    };
    let blob = build_blob(&zh, &tail, &data_crcs, &parity);
    let mut moved = tail;
    patch_tail(&mut moved, cd, blob.len() as i64)?;
    f.seek(SeekFrom::Start(cd))?;
    f.write_all(&blob)?;
    f.write_all(&moved)?;
    f.set_len(cd + blob.len() as u64 + tail_len)?;
    f.flush()?;
    Ok(plan)
}

/// Finds the recovery section: through the end records when they are intact, otherwise by scanning for a header.
fn locate(f: &mut File, len: u64) -> Result<ZHeader> {
    let check = |f: &mut File, at: u64| -> Option<ZHeader> {
        let mut h = [0u8; ZHDR];
        f.seek(SeekFrom::Start(at)).ok()?;
        f.read_exact(&mut h).ok()?;
        let zh = ZHeader::decode(&h)?;
        let is_a = at == zh.plan.protected;
        let is_b = at + ZHDR as u64 + zh.tail_len == len;
        ((is_a || is_b) && zh.plan.protected + zh.blob_len() + zh.tail_len == len).then_some(zh)
    };
    if let Ok(cd) = central_directory_offset(f, len)
        && cd >= ZHDR as u64
        && let Some(zh) = check(f, cd - ZHDR as u64)
    {
        return Ok(zh);
    }
    let mut pos = 0u64;
    let mut win = vec![0u8; (4 << 20) + 8];
    while pos < len {
        f.seek(SeekFrom::Start(pos))?;
        let n = f.read(&mut win)?;
        if n == 0 {
            break;
        }
        let mut from = 0;
        while let Some(i) = win[from..n].windows(8).position(|w| w == ZMAGIC) {
            if let Some(zh) = check(f, pos + (from + i) as u64) {
                return Ok(zh);
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

/// Does the ZIP file have recovery data from Packrat?
pub fn recovery_info(path: &Path) -> Option<Plan> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    locate(&mut f, len).ok().map(|zh| zh.plan)
}

/// Writes a repaired copy of the ZIP file `src` to `dst` (which must not exist); `src` is never changed.
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
        let zh = locate(&mut probe, len)?;
        if zh.plan.protected > MAX_REPAIR_BYTES {
            return Err(Error::Unsupported(format!(
                "repairing an archive this large ({} GiB) needs more memory than is safe to use",
                zh.plan.protected >> 30
            )));
        }
    }
    fs::copy(src, dst)?;
    let mut f = OpenOptions::new().read(true).write(true).open(dst)?;
    let zh = locate(&mut f, len)?;
    let plan = zh.plan;
    let start = plan.protected;
    let blob_len = zh.blob_len();

    let tab_len = plan.table_len() as usize;
    let mut ta = vec![0u8; tab_len];
    let mut tb = vec![0u8; tab_len];
    f.seek(SeekFrom::Start(start + ZHDR as u64 + zh.tail_len))?;
    f.read_exact(&mut ta)?;
    f.read_exact(&mut tb)?;
    let (data_crcs, parity_crcs) = decode_table(&ta, &plan)
        .or_else(|| decode_table(&tb, &plan))
        .ok_or_else(|| Error::Corrupt("both copies of the recovery checksums are damaged".into()))?;

    let (mut shards, damaged) = read_shards(&mut f, &plan, &data_crcs)?;
    let (good_parity, _) = read_good_parity(&mut f, zh.parity_at(), &plan, &parity_crcs, damaged.len())?;
    let mut report = RepairReport {
        shards: plan.data_shards,
        shard_bytes: plan.shard,
        ..Default::default()
    };
    report.repaired = reconstruct(&mut f, &plan, &mut shards, &damaged, &good_parity, &data_crcs)?;

    // the tail: the copy inside the section, or the live directory moved back to its original offsets
    let mut tail = vec![0u8; zh.tail_len as usize];
    f.seek(SeekFrom::Start(start + ZHDR as u64))?;
    f.read_exact(&mut tail)?;
    if crc32fast::hash(&tail) != zh.tail_crc {
        f.seek(SeekFrom::Start(start + blob_len))?;
        f.read_exact(&mut tail)?;
        let live_ok = patch_tail(&mut tail, start + blob_len, -(blob_len as i64)).is_ok();
        if !live_ok || crc32fast::hash(&tail) != zh.tail_crc {
            return Err(Error::Corrupt(
                "both copies of the ZIP central directory are damaged".into(),
            ));
        }
    }

    // everything after the protected bytes is regenerated from the shards and the tail
    let parity = encode_parity(&plan, &shards)?;
    let blob = build_blob(&zh, &tail, &data_crcs, &parity);
    let mut moved = tail;
    patch_tail(&mut moved, start, blob_len as i64)?;
    let mut now = vec![0u8; (blob_len + zh.tail_len) as usize];
    f.seek(SeekFrom::Start(start))?;
    f.read_exact(&mut now)?;
    let (now_blob, now_tail) = now.split_at(blob_len as usize);
    report.recovery_rewritten = now_blob != blob.as_slice();
    report.footer_rewritten = now_tail != moved.as_slice();
    if report.recovery_rewritten || report.footer_rewritten {
        f.seek(SeekFrom::Start(start))?;
        f.write_all(&blob)?;
        f.write_all(&moved)?;
    }
    f.flush()?;
    drop(f);

    // the result must open as a ZIP archive
    crate::zip::ZipArchive::from_source(std::sync::Arc::new(FileSource::open(dst)?))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// central directory stand-in + ZIP64 end record + locator + end record, with the offsets of a file in which
    /// the directory starts at `cd`.
    fn tail(cd: u64, zip64: bool) -> Vec<u8> {
        let mut t = vec![0x11u8; 100]; // pretend central directory
        let record_at = cd + t.len() as u64;
        if zip64 {
            let mut rec = vec![0u8; 56];
            rec[..4].copy_from_slice(&Z64_EOCD_SIG);
            rec[48..56].copy_from_slice(&cd.to_le_bytes());
            t.extend(rec);
            let mut loc = vec![0u8; 20];
            loc[..4].copy_from_slice(&Z64_LOCATOR_SIG);
            loc[8..16].copy_from_slice(&record_at.to_le_bytes());
            t.extend(loc);
        }
        let mut e = vec![0u8; 22];
        e[..4].copy_from_slice(&EOCD_SIG);
        let off32 = if zip64 { u32::MAX } else { cd as u32 };
        e[16..20].copy_from_slice(&off32.to_le_bytes());
        t.extend(e);
        t
    }

    #[test]
    fn plain_end_records_are_moved_and_moved_back() {
        let original = tail(1000, false);
        let mut t = original.clone();
        patch_tail(&mut t, 1000, 5000).unwrap();
        assert_eq!(t, tail(6000, false));
        patch_tail(&mut t, 6000, -5000).unwrap();
        assert_eq!(t, original);
    }

    #[test]
    fn zip64_end_records_are_moved_and_moved_back() {
        let original = tail(7_000_000_000, true);
        let mut t = original.clone();
        patch_tail(&mut t, 7_000_000_000, 123_456).unwrap();
        assert_eq!(t, tail(7_000_123_456, true));
        patch_tail(&mut t, 7_000_123_456, -123_456).unwrap();
        assert_eq!(t, original);
    }

    #[test]
    fn a_plain_archive_that_would_cross_4_gib_asks_for_zip64() {
        let mut t = tail(4_294_000_000, false);
        let err = patch_tail(&mut t, 4_294_000_000, 5_000_000).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
    }

    #[test]
    fn broken_end_records_are_errors() {
        let mut t = tail(1000, true);
        let n = t.len();
        t[n - 22 - 20 + 8] ^= 0x40; // the locator points elsewhere
        assert!(patch_tail(&mut t, 1000, 10).is_err());
        assert!(patch_tail(&mut [1, 2, 3], 0, 1).is_err());
        let mut no_eocd = vec![0u8; 80];
        assert!(patch_tail(&mut no_eocd, 0, 1).is_err());
    }

    #[test]
    fn the_header_roundtrips_and_rejects_damage() {
        let plan = Plan::new(5 << 20, 5).unwrap();
        let zh = ZHeader {
            plan,
            tail_len: 400,
            tail_crc: 0xabcd_1234,
        };
        let h = zh.encode();
        let d = ZHeader::decode(&h).unwrap();
        assert_eq!((d.plan, d.tail_len, d.tail_crc), (plan, 400, 0xabcd_1234));
        let mut bad = h;
        bad[14] ^= 1;
        assert!(ZHeader::decode(&bad).is_none());
        assert!(ZHeader::decode(&h[..70]).is_none());
        assert_eq!(
            zh.blob_len(),
            160 + 400 + 2 * plan.table_len() + u64::from(plan.parity_shards) * u64::from(plan.shard)
        );
    }
}
