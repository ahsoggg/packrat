//! Changing an existing ZIP archive without recompressing what stays: kept entries are copied byte for byte,
//! new files are compressed into a side archive and appended, and a new central directory is written.
//!
//! The central directory is parsed here into plain records and written back, so Zip64 fields are rebuilt as
//! needed; everything else in a record (flags, method, times, attributes, comment) is carried over unchanged.

use super::extra::{self, ID_UNICODE_PATH, ID_ZIP64};
use super::read::find_end_record;
use super::write::{ZipOptions, write_zip};
use super::{SIG_CENTRAL, SIG_EOCD, SIG_EOCD64, SIG_LOC64, SIG_LOCAL};
use crate::error::{Error, Result};
use crate::input::InputItem;
use crate::progress::Progress;
use crate::source::{FileSource, Source, read_exact_at};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

const MAX_CENTRAL_DIRECTORY: u64 = 1 << 30;
const FLAG_UTF8: u16 = 1 << 11;

/// What to do with an archive: entries are named by their position in the central directory (the `index` of
/// `Archive::entries`).
pub struct ZipEdit<'a> {
    pub delete: &'a HashSet<usize>,
    /// New full names (with `/`; folders end with `/`).
    pub rename: &'a HashMap<usize, String>,
    pub add: &'a [InputItem],
    pub options: &'a ZipOptions,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ZipEditReport {
    pub kept: usize,
    pub deleted: usize,
    pub renamed: usize,
    pub added: usize,
}

#[derive(Clone)]
struct Rec {
    made_by: u16,
    needed: u16,
    flags: u16,
    method: u16,
    time: u16,
    date: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    name: Vec<u8>,
    /// Without the Zip64 field, which is rebuilt on writing.
    extra: Vec<u8>,
    comment: Vec<u8>,
    internal: u16,
    external: u32,
    offset: u64,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

fn corrupt<T>(m: &str) -> Result<T> {
    Err(Error::Corrupt(m.into()))
}

struct Parsed {
    recs: Vec<Rec>,
    comment: Vec<u8>,
    /// End of the entry data: where the central directory (or the recovery section in front of it) starts.
    data_end: u64,
}

fn parse(src: &dyn Source, recovery_start: Option<u64>) -> Result<Parsed> {
    let end = find_end_record(src)?;
    if end.cd_size > MAX_CENTRAL_DIRECTORY || end.cd_size > src.len() {
        return corrupt("central directory size is not plausible");
    }
    let Some(cd_start) = end.end_of_cd.checked_sub(end.cd_size) else {
        return corrupt("central directory does not fit in the file");
    };
    if cd_start != end.cd_offset {
        return Err(Error::Unsupported(
            "this ZIP archive has data in front of it (a self-extractor?); it cannot be changed in place".into(),
        ));
    }
    if end.entries > end.cd_size / 46 {
        return corrupt("entry count does not match the central directory size");
    }
    let mut cd = vec![0u8; end.cd_size as usize];
    read_exact_at(src, cd_start, &mut cd)?;
    let mut recs = Vec::with_capacity(end.entries as usize);
    let mut p = 0usize;
    for _ in 0..end.entries {
        if cd.len() < p + 46 || le32(&cd, p) != SIG_CENTRAL {
            return corrupt("central directory entry is damaged");
        }
        let (nl, el, cl) = (
            le16(&cd, p + 28) as usize,
            le16(&cd, p + 30) as usize,
            le16(&cd, p + 32) as usize,
        );
        let total = 46 + nl + el + cl;
        if cd.len() < p + total {
            return corrupt("central directory is truncated");
        }
        let name = cd[p + 46..p + 46 + nl].to_vec();
        let extra_all = &cd[p + 46 + nl..p + 46 + nl + el];
        let mut r = Rec {
            made_by: le16(&cd, p + 4),
            needed: le16(&cd, p + 6),
            flags: le16(&cd, p + 8),
            method: le16(&cd, p + 10),
            time: le16(&cd, p + 12),
            date: le16(&cd, p + 14),
            crc: le32(&cd, p + 16),
            csize: u64::from(le32(&cd, p + 20)),
            usize: u64::from(le32(&cd, p + 24)),
            name,
            extra: Vec::new(),
            comment: cd[p + 46 + nl + el..p + total].to_vec(),
            internal: le16(&cd, p + 36),
            external: le32(&cd, p + 38),
            offset: u64::from(le32(&cd, p + 42)),
        };
        if le16(&cd, p + 34) != 0 {
            return Err(Error::Unsupported("multi-volume ZIP archives cannot be changed".into()));
        }
        // Zip64: the fields that did not fit are here, in this order
        if let Some(z) = extra::find(extra_all, ID_ZIP64) {
            let mut q = 0;
            let take = |q: &mut usize| -> Option<u64> {
                let v = z.get(*q..*q + 8).map(|b| le64(b, 0));
                *q += 8;
                v
            };
            if r.usize == u64::from(u32::MAX) {
                r.usize = take(&mut q).ok_or_else(|| Error::Corrupt("Zip64 field is too short".into()))?;
            }
            if r.csize == u64::from(u32::MAX) {
                r.csize = take(&mut q).ok_or_else(|| Error::Corrupt("Zip64 field is too short".into()))?;
            }
            if r.offset == u64::from(u32::MAX) {
                r.offset = take(&mut q).ok_or_else(|| Error::Corrupt("Zip64 field is too short".into()))?;
            }
        }
        r.extra = strip_fields(extra_all, &[ID_ZIP64]);
        recs.push(r);
        p += total;
    }
    Ok(Parsed {
        recs,
        comment: end.comment,
        data_end: recovery_start.unwrap_or(cd_start),
    })
}

/// The extra fields without the ones listed.
fn strip_fields(extra_all: &[u8], ids: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(extra_all.len());
    for (id, data) in extra::fields(extra_all) {
        if !ids.contains(&id) {
            out.extend(id.to_le_bytes());
            out.extend((data.len() as u16).to_le_bytes());
            out.extend(data);
        }
    }
    out
}

fn write_central<W: Write>(w: &mut W, recs: &[Rec], comment: &[u8], cd_start: u64) -> Result<()> {
    let mut cd_size = 0u64;
    for r in recs {
        let big_sizes = r.csize >= u64::from(u32::MAX) || r.usize >= u64::from(u32::MAX);
        let big_offset = r.offset >= u64::from(u32::MAX);
        let mut extra = r.extra.clone();
        let mut z = Vec::new();
        if big_sizes {
            z.extend(r.usize.to_le_bytes());
            z.extend(r.csize.to_le_bytes());
        }
        if big_offset {
            z.extend(r.offset.to_le_bytes());
        }
        if !z.is_empty() {
            extra.extend(ID_ZIP64.to_le_bytes());
            extra.extend((z.len() as u16).to_le_bytes());
            extra.extend(z);
        }
        let needed = if big_sizes || big_offset {
            r.needed.max(45)
        } else {
            r.needed
        };
        let mut b = Vec::with_capacity(46 + r.name.len() + extra.len() + r.comment.len());
        b.extend(SIG_CENTRAL.to_le_bytes());
        b.extend(r.made_by.to_le_bytes());
        b.extend(needed.to_le_bytes());
        b.extend(r.flags.to_le_bytes());
        b.extend(r.method.to_le_bytes());
        b.extend(r.time.to_le_bytes());
        b.extend(r.date.to_le_bytes());
        b.extend(r.crc.to_le_bytes());
        b.extend((if big_sizes { u32::MAX } else { r.csize as u32 }).to_le_bytes());
        b.extend((if big_sizes { u32::MAX } else { r.usize as u32 }).to_le_bytes());
        b.extend((r.name.len() as u16).to_le_bytes());
        b.extend((extra.len() as u16).to_le_bytes());
        b.extend((r.comment.len() as u16).to_le_bytes());
        b.extend(0u16.to_le_bytes());
        b.extend(r.internal.to_le_bytes());
        b.extend(r.external.to_le_bytes());
        b.extend((if big_offset { u32::MAX } else { r.offset as u32 }).to_le_bytes());
        b.extend(&r.name);
        b.extend(&extra);
        b.extend(&r.comment);
        cd_size += b.len() as u64;
        w.write_all(&b)?;
    }
    let n = recs.len() as u64;
    let cd_end = cd_start + cd_size;
    let need64 = n >= 0xFFFF || cd_size >= u64::from(u32::MAX) || cd_start >= u64::from(u32::MAX);
    if need64 {
        w.write_all(&SIG_EOCD64.to_le_bytes())?;
        w.write_all(&44u64.to_le_bytes())?;
        w.write_all(&63u16.to_le_bytes())?;
        w.write_all(&45u16.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&n.to_le_bytes())?;
        w.write_all(&n.to_le_bytes())?;
        w.write_all(&cd_size.to_le_bytes())?;
        w.write_all(&cd_start.to_le_bytes())?;
        w.write_all(&SIG_LOC64.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&cd_end.to_le_bytes())?;
        w.write_all(&1u32.to_le_bytes())?;
    }
    w.write_all(&SIG_EOCD.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    w.write_all(&0u16.to_le_bytes())?;
    let n16 = if need64 { 0xFFFF } else { n as u16 };
    w.write_all(&n16.to_le_bytes())?;
    w.write_all(&n16.to_le_bytes())?;
    w.write_all(&(if need64 { u32::MAX } else { cd_size as u32 }).to_le_bytes())?;
    w.write_all(&(if need64 { u32::MAX } else { cd_start as u32 }).to_le_bytes())?;
    w.write_all(&(comment.len() as u16).to_le_bytes())?;
    w.write_all(comment)?;
    w.flush()?;
    Ok(())
}

fn copy_range(f: &mut File, from: u64, len: u64, out: &mut impl Write, buf: &mut [u8]) -> Result<()> {
    f.seek(SeekFrom::Start(from))?;
    let mut left = len;
    while left > 0 {
        let n = buf.len().min(left as usize);
        f.read_exact(&mut buf[..n])?;
        out.write_all(&buf[..n])?;
        left -= n as u64;
    }
    Ok(())
}

/// Writes the entry that starts at `rec.offset` and is `span` bytes long, under a new name.
fn copy_renamed(
    f: &mut File,
    rec: &Rec,
    span: u64,
    new_name: &[u8],
    out: &mut impl Write,
    buf: &mut [u8],
) -> Result<()> {
    let mut head = [0u8; 30];
    f.seek(SeekFrom::Start(rec.offset))?;
    f.read_exact(&mut head)?;
    if le32(&head, 0) != SIG_LOCAL {
        return corrupt("a local header is not where the central directory says");
    }
    let (nl, el) = (le16(&head, 26) as u64, le16(&head, 28) as usize);
    if 30 + nl + el as u64 > span {
        return corrupt("a local header is larger than its entry");
    }
    f.seek(SeekFrom::Start(rec.offset + 30 + nl))?;
    let mut old_extra = vec![0u8; el];
    f.read_exact(&mut old_extra)?;
    let extra = strip_fields(&old_extra, &[ID_UNICODE_PATH]);
    let flags = le16(&head, 6) | FLAG_UTF8;
    let mut h = head;
    h[6..8].copy_from_slice(&flags.to_le_bytes());
    h[26..28].copy_from_slice(&(new_name.len() as u16).to_le_bytes());
    h[28..30].copy_from_slice(&(extra.len() as u16).to_le_bytes());
    out.write_all(&h)?;
    out.write_all(new_name)?;
    out.write_all(&extra)?;
    copy_range(
        f,
        rec.offset + 30 + nl + el as u64,
        span - 30 - nl - el as u64,
        out,
        buf,
    )
}

/// Writes the changed archive to `dst` (which must not exist); `src` is not touched. Name conflicts between
/// added items and kept entries are the caller's business: delete the old entry in the same edit.
pub fn edit_zip(
    src: &Path,
    dst: &Path,
    recovery_start: Option<u64>,
    edit: &ZipEdit<'_>,
    progress: &Progress,
) -> Result<ZipEditReport> {
    let source = FileSource::open(src)?;
    let Parsed {
        mut recs,
        comment,
        data_end,
    } = parse(&source, recovery_start)?;
    drop(source);
    if let Some(&bad) = edit.delete.iter().chain(edit.rename.keys()).find(|&&i| i >= recs.len()) {
        return Err(Error::Other(format!("no entry #{bad} in the archive")));
    }

    // each entry spans from its offset to the next one's (descriptors included)
    let mut order: Vec<usize> = (0..recs.len()).collect();
    order.sort_by_key(|&i| recs[i].offset);
    let mut span = vec![0u64; recs.len()];
    for (k, &i) in order.iter().enumerate() {
        let end = order.get(k + 1).map_or(data_end, |&j| recs[j].offset);
        if end <= recs[i].offset || end > data_end {
            return Err(Error::Corrupt(
                "entries of this ZIP archive overlap or point outside the file; it cannot be changed safely".into(),
            ));
        }
        span[i] = end - recs[i].offset;
    }

    let side = dst.with_extension("packrat-new");
    let added = if edit.add.is_empty() {
        None
    } else {
        let f = File::options().write(true).create_new(true).open(&side)?;
        write_zip(BufWriter::with_capacity(256 << 10, f), edit.add, edit.options, progress)?;
        Some(side.as_path())
    };
    let result = assemble(src, dst, &mut recs, &span, &comment, edit, added);
    let _ = fs::remove_file(&side);
    if result.is_err() {
        let _ = fs::remove_file(dst);
    }
    result
}

fn assemble(
    src: &Path,
    dst: &Path,
    recs: &mut [Rec],
    span: &[u64],
    comment: &[u8],
    edit: &ZipEdit<'_>,
    added: Option<&Path>,
) -> Result<ZipEditReport> {
    let mut report = ZipEditReport::default();
    let mut f = File::open(src)?;
    let out_file = File::options().write(true).create_new(true).open(dst)?;
    let mut out = CountingWriter {
        inner: BufWriter::with_capacity(1 << 20, out_file),
        pos: 0,
    };
    let mut buf = vec![0u8; 1 << 20];
    let mut kept: Vec<Rec> = Vec::with_capacity(recs.len());
    for i in 0..recs.len() {
        if edit.delete.contains(&i) {
            report.deleted += 1;
            continue;
        }
        let mut r = recs[i].clone();
        let at = out.pos;
        if let Some(new_name) = edit.rename.get(&i) {
            r.name = new_name.as_bytes().to_vec();
            r.flags |= FLAG_UTF8;
            r.extra = strip_fields(&r.extra, &[ID_UNICODE_PATH]);
            copy_renamed(&mut f, &recs[i], span[i], &r.name, &mut out, &mut buf)?;
            report.renamed += 1;
        } else {
            copy_range(&mut f, recs[i].offset, span[i], &mut out, &mut buf)?;
        }
        r.offset = at;
        kept.push(r);
        report.kept += 1;
    }
    if let Some(side) = added {
        let mut sf = File::open(side)?;
        let sl = sf.metadata()?.len();
        let parsed = parse(&FileSource::open(side)?, None)?;
        let base = out.pos;
        copy_range(&mut sf, 0, parsed.data_end.min(sl), &mut out, &mut buf)?;
        for mut r in parsed.recs {
            r.offset += base;
            kept.push(r);
            report.added += 1;
        }
    }
    let cd_start = out.pos;
    write_central(&mut out, &kept, comment, cd_start)?;
    out.inner
        .into_inner()
        .map_err(|e| Error::from(io::Error::from(e)))?
        .sync_all()?;
    Ok(report)
}

struct CountingWriter<W: Write> {
    inner: W,
    pos: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(b)?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
