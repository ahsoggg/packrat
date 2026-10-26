//! Split archives (`name.7z.001`, `.002`, ...): the volumes are plain pieces of one file, the way 7-Zip splits them.
//! Joining them is just reading one after the other.

use crate::error::{Error, Result};
use crate::source::{FileSource, SharedSource, Source};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Most volumes `split_file` will produce; also the most `series` will look for.
pub const MAX_VOLUMES: usize = 100_000;

/// A window `[start, start + len)` of another source.
pub struct SliceSource {
    inner: SharedSource,
    start: u64,
    len: u64,
}

impl SliceSource {
    pub fn new(inner: SharedSource, start: u64, len: u64) -> Self {
        let start = start.min(inner.len());
        let len = len.min(inner.len() - start);
        Self { inner, start, len }
    }
}

impl Source for SliceSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let n = buf.len().min((self.len - offset) as usize);
        self.inner.read_at(self.start + offset, &mut buf[..n])
    }
}

/// Several files read as one.
pub struct MultiSource {
    parts: Vec<(FileSource, u64)>,
    len: u64,
}

impl MultiSource {
    pub fn open(paths: &[PathBuf]) -> io::Result<Self> {
        let mut parts = Vec::with_capacity(paths.len());
        let mut at = 0u64;
        for p in paths {
            let f = FileSource::open(p)?;
            let l = f.len();
            parts.push((f, at));
            at += l;
        }
        Ok(Self { parts, len: at })
    }
}

impl Source for MultiSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        // the last part that starts at or before the offset
        let i = self.parts.partition_point(|(_, start)| *start <= offset) - 1;
        let (f, start) = &self.parts[i];
        let inside = offset - start;
        let n = buf.len().min((f.len() - inside) as usize);
        f.read_at(inside, &mut buf[..n])
    }
}

/// `x.7z.001` -> `Some(("x.7z", 1))`: the name without the volume number, and the number.
fn split_volume_name(name: &str) -> Option<(&str, u32)> {
    let (stem, ext) = name.rsplit_once('.')?;
    (ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()) && !stem.is_empty())
        .then(|| ext.parse().ok().map(|n| (stem, n)))?
}

/// The volumes of the series that `path` belongs to, in order, when `path` is named like one
/// (`.001`, `.002`, ...). The series starts at `.001`; a gap in the numbers ends it.
pub fn series(path: &Path) -> Result<Option<Vec<PathBuf>>> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Some((stem, number)) = split_volume_name(&name) else {
        return Ok(None);
    };
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let first = dir.join(format!("{stem}.001"));
    if !first.exists() {
        return Err(Error::Other(format!(
            "the first volume '{}' is missing",
            first.display()
        )));
    }
    let mut out = Vec::new();
    for n in 1..=MAX_VOLUMES as u32 {
        let p = dir.join(format!("{stem}.{n:03}"));
        if !p.is_file() {
            if n <= number {
                return Err(Error::Other(format!("volume '{}' is missing", p.display())));
            }
            break;
        }
        out.push(p);
    }
    Ok(Some(out))
}

/// The name an archive in a series has without the volume number: what decides its format by extension.
pub fn logical_name(name: &str) -> &str {
    split_volume_name(name).map_or(name, |(stem, _)| stem)
}

/// Opens `path` as one source: the whole series when it is a volume, else the file itself.
pub fn open_source(path: &Path) -> Result<SharedSource> {
    Ok(match series(path)? {
        Some(parts) => Arc::new(MultiSource::open(&parts)?),
        None => Arc::new(FileSource::open(path)?),
    })
}

/// Cuts `path` into volumes of `size` bytes named `path.001`, `path.002`, ...; the original is removed. Returns the
/// volumes. Nothing is changed when a volume cannot be written (the pieces made so far are removed again).
pub fn split_file(path: &Path, size: u64) -> Result<Vec<PathBuf>> {
    if size < 64 << 10 {
        return Err(Error::Other("a volume must be at least 64 KiB".into()));
    }
    let len = fs::metadata(path)?.len();
    if len.div_ceil(size) > MAX_VOLUMES as u64 {
        return Err(Error::Other("too many volumes; use a larger volume size".into()));
    }
    let mut input = File::open(path)?;
    let mut made: Vec<PathBuf> = Vec::new();
    let result = (|| -> Result<()> {
        let mut buf = vec![0u8; 1 << 20];
        let mut left = len;
        let mut n = 1usize;
        while left > 0 || n == 1 {
            let part = PathBuf::from(format!("{}.{n:03}", path.display()));
            if part.exists() {
                return Err(Error::Other(format!("'{}' already exists", part.display())));
            }
            let mut out = File::options().write(true).create_new(true).open(&part)?;
            made.push(part);
            let mut take = left.min(size);
            left -= take;
            while take > 0 {
                let k = buf.len().min(take as usize);
                input.read_exact(&mut buf[..k])?;
                out.write_all(&buf[..k])?;
                take -= k as u64;
            }
            out.flush()?;
            n += 1;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            drop(input);
            fs::remove_file(path)?;
            Ok(made)
        }
        Err(e) => {
            for p in &made {
                let _ = fs::remove_file(p);
            }
            Err(e)
        }
    }
}

/// `100m`, `4g`, `700k`, or a plain number of bytes.
pub fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim().to_ascii_lowercase();
    let t = t.trim_end_matches('b');
    let (digits, mult) = match t.chars().last()? {
        'k' => (&t[..t.len() - 1], 1u64 << 10),
        'm' => (&t[..t.len() - 1], 1 << 20),
        'g' => (&t[..t.len() - 1], 1 << 30),
        _ => (t, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("100m"), Some(100 << 20));
        assert_eq!(parse_size("4GB"), Some(4 << 30));
        assert_eq!(parse_size("700k"), Some(700 << 10));
        assert_eq!(parse_size("65536"), Some(65536));
        assert_eq!(parse_size("x"), None);
    }

    #[test]
    fn names() {
        assert_eq!(split_volume_name("a.7z.001"), Some(("a.7z", 1)));
        assert_eq!(split_volume_name("a.7z"), None);
        assert_eq!(split_volume_name("a.12"), None);
        assert_eq!(logical_name("a.zip.003"), "a.zip");
        assert_eq!(logical_name("a.zip"), "a.zip");
    }

    #[test]
    fn split_and_join_give_back_the_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
        let f = dir.path().join("x.bin");
        fs::write(&f, &data).unwrap();
        let parts = split_file(&f, 100_000).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(!f.exists());
        // any volume leads to the whole series
        let one = series(&parts[1]).unwrap().unwrap();
        assert_eq!(one, parts);
        let src = open_source(&parts[2]).unwrap();
        assert_eq!(src.len(), data.len() as u64);
        let mut got = vec![0u8; data.len()];
        crate::source::read_exact_at(&*src, 0, &mut got).unwrap();
        assert_eq!(got, data);
        // a read across a boundary
        let mut mid = [0u8; 10];
        crate::source::read_exact_at(&*src, 99_995, &mut mid).unwrap();
        assert_eq!(&mid[..], &data[99_995..100_005]);
        // a missing middle volume is reported
        fs::remove_file(&parts[1]).unwrap();
        assert!(series(&parts[2]).is_err());
    }

    #[test]
    fn slices() {
        let s: SharedSource = Arc::new(crate::source::MemSource((0..100u8).collect()));
        let w = SliceSource::new(s, 10, 20);
        assert_eq!(w.len(), 20);
        let mut b = [0u8; 8];
        assert_eq!(w.read_at(16, &mut b).unwrap(), 4);
        assert_eq!(b[..4], [26, 27, 28, 29]);
        assert_eq!(w.read_at(20, &mut b).unwrap(), 0);
    }
}
