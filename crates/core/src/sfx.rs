//! Self-extracting archives: a small program (the stub) followed by an ordinary archive and a trailer that says
//! where the archive starts. The stub finds its own archive through the trailer; other tools see a program with
//! data after it (ZIP and 7z readers find their archive inside anyway).

use crate::error::{Error, Result};
use crate::source::{Source, read_exact_at};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::Path;

pub const MAGIC: [u8; 8] = *b"PRATSFX1";
/// Magic, archive offset, archive length (little endian), CRC-32 of those 24 bytes.
pub const TRAILER_LEN: usize = 28;

/// File name of the stub program.
pub const STUB_NAME: &str = "packrat-sfx.exe";

/// The stub that ships with Packrat: `packrat-sfx.exe` in the folder of the running program, or the file named by the
/// `PACKRAT_SFX_STUB` environment variable.
pub fn find_stub() -> Result<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("PACKRAT_SFX_STUB") {
        return Ok(p.into());
    }
    let here = std::env::current_exe()?;
    let stub = here.with_file_name(STUB_NAME);
    if stub.is_file() {
        return Ok(stub);
    }
    Err(Error::Other(format!(
        "the self-extractor stub {STUB_NAME} was not found next to {}",
        here.display()
    )))
}

/// Writes `stub`, then `archive`, then the trailer to `out` (which must not exist yet).
pub fn build(stub: &Path, archive: &Path, out: &Path) -> Result<()> {
    let mut stub_bytes = Vec::new();
    File::open(stub)?.read_to_end(&mut stub_bytes)?;
    if !stub_bytes.starts_with(b"MZ") {
        return Err(Error::Other(format!("'{}' is not a Windows program", stub.display())));
    }
    let mut arc = File::open(archive)?;
    let arc_len = arc.metadata()?.len();
    let mut w = BufWriter::with_capacity(1 << 20, File::options().write(true).create_new(true).open(out)?);
    let result = (|| -> io::Result<()> {
        w.write_all(&stub_bytes)?;
        io::copy(&mut arc, &mut w)?;
        let mut t = Vec::with_capacity(TRAILER_LEN);
        t.extend(MAGIC);
        t.extend((stub_bytes.len() as u64).to_le_bytes());
        t.extend(arc_len.to_le_bytes());
        t.extend(crc32fast::hash(&t).to_le_bytes());
        w.write_all(&t)?;
        w.flush()
    })();
    if let Err(e) = result {
        drop(w);
        let _ = std::fs::remove_file(out);
        return Err(e.into());
    }
    Ok(())
}

/// Where the archive lies inside `src`: `(offset, length)`, from the trailer written by `build`.
pub fn find_payload(src: &dyn Source) -> Option<(u64, u64)> {
    let len = src.len();
    if len < TRAILER_LEN as u64 {
        return None;
    }
    let mut t = [0u8; TRAILER_LEN];
    read_exact_at(src, len - TRAILER_LEN as u64, &mut t).ok()?;
    if t[..8] != MAGIC || crc32fast::hash(&t[..24]) != u32::from_le_bytes(t[24..].try_into().ok()?) {
        return None;
    }
    let offset = u64::from_le_bytes(t[8..16].try_into().ok()?);
    let size = u64::from_le_bytes(t[16..24].try_into().ok()?);
    (offset.checked_add(size)? + TRAILER_LEN as u64 == len).then_some((offset, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    #[test]
    fn trailer_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (stub, arc, out) = (
            dir.path().join("s.exe"),
            dir.path().join("a.zip"),
            dir.path().join("o.exe"),
        );
        std::fs::write(&stub, b"MZ stub bytes").unwrap();
        std::fs::write(&arc, b"PK archive bytes").unwrap();
        build(&stub, &arc, &out).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        let (o, l) = find_payload(&MemSource(bytes.clone())).unwrap();
        assert_eq!(&bytes[o as usize..(o + l) as usize], b"PK archive bytes");
        // damaged trailer or an ordinary file: no payload
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 5] ^= 1;
        assert!(find_payload(&MemSource(bad)).is_none());
        assert!(find_payload(&MemSource(b"MZ plain program".to_vec())).is_none());
        assert!(build(&arc, &arc, &dir.path().join("x.exe")).is_err());
    }
}
