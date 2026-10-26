//! The `.prat` container layout (see `docs/PRAT_FORMAT.md`): header, self-describing blocks, an index and a footer.
//! Everything read from a file is treated as hostile: counts are checked against the bytes that are left and
//! every reference is checked against what it points to before it is used.

use crate::error::{Error, Result};

pub const MAGIC: [u8; 8] = *b"PRAT\r\n\x1a\n";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: u64 = 16;

pub const BLOCK_SYNC: [u8; 4] = *b"PrBk";
pub const BLOCK_HEADER_LEN: usize = 52;
pub const FOOTER_MAGIC: [u8; 8] = *b"PRATEND\x01";
pub const FOOTER_LEN: usize = 68;

/// Largest uncompressed block a reader will allocate for, whatever the file claims.
pub const MAX_BLOCK_ULEN: u32 = 256 << 20;
/// Largest index a reader will decompress.
pub const MAX_INDEX_ULEN: u64 = 512 << 20;

pub const CODEC_STORE: u8 = 0;
pub const CODEC_ZSTD: u8 = 1;

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;

fn corrupt<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Corrupt(msg.into()))
}

pub fn header_bytes() -> [u8; HEADER_LEN as usize] {
    let mut h = [0u8; HEADER_LEN as usize];
    h[..8].copy_from_slice(&MAGIC);
    h[8..10].copy_from_slice(&VERSION.to_le_bytes());
    h
}

pub fn check_header(h: &[u8]) -> Result<()> {
    if h.len() < HEADER_LEN as usize || h[..8] != MAGIC {
        return corrupt("not a .prat file");
    }
    let version = u16::from_le_bytes([h[8], h[9]]);
    if version == 0 || version > VERSION {
        return Err(Error::Unsupported(format!(
            "this .prat file is version {version}; this Packrat reads up to version {VERSION}"
        )));
    }
    Ok(())
}

/// Header in front of every block's payload. It is complete on its own, so a damaged index can be rebuilt by
/// walking the file from block to block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub codec: u8,
    pub clen: u32,
    pub ulen: u32,
    /// BLAKE3 of the uncompressed data.
    pub hash: [u8; 32],
}

impl BlockHeader {
    pub fn encode(&self) -> [u8; BLOCK_HEADER_LEN] {
        let mut b = [0u8; BLOCK_HEADER_LEN];
        b[..4].copy_from_slice(&BLOCK_SYNC);
        b[4] = self.codec;
        b[8..12].copy_from_slice(&self.clen.to_le_bytes());
        b[12..16].copy_from_slice(&self.ulen.to_le_bytes());
        b[16..48].copy_from_slice(&self.hash);
        let crc = crc32fast::hash(&b[..48]);
        b[48..].copy_from_slice(&crc.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < BLOCK_HEADER_LEN || b[..4] != BLOCK_SYNC {
            return corrupt("a block header is missing");
        }
        let crc = u32::from_le_bytes(b[48..52].try_into().unwrap());
        if crc != crc32fast::hash(&b[..48]) {
            return corrupt("a block header is damaged");
        }
        let h = Self {
            codec: b[4],
            clen: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            ulen: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            hash: b[16..48].try_into().unwrap(),
        };
        if h.ulen > MAX_BLOCK_ULEN {
            return corrupt("a block claims an unreasonable size");
        }
        Ok(h)
    }
}

/// Last bytes of the file: where the index is and how to check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Footer {
    pub index_offset: u64,
    pub index_clen: u64,
    pub index_ulen: u64,
    /// BLAKE3 of the stored (compressed) index bytes.
    pub index_hash: [u8; 32],
}

impl Footer {
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut b = [0u8; FOOTER_LEN];
        b[..8].copy_from_slice(&self.index_offset.to_le_bytes());
        b[8..16].copy_from_slice(&self.index_clen.to_le_bytes());
        b[16..24].copy_from_slice(&self.index_ulen.to_le_bytes());
        b[24..56].copy_from_slice(&self.index_hash);
        let crc = crc32fast::hash(&b[..56]);
        b[56..60].copy_from_slice(&crc.to_le_bytes());
        b[60..].copy_from_slice(&FOOTER_MAGIC);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != FOOTER_LEN || b[60..] != FOOTER_MAGIC {
            return corrupt("the end of the archive is missing (truncated or not finished?)");
        }
        let crc = u32::from_le_bytes(b[56..60].try_into().unwrap());
        if crc != crc32fast::hash(&b[..56]) {
            return corrupt("the archive footer is damaged");
        }
        Ok(Self {
            index_offset: u64::from_le_bytes(b[..8].try_into().unwrap()),
            index_clen: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            index_ulen: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            index_hash: b[24..56].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    /// Offset of the block's header in the file.
    pub offset: u64,
    pub clen: u32,
    pub ulen: u32,
    pub codec: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub block: u32,
    pub offset: u32,
    pub len: u32,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRec {
    pub path: String,
    pub kind: u8,
    pub size: u64,
    pub mtime: Option<i64>,
    pub mode: Option<u32>,
    /// Chunk ids in file order.
    pub chunks: Vec<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Index {
    pub blocks: Vec<BlockRef>,
    pub chunks: Vec<ChunkRef>,
    pub files: Vec<FileRec>,
}

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

struct Cur<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn left(&self) -> usize {
        self.data.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| Error::Corrupt("the index ends early".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn varint(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.u8()?;
            if shift == 63 && b > 1 {
                return corrupt("a number in the index is too large");
            }
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        corrupt("a number in the index is too long")
    }

    /// A count of items that each take at least `min_each` bytes: it cannot exceed what is left.
    fn count(&mut self, min_each: usize) -> Result<usize> {
        let n = self.varint()?;
        if n > (self.left() / min_each.max(1)) as u64 {
            return corrupt("the index claims more entries than it can hold");
        }
        Ok(n as usize)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.left() {
            return corrupt("the index ends early");
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

const INDEX_MAGIC: &[u8; 4] = b"PIDX";

impl Index {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(64 + self.chunks.len() * 40 + self.files.len() * 48);
        o.extend_from_slice(INDEX_MAGIC);
        put_varint(&mut o, self.blocks.len() as u64);
        for b in &self.blocks {
            put_varint(&mut o, b.offset);
            put_varint(&mut o, u64::from(b.clen));
            put_varint(&mut o, u64::from(b.ulen));
            o.push(b.codec);
        }
        put_varint(&mut o, self.chunks.len() as u64);
        for c in &self.chunks {
            put_varint(&mut o, u64::from(c.block));
            put_varint(&mut o, u64::from(c.offset));
            put_varint(&mut o, u64::from(c.len));
            o.extend_from_slice(&c.hash);
        }
        put_varint(&mut o, self.files.len() as u64);
        for f in &self.files {
            o.push(f.kind);
            put_varint(&mut o, f.path.len() as u64);
            o.extend_from_slice(f.path.as_bytes());
            put_varint(&mut o, f.size);
            o.push(u8::from(f.mtime.is_some()) | (u8::from(f.mode.is_some()) << 1));
            if let Some(t) = f.mtime {
                put_varint(&mut o, zigzag(t));
            }
            if let Some(m) = f.mode {
                put_varint(&mut o, u64::from(m));
            }
            put_varint(&mut o, f.chunks.len() as u64);
            let mut prev = 0i64;
            for &id in &f.chunks {
                put_varint(&mut o, zigzag(i64::from(id) - prev));
                prev = i64::from(id);
            }
        }
        o
    }

    /// `file_len` is the size of the whole archive: block offsets must lie inside it.
    pub fn decode(data: &[u8], file_len: u64) -> Result<Self> {
        let mut c = Cur { data, pos: 0 };
        if c.bytes(4)? != INDEX_MAGIC {
            return corrupt("the index is not valid");
        }
        let nblocks = c.count(4)?;
        let mut blocks = Vec::with_capacity(nblocks);
        for _ in 0..nblocks {
            let offset = c.varint()?;
            let clen = u32::try_from(c.varint()?).map_err(|_| Error::Corrupt("a block is too large".into()))?;
            let ulen = u32::try_from(c.varint()?).map_err(|_| Error::Corrupt("a block is too large".into()))?;
            let codec = c.u8()?;
            if ulen > MAX_BLOCK_ULEN || codec > CODEC_ZSTD {
                return corrupt("a block has unsupported properties");
            }
            let end = offset
                .checked_add(BLOCK_HEADER_LEN as u64)
                .and_then(|v| v.checked_add(u64::from(clen)));
            if offset < HEADER_LEN || end.is_none_or(|e| e > file_len) {
                return corrupt("a block lies outside the archive");
            }
            blocks.push(BlockRef {
                offset,
                clen,
                ulen,
                codec,
            });
        }
        let nchunks = c.count(35)?;
        let mut chunks = Vec::with_capacity(nchunks);
        for _ in 0..nchunks {
            let block = u32::try_from(c.varint()?).map_err(|_| Error::Corrupt("bad chunk reference".into()))?;
            let offset = u32::try_from(c.varint()?).map_err(|_| Error::Corrupt("bad chunk reference".into()))?;
            let len = u32::try_from(c.varint()?).map_err(|_| Error::Corrupt("bad chunk reference".into()))?;
            let hash: [u8; 32] = c.bytes(32)?.try_into().unwrap();
            let b = blocks
                .get(block as usize)
                .ok_or_else(|| Error::Corrupt("a chunk refers to a missing block".into()))?;
            if len == 0 || u64::from(offset) + u64::from(len) > u64::from(b.ulen) {
                return corrupt("a chunk does not fit in its block");
            }
            chunks.push(ChunkRef {
                block,
                offset,
                len,
                hash,
            });
        }
        let nfiles = c.count(4)?;
        let mut files = Vec::with_capacity(nfiles);
        for _ in 0..nfiles {
            let kind = c.u8()?;
            if kind > KIND_DIR {
                return corrupt("an entry has an unknown type");
            }
            let plen = c.count(1)?;
            let path = String::from_utf8(c.bytes(plen)?.to_vec())
                .map_err(|_| Error::Corrupt("a name in the index is not valid text".into()))?;
            let size = c.varint()?;
            let flags = c.u8()?;
            let mtime = if flags & 1 != 0 {
                Some(unzigzag(c.varint()?))
            } else {
                None
            };
            let mode = if flags & 2 != 0 {
                Some(u32::try_from(c.varint()?).map_err(|_| Error::Corrupt("bad file mode".into()))?)
            } else {
                None
            };
            let n = c.count(1)?;
            let mut ids = Vec::with_capacity(n);
            let mut prev = 0i64;
            let mut total = 0u64;
            for _ in 0..n {
                prev = prev
                    .checked_add(unzigzag(c.varint()?))
                    .ok_or_else(|| Error::Corrupt("bad chunk list".into()))?;
                let id = u32::try_from(prev).map_err(|_| Error::Corrupt("bad chunk list".into()))?;
                let ch = chunks
                    .get(id as usize)
                    .ok_or_else(|| Error::Corrupt("a file refers to a missing chunk".into()))?;
                total += u64::from(ch.len);
                ids.push(id);
            }
            if kind == KIND_DIR && (size != 0 || !ids.is_empty()) || kind == KIND_FILE && total != size {
                return corrupt(format!("the size of '{path}' does not match its chunks"));
            }
            files.push(FileRec {
                path,
                kind,
                size,
                mtime,
                mode,
                chunks: ids,
            });
        }
        if c.left() != 0 {
            return corrupt("the index has extra bytes");
        }
        Ok(Self { blocks, chunks, files })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Index {
        let blocks = vec![
            BlockRef {
                offset: 16,
                clen: 100,
                ulen: 300,
                codec: CODEC_ZSTD,
            },
            BlockRef {
                offset: 200,
                clen: 50,
                ulen: 50,
                codec: CODEC_STORE,
            },
        ];
        let chunks = vec![
            ChunkRef {
                block: 0,
                offset: 0,
                len: 200,
                hash: [1; 32],
            },
            ChunkRef {
                block: 0,
                offset: 200,
                len: 100,
                hash: [2; 32],
            },
            ChunkRef {
                block: 1,
                offset: 0,
                len: 50,
                hash: [3; 32],
            },
        ];
        let files = vec![
            FileRec {
                path: "d".into(),
                kind: KIND_DIR,
                size: 0,
                mtime: Some(-5),
                mode: None,
                chunks: vec![],
            },
            FileRec {
                path: "d/файл.txt".into(),
                kind: KIND_FILE,
                size: 350,
                mtime: Some(1_700_000_000),
                mode: Some(0o644),
                chunks: vec![0, 2, 1],
            },
            FileRec {
                path: "empty".into(),
                kind: KIND_FILE,
                size: 0,
                mtime: None,
                mode: None,
                chunks: vec![],
            },
        ];
        Index { blocks, chunks, files }
    }

    #[test]
    fn index_roundtrip() {
        let idx = sample();
        let bytes = idx.encode();
        assert_eq!(Index::decode(&bytes, 10_000).unwrap(), idx);
    }

    #[test]
    fn varints_roundtrip_including_the_extremes() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut o = Vec::new();
            put_varint(&mut o, v);
            let mut c = Cur { data: &o, pos: 0 };
            assert_eq!(c.varint().unwrap(), v);
            assert_eq!(c.left(), 0);
        }
        for v in [0i64, -1, 1, i64::MIN, i64::MAX] {
            assert_eq!(unzigzag(zigzag(v)), v);
        }
        // eleven continuation bytes never end
        let mut c = Cur {
            data: &[0xff; 11],
            pos: 0,
        };
        assert!(c.varint().is_err());
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let bytes = sample().encode();
        for cut in 0..bytes.len() {
            assert!(Index::decode(&bytes[..cut], 10_000).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn corrupted_indexes_never_panic() {
        let bytes = sample().encode();
        let mut x = 12345u32;
        for _ in 0..3000 {
            let mut b = bytes.clone();
            for _ in 0..3 {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let i = (x >> 8) as usize % b.len();
                b[i] = (x >> 24) as u8;
            }
            let _ = Index::decode(&b, 10_000);
        }
    }

    #[test]
    fn references_are_checked_against_their_targets() {
        let mut idx = sample();
        idx.chunks[0].len = 400; // runs past the end of block 0
        assert!(Index::decode(&idx.encode(), 10_000).is_err());
        let mut idx = sample();
        idx.files[1].size = 351; // does not match the chunks
        assert!(Index::decode(&idx.encode(), 10_000).is_err());
        let mut idx = sample();
        idx.files[1].chunks = vec![0, 9]; // missing chunk
        assert!(Index::decode(&idx.encode(), 10_000).is_err());
        // a block that lies beyond the end of the file
        assert!(Index::decode(&sample().encode(), 100).is_err());
    }

    #[test]
    fn block_header_and_footer_roundtrip_and_detect_damage() {
        let h = BlockHeader {
            codec: CODEC_ZSTD,
            clen: 10,
            ulen: 99,
            hash: [7; 32],
        };
        let mut b = h.encode();
        assert_eq!(BlockHeader::decode(&b).unwrap(), h);
        b[20] ^= 1;
        assert!(BlockHeader::decode(&b).is_err());

        let f = Footer {
            index_offset: 1234,
            index_clen: 55,
            index_ulen: 66,
            index_hash: [9; 32],
        };
        let mut b = f.encode();
        assert_eq!(Footer::decode(&b).unwrap(), f);
        b[3] ^= 1;
        assert!(Footer::decode(&b).is_err());
        assert!(Footer::decode(&f.encode()[..60]).is_err());
    }

    #[test]
    fn headers_from_a_newer_version_are_refused_politely() {
        let mut h = header_bytes();
        assert!(check_header(&h).is_ok());
        h[8] = 99;
        assert!(matches!(check_header(&h), Err(Error::Unsupported(_))));
        assert!(check_header(b"PK\x03\x04 not it at all").is_err());
    }
}
