//! Reading a `.prat` archive. Only the footer and the index are read when it is opened; a file is read by decoding
//! the blocks its chunks live in. Decoded blocks are shared between threads through a small cache, so several
//! files that sit in one block do not decode it again, and two threads that need the same block wait for one decode.

use super::format::*;
use crate::archive::{Archive, EntryReader, Kind};
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::source::{SharedSource, read_exact_at};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::sync::{Arc, Mutex, OnceLock};

type Cell = Arc<OnceLock<std::result::Result<Arc<Vec<u8>>, String>>>;

struct Cache {
    capacity: usize,
    inner: Mutex<(HashMap<u32, Cell>, VecDeque<u32>)>,
}

impl Cache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(2),
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    fn get(&self, id: u32, load: impl FnOnce() -> Result<Vec<u8>>) -> Result<Arc<Vec<u8>>> {
        let cell = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let (map, order) = &mut *g;
            match map.get(&id) {
                Some(c) => c.clone(),
                None => {
                    let c: Cell = Arc::default();
                    map.insert(id, c.clone());
                    order.push_back(id);
                    while order.len() > self.capacity {
                        if let Some(old) = order.pop_front() {
                            map.remove(&old);
                        }
                    }
                    c
                }
            }
        };
        match cell.get_or_init(|| load().map(Arc::new).map_err(|e| e.to_string())) {
            Ok(data) => Ok(data.clone()),
            Err(msg) => Err(Error::Corrupt(msg.clone())),
        }
    }
}

pub struct PratArchive {
    src: SharedSource,
    index: Index,
    entries: Vec<Entry>,
    cache: Cache,
}

impl PratArchive {
    pub fn from_source(src: SharedSource) -> Result<Self> {
        let len = src.len();
        if len < HEADER_LEN + FOOTER_LEN as u64 {
            return Err(Error::Corrupt("the file is too short to be a .prat archive".into()));
        }
        let mut head = [0u8; HEADER_LEN as usize];
        read_exact_at(&*src, 0, &mut head)?;
        check_header(&head)?;
        let mut foot = [0u8; FOOTER_LEN];
        read_exact_at(&*src, len - FOOTER_LEN as u64, &mut foot)?;
        let footer = Footer::decode(&foot)?;

        let idx_end = footer.index_offset.checked_add(footer.index_clen);
        if footer.index_offset < HEADER_LEN
            || idx_end.is_none_or(|e| e > len - FOOTER_LEN as u64)
            || footer.index_ulen > MAX_INDEX_ULEN
        {
            return Err(Error::Corrupt("the index lies outside the archive".into()));
        }
        let mut stored = vec![0u8; footer.index_clen as usize];
        read_exact_at(&*src, footer.index_offset, &mut stored)?;
        if *blake3::hash(&stored).as_bytes() != footer.index_hash {
            return Err(Error::Corrupt("the index is damaged".into()));
        }
        let raw = if footer.index_clen == footer.index_ulen {
            stored
        } else {
            let raw = zstd::bulk::decompress(&stored, footer.index_ulen as usize)
                .map_err(|e| Error::Corrupt(format!("the index cannot be decoded: {e}")))?;
            if raw.len() as u64 != footer.index_ulen {
                return Err(Error::Corrupt("the index has the wrong size".into()));
            }
            raw
        };
        let index = Index::decode(&raw, len)?;

        let entries = index
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let kind = if f.kind == KIND_DIR {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                };
                let mut e = Entry::new(i, f.path.clone(), kind);
                e.size = f.size;
                e.mtime = f.mtime;
                e.mode = f.mode;
                e.method = "PRAT".into();
                e
            })
            .collect();
        let biggest = index.blocks.iter().map(|b| b.ulen).max().unwrap_or(1).max(1) as usize;
        let cache = Cache::new(((256 << 20) / biggest).clamp(4, 64));
        Ok(Self {
            src,
            index,
            entries,
            cache,
        })
    }

    pub fn block_count(&self) -> usize {
        self.index.blocks.len()
    }

    pub fn unique_chunks(&self) -> usize {
        self.index.chunks.len()
    }

    /// Reads, decodes and verifies one block.
    fn load_block(&self, id: u32) -> Result<Vec<u8>> {
        let b = self.index.blocks[id as usize];
        let mut hdr = [0u8; BLOCK_HEADER_LEN];
        read_exact_at(&*self.src, b.offset, &mut hdr)?;
        let h = BlockHeader::decode(&hdr)?;
        if h.clen != b.clen || h.ulen != b.ulen || h.codec != b.codec {
            return Err(Error::Corrupt(format!("block {id} does not match the index")));
        }
        let mut payload = vec![0u8; h.clen as usize];
        read_exact_at(&*self.src, b.offset + BLOCK_HEADER_LEN as u64, &mut payload)?;
        let data = match h.codec {
            CODEC_STORE => payload,
            CODEC_ZSTD => zstd::bulk::decompress(&payload, h.ulen as usize)
                .map_err(|e| Error::Corrupt(format!("block {id} cannot be decoded: {e}")))?,
            other => return Err(Error::Unsupported(format!("block compression method {other}"))),
        };
        if data.len() != h.ulen as usize || *blake3::hash(&data).as_bytes() != h.hash {
            return Err(Error::Corrupt(format!("block {id} is damaged")));
        }
        Ok(data)
    }

    fn block(&self, id: u32) -> Result<Arc<Vec<u8>>> {
        self.cache.get(id, || self.load_block(id))
    }
}

struct PratReader<'a> {
    arch: &'a PratArchive,
    chunks: &'a [u32],
    next: usize,
    cur: Option<(Arc<Vec<u8>>, usize, usize)>,
}

impl Read for PratReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some((data, pos, end)) = &mut self.cur {
                if *pos < *end {
                    let n = buf.len().min(*end - *pos);
                    buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                    *pos += n;
                    return Ok(n);
                }
                self.cur = None;
            }
            let Some(&id) = self.chunks.get(self.next) else {
                return Ok(0);
            };
            self.next += 1;
            let c = self.arch.index.chunks[id as usize];
            let data = self.arch.block(c.block).map_err(io::Error::other)?;
            let (start, end) = (c.offset as usize, c.offset as usize + c.len as usize);
            // already checked when the index was read, but a slice must never panic
            if end > data.len() {
                return Err(io::Error::other(Error::Corrupt(
                    "a chunk lies outside its block".into(),
                )));
            }
            self.cur = Some((data, start, end));
        }
    }
}

impl Archive for PratArchive {
    fn kind(&self) -> Kind {
        Kind::Prat
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn prefers_archive_order(&self) -> bool {
        true
    }

    fn open_entry(&self, index: usize) -> Result<EntryReader<'_>> {
        let rec = self
            .index
            .files
            .get(index)
            .ok_or_else(|| Error::Other(format!("no entry #{index}")))?;
        Ok(Box::new(PratReader {
            arch: self,
            chunks: &rec.chunks,
            next: 0,
            cur: None,
        }))
    }
}
