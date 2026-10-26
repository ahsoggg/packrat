//! Writing a `.prat` archive: files are cut into content-defined chunks, chunks that were seen before are only
//! referenced, new chunks are collected into blocks of several MiB that are compressed on worker threads, and the
//! index goes at the end.

use super::format::*;
use crate::codec::zstd::zstd_level;
use crate::error::{Error, Result};
use crate::input::InputItem;
use crate::par::OrderedPool;
use crate::progress::Progress;
use fastcdc::v2020::{FastCDC, StreamCDC};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};

/// Files up to this size are read whole and cut in memory; bigger ones are streamed.
const IN_MEMORY_LIMIT: u64 = 64 << 20;

#[derive(Clone, Debug)]
pub struct PratOptions {
    /// 1..=9 (zstd 1..19).
    pub level: u32,
    /// 0 = all cores.
    pub threads: usize,
    /// Uncompressed bytes per block: a bigger block compresses better, a smaller one opens one file faster.
    pub block_bytes: usize,
    pub min_chunk: u32,
    pub avg_chunk: u32,
    pub max_chunk: u32,
}

impl Default for PratOptions {
    fn default() -> Self {
        Self {
            level: 6,
            threads: 0,
            block_bytes: 16 << 20,
            min_chunk: 16 << 10,
            avg_chunk: 64 << 10,
            max_chunk: 256 << 10,
        }
    }
}

/// What deduplication did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PratStats {
    pub chunks: u64,
    pub unique_chunks: u64,
    pub bytes_in: u64,
    pub unique_bytes: u64,
    pub blocks: u64,
}

struct Packed {
    header: BlockHeader,
    payload: Vec<u8>,
}

fn pack_block(raw: Vec<u8>, level: i32) -> Packed {
    let hash = *blake3::hash(&raw).as_bytes();
    let ulen = raw.len() as u32;
    match zstd::bulk::compress(&raw, level) {
        Ok(c) if c.len() < raw.len() => Packed {
            header: BlockHeader {
                codec: CODEC_ZSTD,
                clen: c.len() as u32,
                ulen,
                hash,
            },
            payload: c,
        },
        _ => Packed {
            header: BlockHeader {
                codec: CODEC_STORE,
                clen: ulen,
                ulen,
                hash,
            },
            payload: raw,
        },
    }
}

struct Sink<W: Write> {
    out: W,
    pos: u64,
    blocks: Vec<BlockRef>,
}

impl<W: Write> Sink<W> {
    fn accept(&mut self, p: Packed) -> Result<()> {
        self.out.write_all(&p.header.encode())?;
        self.out.write_all(&p.payload)?;
        self.blocks.push(BlockRef {
            offset: self.pos,
            clen: p.header.clen,
            ulen: p.header.ulen,
            codec: p.header.codec,
        });
        self.pos += (BLOCK_HEADER_LEN + p.payload.len()) as u64;
        Ok(())
    }
}

struct Builder<'a, W: Write> {
    opts: &'a PratOptions,
    zstd_level: i32,
    pool: OrderedPool<Packed>,
    sink: Sink<W>,
    seen: HashMap<[u8; 32], u32>,
    chunks: Vec<ChunkRef>,
    cur: Vec<u8>,
    /// Blocks handed to the pool so far: the id of the block that `cur` will become.
    submitted: u32,
    stats: PratStats,
    progress: &'a Progress,
}

impl<W: Write> Builder<'_, W> {
    fn flush_block(&mut self) -> Result<()> {
        if self.cur.is_empty() {
            return Ok(());
        }
        let raw = std::mem::replace(&mut self.cur, Vec::with_capacity(self.opts.block_bytes));
        let level = self.zstd_level;
        let sink = &mut self.sink;
        self.pool
            .submit(move || pack_block(raw, level), &mut |p| sink.accept(p))?;
        self.submitted += 1;
        self.stats.blocks += 1;
        Ok(())
    }

    /// Returns the id of the chunk with this content, adding it to the current block if it is new.
    fn add_chunk(&mut self, data: &[u8]) -> Result<u32> {
        self.progress.check()?;
        let hash = *blake3::hash(data).as_bytes();
        self.stats.chunks += 1;
        self.stats.bytes_in += data.len() as u64;
        self.progress.add_bytes(data.len() as u64);
        if let Some(&id) = self.seen.get(&hash) {
            return Ok(id);
        }
        if !self.cur.is_empty() && self.cur.len() + data.len() > self.opts.block_bytes {
            self.flush_block()?;
        }
        let id =
            u32::try_from(self.chunks.len()).map_err(|_| Error::Other("too many chunks for one archive".into()))?;
        self.chunks.push(ChunkRef {
            block: self.submitted,
            offset: self.cur.len() as u32,
            len: data.len() as u32,
            hash,
        });
        self.cur.extend_from_slice(data);
        self.seen.insert(hash, id);
        self.stats.unique_chunks += 1;
        self.stats.unique_bytes += data.len() as u64;
        if self.cur.len() >= self.opts.block_bytes {
            self.flush_block()?;
        }
        Ok(id)
    }

    /// Reads one file and returns its chunk ids and its real size.
    fn add_file(&mut self, item: &InputItem) -> Result<(Vec<u32>, u64)> {
        let mut file = File::open(&item.disk_path)
            .map_err(|e| Error::Other(format!("cannot read '{}': {e}", item.disk_path.display())))?;
        let (min, avg, max) = (self.opts.min_chunk, self.opts.avg_chunk, self.opts.max_chunk);
        let mut ids = Vec::new();
        let mut total = 0u64;
        if item.size <= IN_MEMORY_LIMIT {
            let mut data = Vec::with_capacity(item.size as usize);
            file.read_to_end(&mut data)?;
            total = data.len() as u64;
            if data.len() <= min as usize {
                if !data.is_empty() {
                    ids.push(self.add_chunk(&data)?);
                }
            } else {
                for c in FastCDC::new(&data, min, avg, max) {
                    ids.push(self.add_chunk(&data[c.offset..c.offset + c.length])?);
                }
            }
        } else {
            for c in StreamCDC::new(file, min, avg, max) {
                let c = c.map_err(|e| Error::Other(format!("cannot read '{}': {e}", item.disk_path.display())))?;
                total += c.data.len() as u64;
                ids.push(self.add_chunk(&c.data)?);
            }
        }
        Ok((ids, total))
    }
}

pub fn write_prat<W: Write>(out: W, items: &[InputItem], opts: &PratOptions, progress: &Progress) -> Result<PratStats> {
    progress.set_totals(
        items.iter().filter(|i| !i.is_dir).count() as u64,
        items.iter().map(|i| i.size).sum(),
    );
    let mut out = BufWriter::with_capacity(1 << 20, out);
    out.write_all(&header_bytes())?;
    let mut b = Builder {
        opts,
        zstd_level: zstd_level(opts.level),
        pool: OrderedPool::new(opts.threads)?,
        sink: Sink {
            out,
            pos: HEADER_LEN,
            blocks: Vec::new(),
        },
        seen: HashMap::new(),
        chunks: Vec::new(),
        cur: Vec::with_capacity(opts.block_bytes),
        submitted: 0,
        stats: PratStats::default(),
        progress,
    };

    let mut files = Vec::with_capacity(items.len());
    for item in items {
        progress.check()?;
        let path = item.name.trim_end_matches('/').to_owned();
        if item.is_dir {
            files.push(FileRec {
                path,
                kind: KIND_DIR,
                size: 0,
                mtime: item.mtime,
                mode: None,
                chunks: Vec::new(),
            });
            continue;
        }
        progress.set_current(&item.name);
        let (ids, size) = b.add_file(item)?;
        files.push(FileRec {
            path,
            kind: KIND_FILE,
            size,
            mtime: item.mtime,
            mode: None,
            chunks: ids,
        });
        progress.add_file();
    }
    b.flush_block()?;
    let sink = &mut b.sink;
    b.pool.finish(&mut |p| sink.accept(p))?;

    let index = Index {
        blocks: std::mem::take(&mut b.sink.blocks),
        chunks: std::mem::take(&mut b.chunks),
        files,
    };
    let raw = index.encode();
    let stored = match zstd::bulk::compress(&raw, 6) {
        Ok(c) if c.len() < raw.len() => c,
        _ => raw.clone(),
    };
    let footer = Footer {
        index_offset: b.sink.pos,
        index_clen: stored.len() as u64,
        index_ulen: raw.len() as u64,
        index_hash: *blake3::hash(&stored).as_bytes(),
    };
    b.sink.out.write_all(&stored)?;
    b.sink.out.write_all(&footer.encode())?;
    b.sink.out.flush()?;
    Ok(b.stats)
}
