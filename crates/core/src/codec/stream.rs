//! Single compressed streams (`.gz`, `.bz2`, `.xz`, `.zst`, `.lz4`) as readers, and the parallel writers
//! used for `tar.gz`, `tar.zst`, `tar.xz` and `tar.lz4`.

use super::deflate;
use super::zstd::{self, ZstdReader};
use crate::error::Result;
use crate::par::{OrderedPool, resolve_threads};
use std::io::{self, BufReader, Read, Write};
use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Gz,
    Bz2,
    Xz,
    Zst,
    Lz4,
}

impl Compression {
    pub fn detect(head: &[u8]) -> Self {
        match head {
            [0x1f, 0x8b, ..] => Compression::Gz,
            [b'B', b'Z', b'h', ..] => Compression::Bz2,
            [0xfd, b'7', b'z', b'X', b'Z', 0, ..] => Compression::Xz,
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Compression::Zst,
            [0x04, 0x22, 0x4d, 0x18, ..] => Compression::Lz4,
            _ => Compression::None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gz => "gz",
            Compression::Bz2 => "bz2",
            Compression::Xz => "xz",
            Compression::Zst => "zst",
            Compression::Lz4 => "lz4",
        }
    }
}

/// Wraps `r` in the decoder for `c`.
pub fn reader<'a, R: Read + Send + 'a>(c: Compression, r: R) -> Box<dyn Read + Send + 'a> {
    let r = BufReader::with_capacity(128 << 10, r);
    match c {
        Compression::None => Box::new(r),
        Compression::Gz => Box::new(flate2::bufread::MultiGzDecoder::new(r)),
        Compression::Bz2 => Box::new(bzip2::bufread::MultiBzDecoder::new(r)),
        Compression::Xz => Box::new(lzma_rust2::XzReader::new(r, true)),
        Compression::Zst => Box::new(ZstdReader::new(r)),
        Compression::Lz4 => Box::new(super::lz4::Lz4Reader::new(r)),
    }
}

/// A `Write` that must be finished explicitly, so that trailers are written and errors are not lost.
pub trait FinishWrite: Write + Send {
    fn finish(self: Box<Self>) -> Result<()>;
}

struct Plain<W: Write + Send>(W);

impl<W: Write + Send> Write for Plain<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write + Send> FinishWrite for Plain<W> {
    fn finish(mut self: Box<Self>) -> Result<()> {
        self.0.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum BlockKind {
    Gzip {
        level: u32,
    },
    Zstd {
        level: u32,
    },
    Lz4,
    /// Independent bzip2 streams one after another: a valid multi-stream file that every reader accepts.
    Bzip2 {
        level: u32,
    },
}

struct Encoded {
    data: Vec<u8>,
    crc: u32,
    raw_len: u64,
}

struct Out<W: Write> {
    inner: W,
    crc: crc32fast::Hasher,
    total: u64,
    wrote_anything: bool,
}

impl<W: Write> Out<W> {
    fn accept(&mut self, res: Result<Encoded>) -> Result<()> {
        let e = res?;
        self.inner.write_all(&e.data)?;
        self.crc
            .combine(&crc32fast::Hasher::new_with_initial_len(e.crc, e.raw_len));
        self.total += e.raw_len;
        self.wrote_anything = true;
        Ok(())
    }
}

/// Cuts the input into blocks, compresses them on worker threads and writes the results in order.
struct ParWriter<W: Write + Send + 'static> {
    out: Out<W>,
    pool: OrderedPool<Result<Encoded>>,
    kind: BlockKind,
    block_size: usize,
    buf: Vec<u8>,
}

fn encode(kind: BlockKind, chunk: &[u8]) -> Encoded {
    let data = match kind {
        BlockKind::Gzip { level } => deflate::compress_block(chunk, level, false),
        BlockKind::Zstd { level } => zstd::compress_frame_level(chunk, zstd::zstd_level(level)),
        BlockKind::Bzip2 { level } => {
            let mut enc = bzip2::write::BzEncoder::new(
                Vec::with_capacity(chunk.len() / 3 + 64),
                bzip2::Compression::new(level.clamp(1, 9)),
            );
            enc.write_all(chunk).expect("writing to memory");
            enc.finish().expect("finishing a stream in memory")
        }
        BlockKind::Lz4 => {
            let info = lz4_flex::frame::FrameInfo::new().block_size(lz4_flex::frame::BlockSize::Max1MB);
            let mut enc =
                lz4_flex::frame::FrameEncoder::with_frame_info(info, Vec::with_capacity(chunk.len() / 2 + 64));
            enc.write_all(chunk).expect("writing to memory");
            enc.finish().expect("finishing a frame in memory")
        }
    };
    Encoded {
        data,
        crc: crc32fast::hash(chunk),
        raw_len: chunk.len() as u64,
    }
}

impl<W: Write + Send + 'static> ParWriter<W> {
    fn new(mut inner: W, kind: BlockKind, threads: usize) -> Result<Self> {
        if matches!(kind, BlockKind::Gzip { .. }) {
            // magic, deflate, no flags, no mtime, no extra flags, OS = NTFS
            inner.write_all(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 11])?;
        }
        let block_size = match kind {
            BlockKind::Gzip { .. } => 1 << 20,
            BlockKind::Zstd { .. } | BlockKind::Lz4 | BlockKind::Bzip2 { .. } => 4 << 20,
        };
        Ok(Self {
            out: Out {
                inner,
                crc: crc32fast::Hasher::new(),
                total: 0,
                wrote_anything: false,
            },
            pool: OrderedPool::new(threads)?,
            kind,
            block_size,
            buf: Vec::with_capacity(block_size),
        })
    }

    fn submit_block(&mut self, chunk: Vec<u8>) -> Result<()> {
        let kind = self.kind;
        let out = &mut self.out;
        self.pool
            .submit(move || Ok(encode(kind, &chunk)), &mut |r| out.accept(r))
    }
}

impl<W: Write + Send + 'static> Write for ParWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= self.block_size {
            let rest = self.buf.split_off(self.block_size);
            let chunk = std::mem::replace(&mut self.buf, rest);
            self.submit_block(chunk)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write + Send + 'static> FinishWrite for ParWriter<W> {
    fn finish(mut self: Box<Self>) -> Result<()> {
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            self.submit_block(chunk)?;
        }
        let out = &mut self.out;
        self.pool.finish(&mut |r| out.accept(r))?;
        let kind = self.kind;
        let out = &mut self.out;
        match kind {
            BlockKind::Gzip { .. } => {
                // final empty stored block, then CRC-32 and size modulo 2^32
                out.inner.write_all(&[1, 0, 0, 0xff, 0xff])?;
                out.inner.write_all(&out.crc.clone().finalize().to_le_bytes())?;
                out.inner.write_all(&(out.total as u32).to_le_bytes())?;
            }
            BlockKind::Zstd { .. } if !out.wrote_anything => out.inner.write_all(&zstd::compress_frame(b""))?,
            BlockKind::Lz4 | BlockKind::Bzip2 { .. } if !out.wrote_anything => {
                out.inner.write_all(&encode(kind, b"").data)?
            }
            _ => {}
        }
        out.inner.flush()?;
        Ok(())
    }
}

struct XzOut<W: Write + Send + 'static>(lzma_rust2::XzWriterMt<W>);

impl<W: Write + Send + 'static> Write for XzOut<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write + Send + 'static> FinishWrite for XzOut<W> {
    fn finish(self: Box<Self>) -> Result<()> {
        let mut w = self.0.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Compression writer for `tar.*` output. `level` is 1..=9 (deflate, zstd and xz); lz4 has one level here.
pub fn writer<W: Write + Send + 'static>(
    c: Compression,
    out: W,
    level: u32,
    threads: usize,
) -> Result<Box<dyn FinishWrite>> {
    Ok(match c {
        Compression::None => Box::new(Plain(out)),
        Compression::Gz => Box::new(ParWriter::new(
            out,
            BlockKind::Gzip {
                level: level.clamp(1, 9),
            },
            threads,
        )?),
        Compression::Zst => Box::new(ParWriter::new(out, BlockKind::Zstd { level }, threads)?),
        Compression::Lz4 => Box::new(ParWriter::new(out, BlockKind::Lz4, threads)?),
        Compression::Xz => {
            let mut opts = lzma_rust2::XzOptions::with_preset(level.clamp(1, 9));
            opts.set_block_size(NonZeroU64::new(8 << 20));
            let w = lzma_rust2::XzWriterMt::new(out, opts, resolve_threads(threads) as u32)?;
            Box::new(XzOut(w))
        }
        Compression::Bz2 => Box::new(ParWriter::new(
            out,
            BlockKind::Bzip2 {
                level: level.clamp(1, 9),
            },
            threads,
        )?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 99u32;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                if i % 5 < 3 { b"abcdefgh"[i % 8] } else { (x >> 24) as u8 }
            })
            .collect()
    }

    #[test]
    fn every_writer_roundtrips_through_its_reader() {
        for size in [0usize, 1, 1000, 4_500_000] {
            let data = sample(size);
            for c in [
                Compression::Gz,
                Compression::Zst,
                Compression::Lz4,
                Compression::Xz,
                Compression::Bz2,
            ] {
                for threads in [1, 3] {
                    let sink = Shared::default();
                    let mut w = writer(c, sink.clone(), 4, threads).unwrap();
                    for part in data.chunks(777_777) {
                        w.write_all(part).unwrap();
                    }
                    w.finish().unwrap();
                    let packed = sink.0.lock().unwrap().clone();
                    assert_eq!(Compression::detect(&packed), c, "{c:?} magic");
                    let mut out = Vec::new();
                    reader(c, io::Cursor::new(packed)).read_to_end(&mut out).unwrap();
                    let first_diff = out.iter().zip(&data).position(|(a, b)| a != b);
                    assert!(
                        out == data,
                        "{c:?} size {size} threads {threads}: got {} bytes, want {}, first diff {first_diff:?}",
                        out.len(),
                        data.len()
                    );
                }
            }
        }
    }

    #[test]
    fn gzip_output_is_readable_by_a_plain_gzip_decoder() {
        let data = sample(3_000_000);
        let sink = Shared::default();
        let mut w = writer(Compression::Gz, sink.clone(), 6, 4).unwrap();
        w.write_all(&data).unwrap();
        w.finish().unwrap();
        let packed = sink.0.lock().unwrap().clone();
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&packed[..]).read_to_end(&mut out).unwrap();
        assert!(out == data);
    }
}
