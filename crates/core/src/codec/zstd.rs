//! Zstandard. The encoder is libzstd (levels 1..=22); parallelism comes from cutting the input into blocks
//! and compressing each block as its own frame. A sequence of frames is a valid Zstandard stream, and the
//! pure-Rust reader below (`ruzstd`) decodes any number of them.

use ruzstd::decoding::FrameDecoder;
use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
use std::io::{self, BufRead, Read};

/// Maps Packrat's 1..=9 level scale onto zstd levels: 1 is the fastest, 9 is close to `zstd -19`.
pub fn zstd_level(level: u32) -> i32 {
    const MAP: [i32; 9] = [1, 2, 3, 5, 7, 9, 12, 15, 19];
    MAP[(level.clamp(1, 9) - 1) as usize]
}

/// One independent frame at a native zstd level (1..=22).
pub fn compress_frame_level(data: &[u8], zstd_level: i32) -> Vec<u8> {
    ::zstd::bulk::compress(data, zstd_level).expect("zstd cannot fail on in-memory input")
}

/// One independent frame at the fastest level.
pub fn compress_frame(data: &[u8]) -> Vec<u8> {
    compress_frame_level(data, 1)
}

/// Reads a stream of concatenated Zstandard frames (skippable frames are ignored).
pub struct ZstdReader<R: BufRead> {
    src: R,
    frame: FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> ZstdReader<R> {
    pub fn new(src: R) -> Self {
        Self {
            src,
            frame: FrameDecoder::new(),
            in_frame: false,
        }
    }
}

fn other<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::other(e)
}

impl<R: BufRead> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.in_frame {
                while self.frame.can_collect() == 0 && !self.frame.is_finished() {
                    self.frame
                        .decode_blocks(&mut self.src, ruzstd::decoding::BlockDecodingStrategy::UptoBlocks(1))
                        .map_err(other)?;
                }
                if self.frame.can_collect() > 0 {
                    return self.frame.read(buf);
                }
                self.in_frame = false;
            }
            if self.src.fill_buf()?.is_empty() {
                return Ok(0);
            }
            match self.frame.init(&mut self.src) {
                Ok(()) => self.in_frame = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame { length, .. })) => {
                    io::copy(&mut (&mut self.src).take(length as u64), &mut io::sink())?;
                }
                Err(e) => return Err(other(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 12345u32;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                if i % 3 == 0 {
                    (x >> 24) as u8
                } else {
                    b"packrat "[i % 8]
                }
            })
            .collect()
    }

    #[test]
    fn multi_frame_roundtrip() {
        let data = sample(1_000_000);
        let mut packed = Vec::new();
        for chunk in data.chunks(300_000) {
            packed.extend(compress_frame(chunk));
        }
        // a skippable frame in the middle must be ignored
        packed.extend([0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
        packed.extend(compress_frame(b"tail"));
        let mut out = Vec::new();
        ZstdReader::new(Cursor::new(packed)).read_to_end(&mut out).unwrap();
        assert_eq!(&out[..data.len()], &data[..]);
        assert_eq!(&out[data.len()..], b"tail");
    }

    #[test]
    fn every_level_roundtrips_and_higher_is_not_larger() {
        let data = sample(600_000);
        let mut prev = usize::MAX;
        for level in 1..=9 {
            let packed = compress_frame_level(&data, zstd_level(level));
            let mut out = Vec::new();
            ZstdReader::new(Cursor::new(&packed)).read_to_end(&mut out).unwrap();
            assert_eq!(out, data, "level {level}");
            assert!(
                packed.len() <= prev.saturating_add(prev / 50),
                "level {level} got much larger"
            );
            prev = packed.len();
        }
    }

    #[test]
    fn empty_input_gives_empty_output() {
        let mut out = Vec::new();
        ZstdReader::new(Cursor::new(Vec::new())).read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
        let packed = compress_frame(b"");
        ZstdReader::new(Cursor::new(packed)).read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
