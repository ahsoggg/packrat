use super::crypto::{AES256_STRENGTH, AesWriter};
use super::{
    METHOD_DEFLATE, METHOD_STORE, METHOD_ZSTD, SIG_CENTRAL, SIG_DESCRIPTOR, SIG_EOCD, SIG_EOCD64, SIG_LOC64, SIG_LOCAL,
};
use crate::codec::{deflate, zstd};
use crate::error::{Error, Result};
use crate::input::InputItem;
use crate::options::Password;
use crate::par::OrderedPool;
use crate::progress::Progress;
use crate::source::{FileSource, Source};
use crate::timeutil;
use std::io::{self, Write};
use std::path::Path;

/// Entries this big get Zip64 fields up front: their compressed size is not known when the header is written.
const ZIP64_ENTRY_THRESHOLD: u64 = 0xFFFF_FFFF - (64 << 20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZipMethod {
    Store,
    Deflate,
    Zstd,
}

#[derive(Clone, Debug)]
pub struct ZipOptions {
    pub method: ZipMethod,
    /// Deflate level 1..=9 (ignored by the other methods).
    pub level: u32,
    /// Worker threads; 0 = all cores.
    pub threads: usize,
    /// Files larger than this are cut into blocks that are compressed in parallel.
    pub block_size: usize,
    /// Encrypt file contents with WinZip AES-256 (names stay readable; ZipCrypto is never written).
    pub password: Option<Password>,
}

impl Default for ZipOptions {
    fn default() -> Self {
        Self {
            method: ZipMethod::Deflate,
            level: 6,
            threads: 0,
            block_size: 4 << 20,
            password: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ZipStats {
    pub entries: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

struct Block {
    item: usize,
    index: usize,
    count: usize,
    method: u16,
    data: Vec<u8>,
    raw_len: u64,
    crc: u32,
}

struct Counting<W: Write> {
    inner: W,
    pos: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct Central {
    name: Vec<u8>,
    flags: u16,
    method: u16,
    time: u16,
    date: u16,
    mtime: Option<u32>,
    crc: u32,
    csize: u64,
    usize: u64,
    offset: u64,
    external: u32,
    is_zip64: bool,
    /// Set when the data is AES-encrypted: the compression method that is hidden behind method 99.
    aes_method: Option<u16>,
}

struct Open {
    central: Central,
    crc: crc32fast::Hasher,
    aes: Option<AesWriter>,
}

fn read_block(path: &Path, offset: u64, want: usize) -> Result<Vec<u8>> {
    let src = FileSource::open(path)?;
    let mut buf = vec![0u8; want];
    let mut got = 0;
    while got < want {
        match src.read_at(offset + got as u64, &mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

fn compress(method: ZipMethod, level: u32, raw: Vec<u8>, last: bool, single: bool) -> (u16, Vec<u8>) {
    let packed = match method {
        ZipMethod::Store => return (METHOD_STORE, raw),
        _ if raw.is_empty() => return (METHOD_STORE, raw),
        ZipMethod::Deflate => (METHOD_DEFLATE, deflate::compress_block(&raw, level, last)),
        ZipMethod::Zstd => (METHOD_ZSTD, zstd::compress_frame_level(&raw, zstd::zstd_level(level))),
    };
    // Incompressible single-block files are stored as they are (a multi-block entry has one method for all blocks).
    if single && packed.1.len() >= raw.len() {
        (METHOD_STORE, raw)
    } else {
        packed
    }
}

/// WinZip AES extra field (AE-2, AES-256).
fn aes_extra(actual_method: u16) -> Vec<u8> {
    let mut v = vec![0x01, 0x99, 7, 0, 2, 0, b'A', b'E', AES256_STRENGTH];
    v.extend(actual_method.to_le_bytes());
    v
}

fn stored_method(c: &Central) -> u16 {
    if c.aes_method.is_some() { 99 } else { c.method }
}

fn version_needed(method: u16, zip64: bool, aes: bool) -> u16 {
    if aes {
        51
    } else if zip64 {
        45
    } else if method == METHOD_ZSTD {
        63
    } else {
        20
    }
}

fn ext_time_field(mtime: Option<u32>) -> Vec<u8> {
    match mtime {
        Some(t) => {
            let mut v = vec![0x55, 0x54, 5, 0, 1];
            v.extend(t.to_le_bytes());
            v
        }
        None => Vec::new(),
    }
}

struct Sink<'a, W: Write> {
    password: Option<Password>,
    w: Counting<W>,
    central: Vec<Central>,
    open: Option<Open>,
    items: &'a [InputItem],
    stats: ZipStats,
}

impl<W: Write> Sink<'_, W> {
    fn dos_time(item: &InputItem) -> (u16, u16, Option<u32>) {
        match item.mtime {
            Some(utc) => {
                let (d, t) = timeutil::naive_to_dos(timeutil::utc_to_local(utc));
                (t, d, u32::try_from(utc).ok())
            }
            None => (0, 0x21, None),
        }
    }

    fn write_local_header(&mut self, c: &Central, descriptor: bool) -> io::Result<()> {
        let mut extra = ext_time_field(c.mtime);
        if let Some(m) = c.aes_method {
            extra.extend(aes_extra(m));
        }
        let (csize32, usize32) = if descriptor && c.is_zip64 {
            extra.extend([1, 0, 16, 0]);
            extra.extend([0u8; 16]);
            (u32::MAX, u32::MAX)
        } else if descriptor {
            (0, 0)
        } else {
            (c.csize as u32, c.usize as u32)
        };
        let flags = c.flags;
        let w = &mut self.w;
        w.write_all(&SIG_LOCAL.to_le_bytes())?;
        w.write_all(&version_needed(c.method, c.is_zip64, c.aes_method.is_some()).to_le_bytes())?;
        w.write_all(&flags.to_le_bytes())?;
        w.write_all(&stored_method(c).to_le_bytes())?;
        w.write_all(&c.time.to_le_bytes())?;
        w.write_all(&c.date.to_le_bytes())?;
        w.write_all(&(if descriptor { 0 } else { c.crc }).to_le_bytes())?;
        w.write_all(&csize32.to_le_bytes())?;
        w.write_all(&usize32.to_le_bytes())?;
        w.write_all(&(c.name.len() as u16).to_le_bytes())?;
        w.write_all(&(extra.len() as u16).to_le_bytes())?;
        w.write_all(&c.name)?;
        w.write_all(&extra)
    }

    fn consume(&mut self, block: Block) -> Result<()> {
        let item = &self.items[block.item];
        let (time, date, mtime) = Self::dos_time(item);
        let name = item.name.clone();
        let flags = if name.is_ascii() { 0 } else { 0x0800 };
        let external = if item.is_dir { 0x10 } else { 0x20 };
        let big = item.size >= ZIP64_ENTRY_THRESHOLD;
        self.stats.bytes_in += block.raw_len;
        self.stats.bytes_out += block.data.len() as u64;

        let encrypt = self.password.is_some() && !item.is_dir;

        if block.count == 1 {
            let mut data = block.data;
            let mut crc = block.crc;
            let mut aes_method = None;
            let mut flags = flags;
            if encrypt {
                let mut aes = AesWriter::new(self.password.as_ref().expect("checked").expose())?;
                let mut stored = aes.header();
                aes.encrypt(&mut data);
                stored.append(&mut data);
                stored.extend(aes.finish());
                data = stored;
                crc = 0; // AE-2: the authentication code protects the data, the CRC field is zero
                aes_method = Some(block.method);
                flags |= 1;
            }
            let c = Central {
                name: name.into_bytes(),
                flags,
                method: block.method,
                time,
                date,
                mtime,
                crc,
                csize: data.len() as u64,
                usize: block.raw_len,
                offset: self.w.pos,
                external,
                is_zip64: false,
                aes_method,
            };
            self.write_local_header(&c, false)?;
            self.w.write_all(&data)?;
            self.central.push(c);
            return Ok(());
        }

        if block.index == 0 {
            let aes = if encrypt {
                Some(AesWriter::new(self.password.as_ref().expect("checked").expose())?)
            } else {
                None
            };
            let c = Central {
                name: name.into_bytes(),
                flags: flags | 8 | u16::from(aes.is_some()),
                method: block.method,
                time,
                date,
                mtime,
                crc: 0,
                csize: 0,
                usize: 0,
                offset: self.w.pos,
                external,
                is_zip64: big,
                aes_method: aes.as_ref().map(|_| block.method),
            };
            self.write_local_header(&c, true)?;
            let mut open = Open {
                central: c,
                crc: crc32fast::Hasher::new(),
                aes,
            };
            if let Some(a) = &open.aes {
                let h = a.header();
                self.w.write_all(&h)?;
                open.central.csize += h.len() as u64;
            }
            self.open = Some(open);
        }
        let open = self.open.as_mut().expect("block order is preserved");
        let mut data = block.data;
        if let Some(a) = open.aes.as_mut() {
            a.encrypt(&mut data);
        }
        self.w.write_all(&data)?;
        open.central.csize += data.len() as u64;
        open.central.usize += block.raw_len;
        open.crc
            .combine(&crc32fast::Hasher::new_with_initial_len(block.crc, block.raw_len));

        if block.index + 1 == block.count {
            let mut open = self.open.take().expect("entry is open");
            open.central.crc = open.crc.finalize();
            if let Some(a) = open.aes.take() {
                let tag = a.finish();
                self.w.write_all(&tag)?;
                open.central.csize += tag.len() as u64;
                open.central.crc = 0; // AE-2
            }
            let c = &open.central;
            self.w.write_all(&SIG_DESCRIPTOR.to_le_bytes())?;
            self.w.write_all(&c.crc.to_le_bytes())?;
            if c.is_zip64 {
                self.w.write_all(&c.csize.to_le_bytes())?;
                self.w.write_all(&c.usize.to_le_bytes())?;
            } else {
                self.w.write_all(&(c.csize as u32).to_le_bytes())?;
                self.w.write_all(&(c.usize as u32).to_le_bytes())?;
            }
            let mut done = open.central;
            // sizes above 4 GiB need Zip64 fields even when the estimate said otherwise
            done.is_zip64 = done.is_zip64 || done.csize >= u32::MAX as u64 || done.usize >= u32::MAX as u64;
            self.central.push(done);
        }
        Ok(())
    }

    fn write_central_directory(&mut self) -> Result<()> {
        let cd_start = self.w.pos;
        let entries = std::mem::take(&mut self.central);
        for c in &entries {
            let big_sizes = c.csize >= u32::MAX as u64 || c.usize >= u32::MAX as u64;
            let big_offset = c.offset >= u32::MAX as u64;
            let mut extra = ext_time_field(c.mtime);
            if let Some(m) = c.aes_method {
                extra.extend(aes_extra(m));
            }
            let mut z = Vec::new();
            if big_sizes {
                z.extend(c.usize.to_le_bytes());
                z.extend(c.csize.to_le_bytes());
            }
            if big_offset {
                z.extend(c.offset.to_le_bytes());
            }
            if !z.is_empty() {
                extra.extend([1, 0]);
                extra.extend((z.len() as u16).to_le_bytes());
                extra.extend(z);
            }
            let zip64 = big_sizes || big_offset;
            let w = &mut self.w;
            w.write_all(&SIG_CENTRAL.to_le_bytes())?;
            w.write_all(&63u16.to_le_bytes())?; // made by: MS-DOS / NTFS family, spec 6.3
            w.write_all(&version_needed(c.method, zip64, c.aes_method.is_some()).to_le_bytes())?;
            w.write_all(&c.flags.to_le_bytes())?;
            w.write_all(&stored_method(c).to_le_bytes())?;
            w.write_all(&c.time.to_le_bytes())?;
            w.write_all(&c.date.to_le_bytes())?;
            w.write_all(&c.crc.to_le_bytes())?;
            w.write_all(&(if big_sizes { u32::MAX } else { c.csize as u32 }).to_le_bytes())?;
            w.write_all(&(if big_sizes { u32::MAX } else { c.usize as u32 }).to_le_bytes())?;
            w.write_all(&(c.name.len() as u16).to_le_bytes())?;
            w.write_all(&(extra.len() as u16).to_le_bytes())?;
            w.write_all(&0u16.to_le_bytes())?; // comment
            w.write_all(&0u16.to_le_bytes())?; // disk
            w.write_all(&0u16.to_le_bytes())?; // internal attributes
            w.write_all(&c.external.to_le_bytes())?;
            w.write_all(&(if big_offset { u32::MAX } else { c.offset as u32 }).to_le_bytes())?;
            w.write_all(&c.name)?;
            w.write_all(&extra)?;
        }
        let cd_end = self.w.pos;
        let cd_size = cd_end - cd_start;
        let n = entries.len() as u64;
        let need64 = n >= 0xFFFF || cd_size >= u32::MAX as u64 || cd_start >= u32::MAX as u64;
        let w = &mut self.w;
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
        w.write_all(&0u16.to_le_bytes())?;
        w.flush()?;
        self.stats.entries = entries.len();
        Ok(())
    }
}

/// Writes `items` as a ZIP archive. Entries and blocks are compressed on `opts.threads` workers and written
/// in order, with a bounded number of blocks in flight.
pub fn write_zip<W: Write>(out: W, items: &[InputItem], opts: &ZipOptions, progress: &Progress) -> Result<ZipStats> {
    let total: u64 = items.iter().map(|i| i.size).sum();
    progress.set_totals(items.iter().filter(|i| !i.is_dir).count() as u64, total);
    let block_size = opts.block_size.max(64 << 10);
    let mut pool = OrderedPool::<Result<Block>>::new(opts.threads)?;
    let mut sink = Sink {
        password: opts.password.clone(),
        w: Counting { inner: out, pos: 0 },
        central: Vec::with_capacity(items.len()),
        open: None,
        items,
        stats: ZipStats::default(),
    };

    let mut deliver = |res: Result<Block>| -> Result<()> {
        let block = res?;
        progress.check()?;
        let last = block.index + 1 == block.count;
        let raw = block.raw_len;
        sink.consume(block)?;
        progress.add_bytes(raw);
        if last {
            progress.add_file();
        }
        Ok(())
    };

    for (idx, item) in items.iter().enumerate() {
        progress.check()?;
        if item.is_dir {
            let b = Block {
                item: idx,
                index: 0,
                count: 1,
                method: METHOD_STORE,
                data: Vec::new(),
                raw_len: 0,
                crc: 0,
            };
            pool.push_ready(Ok(b), &mut deliver)?;
            continue;
        }
        progress.set_current(&item.name);
        let count = (item.size as usize).div_ceil(block_size).max(1);
        for index in 0..count {
            let path = item.disk_path.clone();
            let (method, level) = (opts.method, opts.level);
            let offset = (index * block_size) as u64;
            let want = block_size.min(item.size.saturating_sub(offset) as usize);
            pool.submit(
                move || {
                    let raw = read_block(&path, offset, want)
                        .map_err(|e| Error::Other(format!("cannot read '{}': {e}", path.display())))?;
                    let crc = crc32fast::hash(&raw);
                    let raw_len = raw.len() as u64;
                    let (m, data) = compress(method, level, raw, index + 1 == count, count == 1);
                    Ok(Block {
                        item: idx,
                        index,
                        count,
                        method: m,
                        data,
                        raw_len,
                        crc,
                    })
                },
                &mut deliver,
            )?;
        }
    }
    pool.finish(&mut deliver)?;
    sink.write_central_directory()?;
    Ok(sink.stats)
}
