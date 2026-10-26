//! 7z through the pure-Rust `sevenz-rust2`. Reading is block by block (a solid block has to be decoded from
//! its start); writing packs files into solid blocks that are compressed on worker threads.

use crate::analyze::{self, Bcj, Class};
use crate::archive::{Archive, EntryReader, Kind};
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::input::InputItem;
use crate::options::{OpenOptions, Password as CorePassword};
use crate::par::OrderedPool;
use crate::progress::Progress;
use crate::source::{SharedSource, SourceReader};
use crate::timeutil;
use sevenz_rust2::encoder_options::{AesEncoderOptions, EncoderOptions, Lzma2Options};
use sevenz_rust2::{ArchiveEntry, BlockDecoder, EncoderConfiguration, EncoderMethod, NtTime, Password};
use std::io::{self, Read, Seek, Write};
use std::sync::Arc;

const MAX_BUFFERED_ENTRY: u64 = 512 << 20;

fn map_err(e: sevenz_rust2::Error) -> Error {
    map_err_with(e, false)
}

/// `had_password`: a password was supplied, so a decryption failure means it is wrong.
fn map_err_with(e: sevenz_rust2::Error, had_password: bool) -> Error {
    use sevenz_rust2::Error as E;
    match e {
        E::Io(e, _) | E::FileOpen(e, _) => Error::Io(e),
        E::PasswordRequired => Error::PasswordRequired,
        E::MaybeBadPassword(_) if had_password => Error::WrongPassword,
        E::MaybeBadPassword(_) => Error::PasswordRequired,
        E::UnsupportedCompressionMethod(m) => Error::Unsupported(format!("7z compression method {m}")),
        E::Unsupported(m) => Error::Unsupported(m.into_owned()),
        E::ChecksumVerificationFailed => Error::Integrity("7z checksum mismatch".into()),
        other => Error::Corrupt(other.to_string()),
    }
}

pub struct SevenZArchive {
    src: SharedSource,
    archive: sevenz_rust2::Archive,
    entries: Vec<Entry>,
    password: Password,
    has_password: bool,
}

fn entry_from(index: usize, f: &ArchiveEntry) -> Entry {
    let attrs = f.has_windows_attributes.then_some(f.windows_attributes);
    let unix_mode = attrs.filter(|a| a & 0x8000 != 0).map(|a| a >> 16);
    let kind = if f.is_directory {
        EntryKind::Dir
    } else if unix_mode.is_some_and(|m| m & 0o170_000 == 0o120_000)
        || attrs.is_some_and(|a| a & 0x400 != 0 && f.has_stream)
    {
        EntryKind::Symlink
    } else {
        EntryKind::File
    };
    let mut e = Entry::new(index, f.name.clone(), kind);
    e.size = f.size;
    e.packed = (f.compressed_size > 0).then_some(f.compressed_size);
    e.crc32 = f.has_crc.then_some(f.crc as u32);
    e.method = "7z".into();
    e.mode = unix_mode;
    if f.has_last_modified_date {
        let st: std::time::SystemTime = f.last_modified_date.into();
        e.mtime = Some(timeutil::system_time_to_unix(st));
    }
    e
}

impl SevenZArchive {
    pub fn from_source(src: SharedSource) -> Result<Self> {
        Self::from_source_with(src, &OpenOptions::default())
    }

    pub fn from_source_with(src: SharedSource, opts: &OpenOptions) -> Result<Self> {
        let has_password = opts.password.is_some();
        let password = opts
            .password
            .as_ref()
            .map_or_else(Password::empty, |p| Password::from(p.expose()));
        let mut rd = SourceReader::new(src.clone());
        let archive = sevenz_rust2::Archive::read(&mut rd, &password).map_err(|e| map_err_with(e, has_password))?;
        let mut entries: Vec<Entry> = archive
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| entry_from(i, f))
            .collect();
        // A header that was written with a short bit vector (older Packrat versions did this) parses "fine" but
        // shifts everything after it, so names come out empty. Only a single entry may legitimately have no name.
        if entries.iter().filter(|e| e.path.is_empty()).count() > 1 {
            return Err(Error::Corrupt(
                "several entries have no name: the 7z header is damaged".into(),
            ));
        }
        for (i, block) in archive.stream_map.file_block_index.iter().enumerate() {
            if let Some(b) = block
                && archive.blocks[*b]
                    .coders
                    .iter()
                    .any(|c| c.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
            {
                entries[i].encrypted = true;
            }
        }
        Ok(Self {
            src,
            archive,
            entries,
            password,
            has_password,
        })
    }

    pub fn is_solid(&self) -> bool {
        self.archive.is_solid
    }
}

impl Archive for SevenZArchive {
    fn kind(&self) -> Kind {
        Kind::SevenZ
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn skip_cost(&self, index: usize) -> u64 {
        // a solid block is decoded from its first file up to the wanted one
        let map = &self.archive.stream_map;
        match map.file_block_index.get(index).copied().flatten() {
            Some(b) => self.entries[map.block_first_file_index[b]..index]
                .iter()
                .map(|e| e.size)
                .sum(),
            None => 0,
        }
    }

    fn open_entry(&self, index: usize) -> Result<EntryReader<'_>> {
        let e = self
            .entries
            .get(index)
            .ok_or_else(|| Error::Other(format!("no entry #{index}")))?;
        if e.size > MAX_BUFFERED_ENTRY {
            return Err(Error::Unsupported(format!(
                "'{}' is too large to open from a 7z archive",
                e.path
            )));
        }
        let mut data = Vec::with_capacity(e.size as usize);
        self.walk(&mut |x| x.index == index, &mut |_, r| {
            r.read_to_end(&mut data)?;
            Ok(())
        })?;
        Ok(Box::new(io::Cursor::new(data)))
    }

    fn walk(
        &self,
        want: &mut dyn FnMut(&Entry) -> bool,
        visit: &mut dyn FnMut(&Entry, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let map = &self.archive.stream_map;
        let mut failure: Option<Error> = None;

        // files without data belong to no block
        for (i, block) in map.file_block_index.iter().enumerate() {
            if block.is_none() && want(&self.entries[i]) {
                visit(&self.entries[i], &mut io::empty())?;
            }
        }

        let mut wanted_blocks = vec![false; self.archive.blocks.len()];
        for (i, block) in map.file_block_index.iter().enumerate() {
            if let Some(b) = block
                && want(&self.entries[i])
            {
                wanted_blocks[*b] = true;
            }
        }

        let mut source = SourceReader::new(self.src.clone());
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
        let base = self.archive.files.as_ptr() as usize;
        let size = std::mem::size_of::<ArchiveEntry>();
        for block_index in (0..self.archive.blocks.len()).filter(|&b| wanted_blocks[b]) {
            let mut each = |ae: &ArchiveEntry, r: &mut dyn Read| -> std::result::Result<bool, sevenz_rust2::Error> {
                // the decoder hands out references into `archive.files`, so the address gives the index
                let index = (ae as *const ArchiveEntry as usize - base) / size;
                let entry = &self.entries[index];
                if !want(entry) {
                    // the solid stream must be read through even for entries nobody asked for
                    io::copy(r, &mut io::sink()).map_err(|e| sevenz_rust2::Error::Io(e, "skipping an entry".into()))?;
                    return Ok(true);
                }
                match visit(entry, r) {
                    Ok(()) => Ok(true),
                    Err(e) => {
                        failure = Some(e);
                        Ok(false)
                    }
                }
            };
            let finished = BlockDecoder::new(threads, block_index, &self.archive, &self.password, &mut source)
                .for_each_entries(&mut each)
                .map_err(|e| map_err_with(e, self.has_password))?;
            if !finished {
                break;
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SevenZOptions {
    /// LZMA2 level 1..=9 (memory per worker grows quickly above 7).
    pub level: u32,
    pub threads: usize,
    /// LZMA2 dictionary in bytes; `None` picks one for the level (and never more than the data needs).
    pub dict_bytes: Option<u32>,
    /// Target size of one solid block; `None` is eight dictionaries, at least 64 MiB. Blocks are compressed in
    /// parallel, and a bigger block finds more repeats (7-Zip's blocks are in the gigabytes).
    pub solid_bytes: Option<u64>,
    /// Encrypt the contents with AES-256.
    pub password: Option<CorePassword>,
    /// With a password: also encrypt the file names (the header).
    pub encrypt_names: bool,
    /// Sort files by type and give executables a BCJ filter and packed data a plain copy (see `analyze`).
    pub smart: bool,
}

impl Default for SevenZOptions {
    fn default() -> Self {
        Self {
            level: 5,
            threads: 0,
            dict_bytes: None,
            solid_bytes: None,
            password: None,
            encrypt_names: true,
            smart: true,
        }
    }
}

/// LZMA2 dictionary for a level. Bigger than xz's presets from level 4 up, closer to 7-Zip's (16 MiB at 5,
/// 64 MiB at 9): the dictionary is the biggest single factor in how much repeated data is found.
fn default_dict(level: u32) -> u32 {
    const MIB: u32 = 1 << 20;
    [
        MIB,
        2 * MIB,
        4 * MIB,
        8 * MIB,
        16 * MIB,
        16 * MIB,
        32 * MIB,
        64 * MIB,
        64 * MIB,
    ][(level.clamp(1, 9) - 1) as usize]
}

/// Rounds a dictionary size up to one that the 7z header can state exactly. The LZMA2 property is a single byte
/// that holds only 2^n and 3 * 2^(n-1); the writer rounds any other size down in the header while the encoder
/// still uses the full size, so readers get a window that is too small and fail on far matches (7-Zip reports
/// a data error). The largest the format and the encoder allow is 3 * 2^28.
fn lzma2_dict(size: u32) -> u32 {
    const MAX: u32 = 3 << 28;
    if size >= MAX {
        return MAX;
    }
    let size = size.max(1 << 12);
    let base = 1u32 << (31 - size.leading_zeros());
    if size == base {
        base
    } else if size <= base + base / 2 {
        base + base / 2
    } else {
        base * 2
    }
}

/// Memory one LZMA2 encoder needs for this dictionary.
fn encoder_bytes(level: u32, dict: u32) -> u64 {
    let mut o = lzma_rust2::Lzma2Options::with_preset(level);
    o.lzma_options.dict_size = dict;
    u64::from(o.lzma_options.get_memory_usage()) * 1024
}

/// Splits the threads between solid blocks and LZMA2 workers inside a block: (blocks packed at the same
/// time, workers per block). At most half of the free memory goes to encoders, whatever the thread count, so
/// a big dictionary on many cores cannot push the machine into swapping.
fn spread(threads: usize, blocks: usize, encoder_bytes: u64, free_memory: u64) -> (usize, usize) {
    let by_memory = usize::try_from(free_memory / 2 / encoder_bytes.max(1)).unwrap_or(usize::MAX);
    let total = threads.min(by_memory).max(1);
    let parallel = total.min(blocks.max(1));
    (parallel, (total / parallel).max(1))
}

enum Piece {
    Dir(ArchiveEntry),
    Empty(ArchiveEntry),
    Block(
        std::result::Result<sevenz_rust2::PreparedBlock, sevenz_rust2::Error>,
        u64,
        u64,
    ),
}

fn entry_for(item: &InputItem) -> ArchiveEntry {
    let name = item.name.trim_end_matches('/').to_owned();
    let mut e = if item.is_dir {
        ArchiveEntry::new_directory(&name)
    } else {
        ArchiveEntry::new_file(&name)
    };
    if let Some(t) = item.mtime.and_then(|t| u64::try_from(t).ok()) {
        let st = std::time::UNIX_EPOCH + std::time::Duration::from_secs(t);
        if let Ok(nt) = NtTime::try_from(st) {
            e.has_last_modified_date = true;
            e.last_modified_date = nt;
        }
    }
    e
}

pub fn write_7z<W: Write + Seek>(out: W, items: &[InputItem], opts: &SevenZOptions, progress: &Progress) -> Result<()> {
    progress.set_totals(
        items.iter().filter(|i| !i.is_dir).count() as u64,
        items.iter().map(|i| i.size).sum(),
    );
    let level = opts.level.clamp(1, 9);

    // Plan the solid blocks. With `smart` set, files are sorted by class and extension and a block never mixes
    // classes, because every class has its own filter chain (BCJ for code, plain copy for packed data).
    let mut classes = vec![Class::Data; items.len()];
    let mut order: Vec<usize> = (0..items.len())
        .filter(|&i| !items[i].is_dir && items[i].size != 0)
        .collect();
    if opts.smart {
        for &i in &order {
            classes[i] = analyze::classify(&items[i]);
        }
        order.sort_by_cached_key(|&i| analyze::solid_key(&items[i], classes[i]));
    }
    let compressible: u64 = order
        .iter()
        .filter(|&&i| classes[i] != Class::Packed)
        .map(|&i| items[i].size)
        .sum();
    let dict = lzma2_dict(
        opts.dict_bytes
            .unwrap_or_else(|| default_dict(level))
            .min(u32::try_from(compressible).unwrap_or(u32::MAX))
            .max(1 << 16),
    );
    let block_bytes = opts.solid_bytes.unwrap_or_else(|| (u64::from(dict) * 8).max(64 << 20));
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut group_class: Vec<Class> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    let mut cur_bytes = 0u64;
    for &i in &order {
        if !cur.is_empty() && classes[i] != classes[cur[0]] {
            group_class.push(classes[cur[0]]);
            groups.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur.push(i);
        cur_bytes += items[i].size;
        if cur_bytes >= block_bytes {
            group_class.push(classes[i]);
            groups.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
    }
    if !cur.is_empty() {
        group_class.push(classes[cur[0]]);
        groups.push(cur);
    }
    let threads = crate::par::resolve_threads(opts.threads);
    let compressed_groups = group_class.iter().filter(|c| **c != Class::Packed).count();
    let (parallel_blocks, lzma_threads) = spread(
        threads,
        compressed_groups,
        encoder_bytes(level, dict),
        crate::par::available_memory(),
    );
    let mut lzma = if lzma_threads > 1 {
        // Each worker packs one chunk on its own. A chunk of four dictionaries loses little to the cut, but
        // when the block is smaller than that there would be one chunk and one busy thread, so the chunk is
        // the block divided between the workers, never smaller than a dictionary (the encoder enforces that).
        let per_block = compressible / compressed_groups.max(1) as u64;
        let dict = u64::from(dict);
        Lzma2Options::from_level_mt(
            level,
            lzma_threads as u32,
            (per_block / lzma_threads as u64).clamp(dict, dict * 4),
        )
    } else {
        Lzma2Options::from_level(level)
    };
    lzma.set_dictionary_size(dict);
    let lzma_conf = EncoderConfiguration::new(EncoderMethod::LZMA2).with_options(EncoderOptions::Lzma2(lzma));
    // The chain lists the stage nearest the file first. Data flows through it from the end: filter, then LZMA2,
    // then AES (as 7-Zip writes it). Every block gets its own random IV and salt.
    let chain_for_block = {
        let (lzma_conf, password) = (lzma_conf.clone(), opts.password.clone());
        move |class: Class| -> Arc<Vec<EncoderConfiguration>> {
            let mut chain = Vec::with_capacity(3);
            if let Some(p) = &password {
                chain.push(AesEncoderOptions::new(Password::from(p.expose())).into());
            }
            match class {
                Class::Packed => chain.push(EncoderConfiguration::new(EncoderMethod::COPY)),
                Class::Data => chain.push(lzma_conf.clone()),
                Class::Code(bcj) => {
                    chain.push(lzma_conf.clone());
                    chain.push(EncoderConfiguration::new(match bcj {
                        Bcj::X86 => EncoderMethod::BCJ_X86_FILTER,
                        Bcj::Arm => EncoderMethod::BCJ_ARM_FILTER,
                        Bcj::ArmThumb => EncoderMethod::BCJ_ARM_THUMB_FILTER,
                        Bcj::Arm64 => EncoderMethod::BCJ_ARM64_FILTER,
                    }));
                }
            }
            Arc::new(chain)
        }
    };

    let mut writer = sevenz_rust2::ArchiveWriter::new(out).map_err(map_err)?;
    writer.set_content_methods((*chain_for_block(Class::Data)).clone());
    writer.set_encrypt_header(opts.encrypt_names);
    let mut pool = OrderedPool::<Piece>::new(parallel_blocks)?;
    let mut deliver = |piece: Piece| -> Result<()> {
        progress.check()?;
        match piece {
            Piece::Dir(e) => {
                writer.push_archive_entry::<io::Empty>(e, None).map_err(map_err)?;
            }
            Piece::Empty(e) => {
                writer.push_archive_entry::<io::Empty>(e, None).map_err(map_err)?;
                progress.add_file();
            }
            Piece::Block(block, bytes, files) => {
                writer.push_prepared_block(block.map_err(map_err)?).map_err(map_err)?;
                progress.add_bytes(bytes);
                for _ in 0..files {
                    progress.add_file();
                }
            }
        }
        Ok(())
    };

    // Dirs go in item order and each group is queued when its first file is reached. Empty files go last, after
    // every directory: sevenz-rust2 0.24 writes the "empty file" bit vector only up to the last empty file, not
    // up to the last empty entry, and 7-Zip rejects such a header ("Headers Error") when a directory follows an
    // early empty file. With the empty files at the end the vector always has the full length.
    let mut group_of = vec![usize::MAX; items.len()];
    for (g, members) in groups.iter().enumerate() {
        for &i in members {
            group_of[i] = g;
        }
    }
    let mut empty_files = Vec::new();
    for (i, it) in items.iter().enumerate() {
        progress.check()?;
        if it.is_dir {
            pool.push_ready(Piece::Dir(entry_for(it)), &mut deliver)?;
        } else if it.size == 0 {
            empty_files.push(entry_for(it));
        } else if groups[group_of[i]][0] == i {
            let members: Vec<InputItem> = groups[group_of[i]].iter().map(|&m| items[m].clone()).collect();
            let bytes: u64 = members.iter().map(|m| m.size).sum();
            let files = members.len() as u64;
            let chain = chain_for_block.clone();
            let class = group_class[group_of[i]];
            pool.submit(
                move || {
                    let methods = chain(class);
                    let entries: Vec<ArchiveEntry> = members.iter().map(entry_for).collect();
                    let readers = members
                        .iter()
                        .map(|m| std::fs::File::open(&m.disk_path).map(sevenz_rust2::SourceReader::new))
                        .collect::<io::Result<Vec<_>>>();
                    let block = match readers {
                        Ok(r) => sevenz_rust2::prepare_block(methods, entries, r),
                        Err(e) => Err(sevenz_rust2::Error::Io(e, "cannot open a file to pack".into())),
                    };
                    Piece::Block(block, bytes, files)
                },
                &mut deliver,
            )?;
        }
    }
    for e in empty_files {
        progress.check()?;
        pool.push_ready(Piece::Empty(e), &mut deliver)?;
    }
    pool.finish(&mut deliver)?;
    writer.finish().map_err(Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn dictionaries_grow_with_the_level() {
        let d: Vec<u32> = (1..=9).map(default_dict).collect();
        assert!(d.windows(2).all(|w| w[0] <= w[1]), "{d:?}");
        assert_eq!(default_dict(5), 16 << 20);
        assert_eq!(default_dict(9), 64 << 20);
        assert_eq!(default_dict(0), default_dict(1));
        assert_eq!(default_dict(99), default_dict(9));
    }

    #[test]
    fn dictionary_sizes_are_representable_in_the_header() {
        let ok = |s: u32| {
            let n = 31 - s.leading_zeros();
            s == 1 << n || s == 3 << (n - 1)
        };
        for size in [
            1,
            4096,
            65_537,
            3_000_000,
            33 << 20,
            40 << 20,
            44_343_567,
            64 << 20,
            700 << 20,
            u32::MAX,
        ] {
            let d = lzma2_dict(size);
            assert!(ok(d), "{size} -> {d}");
            assert!(d >= size.min(3 << 28), "{size} -> {d} must not shrink");
            assert!(d <= 3 << 28);
        }
        assert_eq!(lzma2_dict(16 << 20), 16 << 20);
        assert_eq!(lzma2_dict(24 << 20), 24 << 20);
        assert_eq!(lzma2_dict((16 << 20) + 1), 24 << 20);
        assert_eq!(lzma2_dict((24 << 20) + 1), 32 << 20);
    }

    #[test]
    fn many_blocks_use_threads_for_blocks() {
        // plenty of memory: 8 blocks on 12 threads -> 8 at once, 1 worker each
        assert_eq!(spread(12, 8, 100 << 20, 64 * GIB), (8, 1));
        assert_eq!(spread(12, 40, 100 << 20, 64 * GIB), (12, 1));
    }

    #[test]
    fn few_blocks_split_threads_inside_the_block() {
        assert_eq!(spread(12, 1, 100 << 20, 64 * GIB), (1, 12));
        assert_eq!(spread(12, 2, 100 << 20, 64 * GIB), (2, 6));
        assert_eq!(spread(12, 5, 100 << 20, 64 * GIB), (5, 2));
    }

    #[test]
    fn memory_limits_the_number_of_encoders() {
        // 800 MB per encoder, 4 GiB free -> half is 2 GiB -> only 2 encoders
        let (blocks, workers) = spread(12, 8, 800 << 20, 4 * GIB);
        assert!(blocks * workers <= 2, "{blocks} x {workers}");
        // never below one, even with no memory at all
        assert_eq!(spread(12, 8, 800 << 20, 0), (1, 1));
        assert_eq!(spread(1, 0, 1, 0), (1, 1));
    }

    #[test]
    fn encoder_memory_grows_with_the_dictionary() {
        assert!(encoder_bytes(9, 64 << 20) > encoder_bytes(5, 16 << 20));
        assert!(encoder_bytes(5, 16 << 20) > 16 << 20);
    }
}
