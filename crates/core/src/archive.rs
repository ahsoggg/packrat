use crate::entry::Entry;
use crate::error::Result;
use std::io::Read;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Zip,
    SevenZ,
    Tar,
    TarGz,
    TarZst,
    TarXz,
    TarBz2,
    TarLz4,
    Gz,
    Bz2,
    Xz,
    Zst,
    Lz4,
    Rar,
    Cab,
    Lzh,
    Ar,
    Cpio,
    Rpm,
    Iso,
    Prat,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Zip => "ZIP",
            Kind::SevenZ => "7z",
            Kind::Tar => "TAR",
            Kind::TarGz => "TAR.GZ",
            Kind::TarZst => "TAR.ZST",
            Kind::TarXz => "TAR.XZ",
            Kind::TarBz2 => "TAR.BZ2",
            Kind::TarLz4 => "TAR.LZ4",
            Kind::Gz => "GZ",
            Kind::Bz2 => "BZ2",
            Kind::Xz => "XZ",
            Kind::Zst => "ZST",
            Kind::Lz4 => "LZ4",
            Kind::Rar => "RAR",
            Kind::Cab => "CAB",
            Kind::Lzh => "LZH",
            Kind::Ar => "AR",
            Kind::Cpio => "CPIO",
            Kind::Rpm => "RPM",
            Kind::Iso => "ISO",
            Kind::Prat => "PRAT",
        }
    }

    /// True when entries can be opened independently (central directory), so extraction can use many
    /// threads and a preview does not have to read what comes before the entry.
    pub fn random_access(self) -> bool {
        matches!(self, Kind::Zip | Kind::Ar | Kind::Cpio | Kind::Iso | Kind::Prat)
    }
}

pub type EntryReader<'a> = Box<dyn Read + Send + 'a>;

pub trait Archive: Send + Sync {
    fn kind(&self) -> Kind;
    fn entries(&self) -> &[Entry];

    /// ZIP names that had no encoding information (see `OpenOptions::encoding`).
    fn legacy_names(&self) -> Option<&crate::zip::read::LegacyNames> {
        None
    }

    /// The entry list was rebuilt from local headers because the central directory was unusable.
    fn is_recovered(&self) -> bool {
        false
    }

    /// Entries whose stored data overlaps another entry (ZIP only).
    fn overlapping_entries(&self) -> usize {
        0
    }

    /// Bytes that must be decoded and thrown away to reach entry `index` (0 when it can be opened directly).
    fn skip_cost(&self, _index: usize) -> u64 {
        0
    }

    fn random_access(&self) -> bool {
        self.kind().random_access()
    }

    /// For random-access formats whose entries share decoded data (blocks): extract in archive order, not by size,
    /// so that threads working at the same time need the same few blocks.
    fn prefers_archive_order(&self) -> bool {
        false
    }

    /// Opens one entry for reading. For streaming formats this decodes everything before the entry, so
    /// callers that want many entries should use `walk`.
    fn open_entry(&self, index: usize) -> Result<EntryReader<'_>>;

    /// Visits the wanted entries in archive order with a reader for each. Streaming formats do this in a
    /// single pass.
    fn walk(
        &self,
        want: &mut dyn FnMut(&Entry) -> bool,
        visit: &mut dyn FnMut(&Entry, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        for e in self.entries() {
            if want(e) {
                let mut r = self.open_entry(e.index)?;
                visit(e, &mut r)?;
            }
        }
        Ok(())
    }
}

/// Largest entry that `open_via_walk` will hold in memory.
const MAX_BUFFERED_ENTRY: u64 = 512 << 20;

/// `open_entry` for formats that can only be read front to back: one `walk` that keeps the wanted entry.
pub(crate) fn open_via_walk(a: &dyn Archive, index: usize) -> Result<EntryReader<'static>> {
    let e = a
        .entries()
        .get(index)
        .ok_or_else(|| crate::error::Error::Other(format!("no entry #{index}")))?;
    if e.size > MAX_BUFFERED_ENTRY {
        return Err(crate::error::Error::Unsupported(format!(
            "'{}' is too large to open from a streaming archive",
            e.path
        )));
    }
    let mut data = Vec::with_capacity(e.size as usize);
    let mut found = false;
    a.walk(&mut |x| x.index == index, &mut |_, r| {
        r.read_to_end(&mut data)?;
        found = true;
        Ok(())
    })?;
    if !found {
        return Err(crate::error::Error::Corrupt(
            "entry disappeared from the archive".into(),
        ));
    }
    Ok(Box::new(std::io::Cursor::new(data)))
}
