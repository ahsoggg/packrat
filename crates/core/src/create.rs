//! Creating archives: collect the inputs, pick the writer, never leave a half-written file behind.

use crate::codec::stream::Compression;
use crate::error::{Error, Result};
use crate::input::{self, InputItem, Skipped};
use crate::options::Password;
use crate::prat::{self, PratOptions};
use crate::progress::Progress;
use crate::sevenz::{self, SevenZOptions};
use crate::tar;
use crate::zip::{self, ZipMethod, ZipOptions};
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Zip(ZipMethod),
    SevenZ,
    /// Packrat's own format: deduplication, solid blocks with random access, BLAKE3 integrity.
    Prat,
    /// TAR, optionally compressed: gz, zstd, xz or lz4.
    Tar(Compression),
}

impl Format {
    /// Extension to give the archive file, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Zip(_) => "zip",
            Format::SevenZ => "7z",
            Format::Prat => "prat",
            Format::Tar(Compression::None) => "tar",
            Format::Tar(Compression::Gz) => "tar.gz",
            Format::Tar(Compression::Zst) => "tar.zst",
            Format::Tar(Compression::Xz) => "tar.xz",
            Format::Tar(Compression::Lz4) => "tar.lz4",
            Format::Tar(Compression::Bz2) => "tar.bz2",
        }
    }

    pub fn from_name(name: &str) -> Option<Format> {
        Some(match name.to_ascii_lowercase().as_str() {
            "zip" => Format::Zip(ZipMethod::Deflate),
            "zip-zstd" => Format::Zip(ZipMethod::Zstd),
            "zip-store" => Format::Zip(ZipMethod::Store),
            "7z" => Format::SevenZ,
            "prat" => Format::Prat,
            "tar" => Format::Tar(Compression::None),
            "tar.gz" | "tgz" => Format::Tar(Compression::Gz),
            "tar.zst" | "tzst" => Format::Tar(Compression::Zst),
            "tar.xz" | "txz" => Format::Tar(Compression::Xz),
            "tar.lz4" => Format::Tar(Compression::Lz4),
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CreateOptions {
    pub format: Format,
    /// 1..=9 where the format has levels (deflate, 7z/LZMA2, xz).
    pub level: u32,
    /// 0 = all cores.
    pub threads: usize,
    /// AES-256 for ZIP and 7z. TAR cannot be encrypted.
    pub password: Option<Password>,
    /// 7z only: also encrypt the file names.
    pub encrypt_names: bool,
    /// 7z only: sort files by type, filter executables (BCJ) and store already-packed files (see `analyze`).
    pub smart: bool,
    /// 7z only: LZMA2 dictionary in bytes (`None`: chosen from the level and the data size).
    pub dict_bytes: Option<u32>,
    /// 7z only: size of one solid block in bytes (`None`: eight dictionaries, at least 64 MiB).
    pub solid_bytes: Option<u64>,
    /// `.prat` only: spend this percentage of the archive size on recovery data (0 = none).
    pub recovery_percent: u32,
}

impl CreateOptions {
    pub fn new(format: Format) -> Self {
        let level = if matches!(format, Format::SevenZ) { 5 } else { 6 };
        Self {
            format,
            level,
            threads: 0,
            password: None,
            encrypt_names: true,
            smart: true,
            dict_bytes: None,
            solid_bytes: None,
            recovery_percent: 0,
        }
    }
}

#[derive(Debug)]
pub struct CreateReport {
    pub entries: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub skipped: Skipped,
}

/// Packs `inputs` (files and folders) into `output`, which must not exist yet. The archive itself is left out
/// if it lies inside one of the inputs.
pub fn create_archive(
    output: &Path,
    inputs: &[PathBuf],
    opts: &CreateOptions,
    progress: &Progress,
) -> Result<CreateReport> {
    if output.exists() {
        return Err(Error::Other(format!("'{}' already exists", output.display())));
    }
    let (mut items, skipped) = input::collect_inputs(inputs)?;
    let out_abs = fs::canonicalize(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .ok()
    .map(|d| d.join(output.file_name().unwrap_or_default()));
    items.retain(|i: &InputItem| fs::canonicalize(&i.disk_path).ok() != out_abs);
    if items.is_empty() {
        return Err(Error::Other("nothing to add".into()));
    }
    let bytes_in = items.iter().map(|i| i.size).sum();

    let result = write_to(output, &items, opts, progress);
    match result {
        Ok(()) => {
            let bytes_out = fs::metadata(output)?.len();
            Ok(CreateReport {
                entries: items.len(),
                bytes_in,
                bytes_out,
                skipped,
            })
        }
        Err(e) => {
            let _ = fs::remove_file(output);
            Err(e)
        }
    }
}

fn write_to(output: &Path, items: &[InputItem], opts: &CreateOptions, progress: &Progress) -> Result<()> {
    if opts.recovery_percent > 0 && opts.format != Format::Prat {
        return Err(Error::Unsupported(
            "recovery data is only available in .prat archives (--format prat)".into(),
        ));
    }
    let file = File::options().write(true).create_new(true).open(output)?;
    match opts.format {
        Format::Zip(method) => {
            let zopts = ZipOptions {
                method,
                level: opts.level,
                threads: opts.threads,
                password: opts.password.clone(),
                ..Default::default()
            };
            zip::write_zip(BufWriter::with_capacity(256 << 10, file), items, &zopts, progress)?;
        }
        Format::SevenZ => {
            let sopts = SevenZOptions {
                level: opts.level,
                threads: opts.threads,
                password: opts.password.clone(),
                encrypt_names: opts.encrypt_names,
                smart: opts.smart,
                dict_bytes: opts.dict_bytes,
                solid_bytes: opts.solid_bytes,
            };
            sevenz::write_7z(file, items, &sopts, progress)?;
        }
        Format::Prat if opts.password.is_some() => {
            return Err(Error::Unsupported(
                "encryption is not available in .prat yet: use ZIP or 7z".into(),
            ));
        }
        Format::Prat => {
            let mut popts = PratOptions {
                level: opts.level,
                threads: opts.threads,
                ..Default::default()
            };
            if let Some(b) = opts.solid_bytes {
                popts.block_bytes = usize::try_from(b.clamp(1 << 20, 128 << 20)).unwrap_or(16 << 20);
            }
            prat::write_prat(file, items, &popts, progress)?;
            if opts.recovery_percent > 0 {
                prat::recover::add_recovery(output, opts.recovery_percent)?;
            }
        }
        Format::Tar(_) if opts.password.is_some() => {
            return Err(Error::Unsupported(
                "TAR archives cannot be encrypted: use ZIP or 7z".into(),
            ));
        }
        Format::Tar(c) => {
            let w =
                crate::codec::stream::writer(c, BufWriter::with_capacity(256 << 10, file), opts.level, opts.threads)?;
            tar::write_tar(w, items, progress)?;
        }
    }
    Ok(())
}
