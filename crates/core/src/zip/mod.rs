//! ZIP, written for this project: raw name bytes, Zip64, random access through the central directory,
//! blocks compressed on worker threads.

pub mod crypto;
pub mod edit;
mod extra;
pub mod read;
mod recover;
pub mod write;

pub use read::ZipArchive;
pub use write::{ZipMethod, ZipOptions, write_zip};

pub(crate) const SIG_LOCAL: u32 = 0x0403_4b50;
pub(crate) const SIG_CENTRAL: u32 = 0x0201_4b50;
pub(crate) const SIG_EOCD: u32 = 0x0605_4b50;
pub(crate) const SIG_EOCD64: u32 = 0x0606_4b50;
pub(crate) const SIG_LOC64: u32 = 0x0707_4b50;
pub(crate) const SIG_DESCRIPTOR: u32 = 0x0807_4b50;

pub(crate) const METHOD_STORE: u16 = 0;
pub(crate) const METHOD_DEFLATE: u16 = 8;
pub(crate) const METHOD_ZSTD: u16 = 93;
