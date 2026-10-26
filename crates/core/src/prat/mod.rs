//! The native `.prat` format: content-defined deduplication, solid blocks that still open one file at a time,
//! BLAKE3 integrity everywhere. Layout and rationale: `docs/PRAT_FORMAT.md`.

pub mod format;
pub mod read;
pub mod recover;
pub mod write;
pub mod zip_recover;

pub use read::PratArchive;
pub use write::{PratOptions, PratStats, write_prat};
