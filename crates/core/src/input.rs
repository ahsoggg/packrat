//! Collecting files for a new archive.

use crate::error::{Error, Result};
use crate::mask::Masks;
use crate::timeutil;
use std::fs;
use std::path::{Path, PathBuf};

/// Paths that could not be added, with the reason.
pub type Skipped = Vec<(PathBuf, String)>;

#[derive(Clone, Debug)]
pub struct InputItem {
    pub disk_path: PathBuf,
    /// Name inside the archive: `/` separators, directories end with `/`.
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<i64>,
}

/// What to collect besides the paths themselves.
#[derive(Clone, Debug)]
pub struct CollectOptions {
    pub masks: Masks,
    /// false: a folder contributes only the files directly inside it.
    pub recursive: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            masks: Masks::new(),
            recursive: true,
        }
    }
}

/// Walks the given files and folders. Names are relative to each path's parent folder, so adding
/// `C:\data\photos` yields `photos/…`. Symbolic links and junctions are skipped, never followed.
/// Returns the items and the paths that could not be read.
pub fn collect_inputs(paths: &[PathBuf]) -> Result<(Vec<InputItem>, Skipped)> {
    collect_inputs_with(paths, &CollectOptions::default())
}

/// `collect_inputs` with masks and the recursion switch.
pub fn collect_inputs_with(paths: &[PathBuf], opts: &CollectOptions) -> Result<(Vec<InputItem>, Skipped)> {
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for p in paths {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| Error::Other(format!("cannot add '{}': no file name", p.display())))?;
        walk(p, &name, opts, &mut items, &mut skipped);
    }
    if opts.masks.has_include() {
        // a folder stays only if something inside it was kept
        let kept: Vec<String> = items.iter().filter(|i| !i.is_dir).map(|i| i.name.clone()).collect();
        items.retain(|i| !i.is_dir || kept.iter().any(|k| k.starts_with(&i.name)));
    }
    Ok((items, skipped))
}

fn walk(
    path: &Path,
    name: &str,
    opts: &CollectOptions,
    items: &mut Vec<InputItem>,
    skipped: &mut Skipped,
) {
    if opts.masks.excluded(name) {
        return;
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            skipped.push((path.to_path_buf(), e.to_string()));
            return;
        }
    };
    if meta.file_type().is_symlink() {
        skipped.push((path.to_path_buf(), "symbolic link".into()));
        return;
    }
    let mtime = meta.modified().ok().map(timeutil::system_time_to_unix);
    if meta.is_dir() {
        items.push(InputItem {
            disk_path: path.to_path_buf(),
            name: format!("{name}/"),
            is_dir: true,
            size: 0,
            mtime,
        });
        let mut children: Vec<_> = match fs::read_dir(path) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(e) => {
                skipped.push((path.to_path_buf(), e.to_string()));
                return;
            }
        };
        children.sort_by_key(|c| c.file_name());
        for c in children {
            if !opts.recursive && c.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let child = c.file_name().to_string_lossy().into_owned();
            walk(&c.path(), &format!("{name}/{child}"), opts, items, skipped);
        }
    } else if meta.is_file() {
        if opts.masks.has_include() && !opts.masks.allows(name) {
            return;
        }
        items.push(InputItem {
            disk_path: path.to_path_buf(),
            name: name.to_owned(),
            is_dir: false,
            size: meta.len(),
            mtime,
        });
    } else {
        skipped.push((path.to_path_buf(), "not a regular file".into()));
    }
}
