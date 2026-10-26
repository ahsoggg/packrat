//! Changing an existing archive: add or update files, delete, rename.
//!
//! ZIP is edited in place (see `zip::edit`): the entries that stay are copied byte for byte, so even a huge archive
//! changes at the speed of the disk. Every other writable format (7z, `.prat`, TAR) is rebuilt: the archive is
//! unpacked into a temporary folder, the change is made there and the folder is packed again in the same format.
//! The result always replaces the original in one step, and the original is left alone if anything fails.

use crate::archive::Kind;
use crate::codec::stream::Compression;
use crate::create::{CreateOptions, Format, create_archive};
use crate::entry::{Entry, EntryKind};
use crate::error::{Error, Result};
use crate::extract::{self, ExtractOptions, Resolution};
use crate::input::{self, CollectOptions, InputItem};
use crate::mask::{Masks, select_entries};
use crate::open;
use crate::options::{OpenOptions, Password};
use crate::prat;
use crate::progress::Progress;
use crate::zip::edit::{ZipEdit, edit_zip};
use crate::zip::{ZipMethod, ZipOptions};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub enum Change {
    /// Put these files and folders in; entries with the same name are replaced.
    Add(Vec<PathBuf>),
    /// Like `Add`, but only files that are newer than the archived copy (or not archived yet).
    Update(Vec<PathBuf>),
    /// Names (a file, a folder with everything in it, or a mask with `*`/`?`) to take out.
    Delete(Vec<String>),
    /// `(from, to)` pairs; a folder takes its contents along.
    Rename(Vec<(String, String)>),
}

#[derive(Clone, Debug)]
pub struct ModifyOptions {
    /// Masks and recursion for `Add`/`Update` and the masks that go with `Delete` names.
    pub masks: Masks,
    pub recursive: bool,
    pub threads: usize,
    /// Level for newly compressed data (`None`: the default of the format).
    pub level: Option<u32>,
    /// Needed to read (and, for 7z and `.prat`, rewrite) an encrypted archive.
    pub password: Option<Password>,
    /// ZIP: how new files are compressed.
    pub zip_method: ZipMethod,
    /// Recovery data after the change: `None` keeps what the archive had, `Some(0)` removes it.
    pub recovery_percent: Option<u32>,
    /// `.prat` with a password: memory for the key derivation in MiB when it is rebuilt (`None`: 64).
    pub kdf_mib: Option<u32>,
}

impl Default for ModifyOptions {
    fn default() -> Self {
        Self {
            masks: Masks::new(),
            recursive: true,
            threads: 0,
            level: None,
            password: None,
            zip_method: ZipMethod::Deflate,
            recovery_percent: None,
            kdf_mib: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ModifyReport {
    pub added: usize,
    pub replaced: usize,
    pub deleted: usize,
    pub renamed: usize,
    pub skipped_older: usize,
    pub bytes_out: u64,
    /// Files that went into the archive (for deleting them afterwards).
    pub added_files: Vec<PathBuf>,
}

fn norm(p: &str) -> String {
    p.replace('\\', "/").trim_end_matches('/').to_owned()
}

/// Recovery percentage that reproduces a plan (parity is rounded up to whole shards).
fn percent_of(plan: &prat::recover::Plan) -> u32 {
    (u64::from(plan.parity_shards) * 100)
        .div_ceil(u64::from(plan.data_shards).max(1))
        .clamp(1, 100) as u32
}

/// Applies `change` to the archive at `path`.
pub fn modify_archive(path: &Path, change: &Change, opts: &ModifyOptions, progress: &Progress) -> Result<ModifyReport> {
    let oo = OpenOptions {
        password: opts.password.clone(),
        ..Default::default()
    };
    let archive = open::open_with(path, &oo)?;
    let kind = archive.kind();
    let entries: Vec<Entry> = archive.entries().to_vec();
    let encrypted = entries.iter().any(|e| e.encrypted);
    let mut report = ModifyReport::default();

    // what the change means for the entries that are there
    let mut delete: HashSet<usize> = HashSet::new();
    let mut rename: HashMap<usize, String> = HashMap::new();
    let mut add: Vec<InputItem> = Vec::new();
    match change {
        Change::Add(paths) | Change::Update(paths) => {
            let (items, skipped) = input::collect_inputs_with(
                paths,
                &CollectOptions {
                    masks: opts.masks.clone(),
                    recursive: opts.recursive,
                },
            )?;
            if let Some((p, why)) = skipped.first() {
                return Err(Error::Other(format!("cannot add '{}': {why}", p.display())));
            }
            let by_name: HashMap<String, &Entry> = entries.iter().map(|e| (norm(&e.path), e)).collect();
            let only_newer = matches!(change, Change::Update(_));
            let canonical = fs::canonicalize(path).ok();
            for item in items {
                if canonical.is_some() && fs::canonicalize(&item.disk_path).ok() == canonical {
                    continue; // the archive itself
                }
                let old = by_name.get(&norm(&item.name)).copied();
                if let Some(old) = old {
                    if item.is_dir && old.is_dir() {
                        continue; // the folder is there already
                    }
                    if only_newer && !item.is_dir && item.mtime.zip(old.mtime).is_some_and(|(new, was)| new <= was + 1)
                    {
                        report.skipped_older += 1;
                        continue;
                    }
                    if old.kind != EntryKind::File && old.kind != EntryKind::Dir {
                        continue;
                    }
                    delete.insert(old.index);
                    report.replaced += 1;
                } else {
                    report.added += 1;
                }
                add.push(item);
            }
            if add.is_empty() {
                return Ok(report);
            }
            report.added_files = add.iter().filter(|i| !i.is_dir).map(|i| i.disk_path.clone()).collect();
        }
        Change::Delete(names) => {
            let sel = select_entries(&entries, names, &opts.masks);
            if sel.is_empty() {
                return Err(Error::Other("nothing in the archive matches the given names".into()));
            }
            report.deleted = sel.len();
            delete.extend(sel);
        }
        Change::Rename(pairs) => {
            let taken: HashSet<String> = entries.iter().map(|e| norm(&e.path)).collect();
            for (from, to) in pairs {
                let (from, to) = (norm(from), norm(to));
                if from.is_empty() || to.is_empty() {
                    return Err(Error::Other("rename needs non-empty names".into()));
                }
                let mut hit = false;
                for e in &entries {
                    let p = norm(&e.path);
                    let new = if p == from {
                        to.clone()
                    } else if let Some(rest) = p.strip_prefix(&format!("{from}/")) {
                        format!("{to}/{rest}")
                    } else {
                        continue;
                    };
                    hit = true;
                    if taken.contains(&new) && !(p == from && new == p) && !pairs.iter().any(|(f, _)| norm(f) == new) {
                        return Err(Error::Other(format!("'{new}' already exists in the archive")));
                    }
                    rename.insert(e.index, if e.is_dir() { format!("{new}/") } else { new });
                    report.renamed += 1;
                }
                if !hit {
                    return Err(Error::Other(format!("'{from}' is not in the archive")));
                }
            }
        }
    }

    let tmp = path.with_extension(format!(
        "{}.packrat-tmp",
        path.extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    if tmp.exists() {
        fs::remove_file(&tmp)?;
    }
    let result = match kind {
        Kind::Zip => zip_in_place(path, &tmp, &delete, &rename, &add, opts, encrypted, progress),
        Kind::SevenZ | Kind::Prat | Kind::Tar | Kind::TarGz | Kind::TarZst | Kind::TarXz | Kind::TarLz4 => {
            let format = match kind {
                Kind::SevenZ => Format::SevenZ,
                Kind::Prat => Format::Prat,
                Kind::Tar => Format::Tar(Compression::None),
                Kind::TarGz => Format::Tar(Compression::Gz),
                Kind::TarZst => Format::Tar(Compression::Zst),
                Kind::TarXz => Format::Tar(Compression::Xz),
                _ => Format::Tar(Compression::Lz4),
            };
            rebuild(&*archive, path, &tmp, format, &delete, &rename, &add, opts, progress)
        }
        other => Err(Error::Unsupported(format!(
            "{} archives cannot be changed: Packrat writes ZIP, 7z, PRAT and TAR",
            other.label()
        ))),
    };
    drop(archive);
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    report.bytes_out = fs::metadata(&tmp)?.len();
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::Other(format!("cannot replace '{}': {e}", path.display()))
    })?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn zip_in_place(
    path: &Path,
    tmp: &Path,
    delete: &HashSet<usize>,
    rename: &HashMap<usize, String>,
    add: &[InputItem],
    opts: &ModifyOptions,
    encrypted: bool,
    progress: &Progress,
) -> Result<()> {
    let recovery = prat::zip_recover::recovery_info(path);
    let zopts = ZipOptions {
        method: opts.zip_method,
        level: opts.level.unwrap_or(6),
        threads: opts.threads,
        // new files get the same protection as the rest; without a password an encrypted archive stays unchanged
        password: if encrypted { opts.password.clone() } else { None },
        ..Default::default()
    };
    if encrypted && opts.password.is_none() && !add.is_empty() {
        return Err(Error::PasswordRequired);
    }
    edit_zip(
        path,
        tmp,
        recovery.map(|p| p.protected),
        &ZipEdit {
            delete,
            rename,
            add,
            options: &zopts,
        },
        progress,
    )?;
    let percent = match opts.recovery_percent {
        Some(p) => p,
        None => recovery.as_ref().map_or(0, percent_of),
    };
    if percent > 0 {
        prat::zip_recover::add_recovery(tmp, percent)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rebuild(
    archive: &dyn crate::archive::Archive,
    path: &Path,
    tmp: &Path,
    format: Format,
    delete: &HashSet<usize>,
    rename: &HashMap<usize, String>,
    add: &[InputItem],
    opts: &ModifyOptions,
    progress: &Progress,
) -> Result<()> {
    let work = tempdir("packrat-edit")?;
    let outcome = rebuild_in(archive, path, tmp, format, delete, rename, add, opts, progress, &work);
    let _ = fs::remove_dir_all(&work);
    outcome
}

#[allow(clippy::too_many_arguments)]
fn rebuild_in(
    archive: &dyn crate::archive::Archive,
    path: &Path,
    tmp: &Path,
    format: Format,
    delete: &HashSet<usize>,
    rename: &HashMap<usize, String>,
    add: &[InputItem],
    opts: &ModifyOptions,
    progress: &Progress,
    work: &Path,
) -> Result<()> {
    // 1. unpack what stays
    let tree = work.join("tree");
    fs::create_dir_all(&tree)?;
    let keep: Vec<usize> = archive
        .entries()
        .iter()
        .filter(|e| !delete.contains(&e.index))
        .map(|e| e.index)
        .collect();
    if !keep.is_empty() {
        let mut xo = ExtractOptions::new(&tree, "");
        xo.smart = false;
        xo.threads = opts.threads;
        xo.selection = Some(keep);
        xo.default_resolution = Resolution::Replace;
        xo.accept_risks = true;
        xo.archive_len = fs::metadata(path).map_or(0, |m| m.len());
        let plan = extract::plan(archive, &xo);
        let rep = extract::execute(archive, &plan, &xo, progress)?;
        if let Some(b) = rep.blocked.first() {
            return Err(Error::Other(format!(
                "'{}' cannot be unpacked for the change: {}",
                b.path, b.message
            )));
        }
        if let Some(f) = rep.failed.first() {
            return Err(Error::Other(format!("'{}' cannot be read: {}", f.path, f.message)));
        }
        if let Some(m) = rep.stopped {
            return Err(Error::Other(m));
        }
    }
    // 2. renames (deepest first would not matter: folders are moved whole)
    let mut moves: Vec<(String, String)> = rename
        .iter()
        .filter_map(|(i, to)| {
            let from = archive.entries().get(*i)?;
            Some((norm(&from.path), norm(to)))
        })
        .collect();
    moves.sort();
    // a folder and its children are all listed; moving the folder takes the children along
    let mut moved: Vec<&str> = Vec::new();
    for (from, to) in &moves {
        if moved.iter().any(|m| from.starts_with(&format!("{m}/"))) {
            continue;
        }
        let (src, dst) = (tree.join(from), tree.join(to));
        if !src.exists() {
            continue;
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&src, &dst)?;
        moved.push(from);
    }
    // 3. new files over the old
    for item in add {
        let dest = tree.join(norm(&item.name));
        if item.is_dir {
            fs::create_dir_all(&dest)?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        if dest.exists() {
            fs::remove_file(&dest)?;
        }
        fs::copy(&item.disk_path, &dest)?;
        if let Some(t) = item.mtime
            && let Ok(f) = fs::File::options().write(true).open(&dest)
        {
            let _ = f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t.max(0) as u64));
        }
    }
    // 4. pack again
    let mut top: Vec<PathBuf> = fs::read_dir(&tree)?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    top.sort();
    if top.is_empty() {
        return Err(Error::Other("the archive would be empty; delete it instead".into()));
    }
    let mut co = CreateOptions::new(format);
    if let Some(l) = opts.level {
        co.level = l;
    }
    co.threads = opts.threads;
    co.password = opts.password.clone();
    co.kdf_mib = opts.kdf_mib;
    co.recovery_percent = match (opts.recovery_percent, format) {
        (Some(p), Format::Prat) => p,
        (None, Format::Prat) => prat::recover::recovery_info(path).as_ref().map_or(0, percent_of),
        _ => 0,
    };
    if archive.entries().iter().any(|e| e.encrypted) && opts.password.is_none() {
        return Err(Error::PasswordRequired);
    }
    create_archive(tmp, &top, &co, progress)?;
    Ok(())
}

fn tempdir(prefix: &str) -> Result<PathBuf> {
    let mut salt = [0u8; 8];
    getrandom::fill(&mut salt).map_err(|e| Error::Other(format!("no random numbers: {e}")))?;
    let name = format!("{prefix}-{}-{:016x}", std::process::id(), u64::from_le_bytes(salt));
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;
    use std::io::Read;

    fn tree(root: &Path) -> PathBuf {
        let d = root.join("d");
        fs::create_dir_all(d.join("sub")).unwrap();
        fs::write(d.join("a.txt"), "one").unwrap();
        fs::write(d.join("sub/b.txt"), "two").unwrap();
        let big: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        fs::write(d.join("big.bin"), big).unwrap();
        d
    }

    fn names(path: &Path, pw: Option<&Password>) -> Vec<String> {
        let oo = OpenOptions {
            password: pw.cloned(),
            ..Default::default()
        };
        let a = open::open_with(path, &oo).unwrap();
        let mut v: Vec<String> = a
            .entries()
            .iter()
            .filter(|e| e.is_file())
            .map(|e| e.path.clone())
            .collect();
        v.sort();
        v
    }

    fn read(path: &Path, name: &str, pw: Option<&Password>) -> String {
        let oo = OpenOptions {
            password: pw.cloned(),
            ..Default::default()
        };
        let a = open::open_with(path, &oo).unwrap();
        let e = a.entries().iter().find(|e| e.path == name).unwrap();
        let mut s = String::new();
        a.open_entry(e.index).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    fn clean(path: &Path, pw: Option<&Password>) {
        let oo = OpenOptions {
            password: pw.cloned(),
            ..Default::default()
        };
        let a = open::open_with(path, &oo).unwrap();
        let r = verify::verify(&*a, None, 2, &Progress::new());
        assert!(r.is_clean(), "{:?}", r.failures);
    }

    fn every_change(ext: &str, format: Format, pw: Option<Password>) {
        let dir = tempfile::tempdir().unwrap();
        let d = tree(dir.path());
        let arc = dir.path().join(format!("t.{ext}"));
        let mut co = CreateOptions::new(format);
        co.password = pw.clone();
        co.kdf_mib = Some(1);
        create_archive(&arc, &[d], &co, &Progress::new()).unwrap();
        let o = ModifyOptions {
            password: pw.clone(),
            kdf_mib: Some(1),
            ..Default::default()
        };
        let pw = pw.as_ref();

        // add a new file and replace an existing one by name
        let extra = dir.path().join("extra");
        fs::create_dir_all(extra.join("d")).unwrap();
        fs::write(extra.join("c.txt"), "three").unwrap();
        fs::write(extra.join("d/a.txt"), "uno").unwrap();
        let r = modify_archive(
            &arc,
            &Change::Add(vec![extra.join("c.txt"), extra.join("d")]),
            &o,
            &Progress::new(),
        )
        .unwrap();
        assert_eq!((r.added, r.replaced), (1, 1), "{ext}");
        assert_eq!(read(&arc, "d/a.txt", pw), "uno");
        assert_eq!(read(&arc, "c.txt", pw), "three");
        assert_eq!(read(&arc, "d/sub/b.txt", pw), "two");
        clean(&arc, pw);

        // rename a folder with its contents, delete by mask
        modify_archive(
            &arc,
            &Change::Rename(vec![("d/sub".into(), "d/inner".into())]),
            &o,
            &Progress::new(),
        )
        .unwrap();
        assert_eq!(read(&arc, "d/inner/b.txt", pw), "two");
        modify_archive(&arc, &Change::Delete(vec!["*.bin".into()]), &o, &Progress::new()).unwrap();
        assert_eq!(names(&arc, pw), ["c.txt", "d/a.txt", "d/inner/b.txt"], "{ext}");
        clean(&arc, pw);

        // update: an older file does not replace, a newer one does
        fs::write(extra.join("c.txt"), "newer").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400 * 30);
        fs::File::options()
            .write(true)
            .open(extra.join("c.txt"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let r = modify_archive(&arc, &Change::Update(vec![extra.join("c.txt")]), &o, &Progress::new()).unwrap();
        assert_eq!(r.skipped_older, 1);
        assert_eq!(read(&arc, "c.txt", pw), "three");
        fs::File::options()
            .write(true)
            .open(extra.join("c.txt"))
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .unwrap();
        modify_archive(&arc, &Change::Update(vec![extra.join("c.txt")]), &o, &Progress::new()).unwrap();
        assert_eq!(read(&arc, "c.txt", pw), "newer");

        // a missing name is an error and leaves the archive alone
        let before = fs::read(&arc).unwrap();
        assert!(modify_archive(&arc, &Change::Delete(vec!["nope".into()]), &o, &Progress::new()).is_err());
        assert!(
            modify_archive(
                &arc,
                &Change::Rename(vec![("nope".into(), "x".into())]),
                &o,
                &Progress::new()
            )
            .is_err()
        );
        assert_eq!(fs::read(&arc).unwrap(), before);
        assert!(
            !dir.path()
                .read_dir()
                .unwrap()
                .any(|e| e.unwrap().file_name().to_string_lossy().contains("packrat-tmp"))
        );
    }

    #[test]
    fn zip_changes_in_place() {
        every_change("zip", Format::Zip(ZipMethod::Deflate), None);
    }

    #[test]
    fn encrypted_zip_keeps_its_password() {
        every_change("zip", Format::Zip(ZipMethod::Deflate), Some(Password::new("hunter2")));
    }

    #[test]
    fn sevenz_is_rebuilt() {
        every_change("7z", Format::SevenZ, None);
        every_change("7z", Format::SevenZ, Some(Password::new("pw")));
    }

    #[test]
    fn prat_is_rebuilt() {
        every_change("prat", Format::Prat, None);
        every_change("prat", Format::Prat, Some(Password::new("pw")));
    }

    #[test]
    fn tar_is_rebuilt() {
        every_change("tar.zst", Format::Tar(Compression::Zst), None);
    }

    #[test]
    fn zip_recovery_data_survives_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let d = tree(dir.path());
        let arc = dir.path().join("r.zip");
        let mut co = CreateOptions::new(Format::Zip(ZipMethod::Deflate));
        co.recovery_percent = 10;
        create_archive(&arc, &[d], &co, &Progress::new()).unwrap();
        assert!(prat::zip_recover::recovery_info(&arc).is_some());
        modify_archive(
            &arc,
            &Change::Delete(vec!["d/a.txt".into()]),
            &ModifyOptions::default(),
            &Progress::new(),
        )
        .unwrap();
        assert!(prat::zip_recover::recovery_info(&arc).is_some());
        clean(&arc, None);
        assert_eq!(names(&arc, None), ["d/big.bin", "d/sub/b.txt"]);
        // and recovery can be dropped
        let o = ModifyOptions {
            recovery_percent: Some(0),
            ..Default::default()
        };
        modify_archive(&arc, &Change::Delete(vec!["d/sub".into()]), &o, &Progress::new()).unwrap();
        assert!(prat::zip_recover::recovery_info(&arc).is_none());
    }

    #[test]
    fn encrypted_archive_needs_the_password_to_be_changed() {
        let dir = tempfile::tempdir().unwrap();
        let d = tree(dir.path());
        let arc = dir.path().join("e.prat");
        let mut co = CreateOptions::new(Format::Prat);
        co.password = Some(Password::new("pw"));
        co.kdf_mib = Some(1);
        create_archive(&arc, &[d], &co, &Progress::new()).unwrap();
        let r = modify_archive(
            &arc,
            &Change::Delete(vec!["d/a.txt".into()]),
            &ModifyOptions::default(),
            &Progress::new(),
        );
        assert!(r.is_err());
    }
}
