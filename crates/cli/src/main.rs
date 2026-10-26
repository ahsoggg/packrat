use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::encoding::NameEncoding;
use packrat_core::extract::{self, ExtractOptions, Resolution};
use packrat_core::mask::Masks;
use packrat_core::{Archive, EntryKind, OpenOptions, Password, Progress, open, timeutil};
use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
packrat-cli — Packrat archive tool

USAGE:
  packrat-cli list <archive> [NAMES/MASKS...] [-i MASK] [-x MASK] [--encoding NAME] [PASSWORD OPTIONS]
  packrat-cli extract <archive> [NAMES/MASKS...] [-o DIR] [--smart] [--threads N] [-i MASK] [-x MASK] [--stdout]
                      [--skip | --overwrite | --keep-both] [--accept-risks] [--repair]
                      [--encoding NAME] [PASSWORD OPTIONS]
  packrat-cli add <archive> <paths...> [-i/-x MASK] [--level N] [PASSWORD OPTIONS]   add files to an archive (7-Zip's `a`);
                      files with the same name are replaced; creates the archive when it does not exist yet
  packrat-cli update <archive> <paths...>    like add, but only files newer than the archived ones
  packrat-cli delete <archive> <names/masks...> [-x MASK]   take files or folders out of an archive
  packrat-cli rename <archive> <old> <new> [<old> <new>...]   rename files or folders inside an archive
  packrat-cli test <archive> [--sha256] [--threads N] [--encoding NAME] [PASSWORD OPTIONS]
  packrat-cli repair <archive.prat|zip> [-o FIXED]  rebuild damaged areas from the recovery data (the original is kept)
  packrat-cli create <output> <paths...> [--format FMT] [--level N] [--threads N] [-i MASK] [-x MASK]
                      [--no-recursion] [--delete-source] [--stdin NAME] [--volume SIZE] [--sfx] [--method M] [--delta N] [--fb N]
                      [PASSWORD OPTIONS] [--no-encrypt-names] [--no-filters] [--dict-mb N] [--solid-mb N] [--recovery PCT] [--kdf-mb N]
  packrat-cli hash <files...> [--algo crc32|sha1|sha256|blake3]   checksums of files
  packrat-cli bench [--mb N]               speed of the compressors on generated data in memory (default 16 MiB)
  packrat-cli bench-gen <dir> [--mb N]     write the deterministic data set used by scripts/bench.ps1
  packrat-cli --version | --help

FORMATS (create): zip (deflate), zip-zstd, zip-store, 7z, prat, tar, tar.gz, tar.zst, tar.xz, tar.bz2, tar.lz4,
  and gz, xz, bz2, zst, lz4 for one single file
  The format is taken from the output extension when --format is not given.

CHANGING ARCHIVES: add, update, delete and rename work on ZIP, 7z, prat and TAR (tar.gz/zst/xz/lz4) archives.
  ZIP is edited in place: what stays is copied as it is, without recompressing, and recovery data and the AES
  password protection are kept. The other formats are unpacked to a temporary folder and packed again (so this
  takes as long as creating them). The old file is replaced only when everything succeeded.

MASKS AND LISTS:
  -i MASK / -x MASK (also --include / --exclude, and 7-Zip's -i!MASK / -x!MASK) keep or leave out files by name;
  repeat them as needed. * is any run of characters, ? one character; a mask without / is tried against every
  folder and file name on the path (`-x node_modules`, `-i *.rs`), a mask with / against the path from the
  archive root. Case is ignored. An argument @FILE is replaced by the lines of FILE (one path or name per line).
  --volume SIZE (-v; 100m, 4g, ...) cuts the finished archive into volumes name.ext.001, .002, ...; open or extract
  any of them (or the .001) and Packrat reads the series, as does 7-Zip. --sfx makes a self-extracting program
  (an .exe that unpacks itself; 7z unless --format says otherwise) from the packrat-sfx.exe stub that sits next
  to packrat-cli.exe; add --volume to split it as well.
  --method M (7z): lzma2 (default), lzma, ppmd (best on text and logs, slow both ways), bzip2, deflate, copy.
  --delta N (7z) puts a delta filter of distance N in front of data files (tables, uncompressed audio and
  images: N is the size of one sample or pixel in bytes); --fb N sets the LZMA word size (5-273).
  --no-recursion (7-Zip's -r-) adds only the files directly inside the given folders; --delete-source (-sdel)
  deletes the added files after the archive was written. --stdin NAME stores what arrives on standard input as
  the file NAME; extract --stdout (-so) writes the contents of the chosen files to standard output.

EXTRACT:
  --smart     one root folder goes straight to the target, one file lands next to it,
               loose items get a folder named after the archive
  existing files are skipped unless --overwrite or --keep-both is given

PASSWORD OPTIONS: --ask-password | --password-file FILE | env PACKRAT_PASSWORD
  Passwords are never taken from the command line. Creating: ZIP and 7z get AES-256; 7z also hides file names
  (--no-encrypt-names keeps them visible). TAR cannot be encrypted.
  7z sorts files by type, runs a BCJ filter over executables and stores already-packed files (JPEG, MP4, ZIP...)
  as they are; --no-filters keeps the input order and compresses everything the same way.
  prat is Packrat's own format: files are cut into content-defined chunks and identical chunks are stored once
  (copies, backups, versions of the same project shrink a lot), blocks are zstd (--level 1-9, --solid-mb sets
  the block size, 1-128, default 16) and every block carries a BLAKE3 hash. Only Packrat opens it for now.
  prat with a password (--ask-password, --password-file or PACKRAT_PASSWORD) is encrypted: every block and the index
  (names, sizes, times) are sealed with XChaCha20-Poly1305 under a key from Argon2id; --kdf-mb sets the memory the
  key derivation uses (default 64 MiB; more makes guessing passwords dearer and opening slower). Repair works
  without the password.
  --recovery PCT (prat and zip) adds Reed-Solomon recovery data of PCT percent of the archive size: any damaged
  areas up to that amount can be rebuilt with `repair`, which writes a repaired copy and never touches the original.
  A ZIP with recovery data is still an ordinary ZIP: WinRAR, 7-Zip and Explorer open it (they skip the recovery
  data), and only Packrat can repair it.
  --dict-mb sets the 7z (LZMA2) dictionary and --solid-mb the size of one solid block. By default the dictionary
  follows the level (16 MiB at 5, 64 MiB at 9, never more than the data) and a block is eight dictionaries, at
  least 64 MiB; bigger values pack better and use more memory. Encoders never take more than half of free RAM.

ENCODING: for old ZIP files whose names have no encoding information, Packrat guesses (cp866, cp1251, cp437,
  shift_jis, gbk, big5, euc-kr); --encoding NAME forces one.

RISKS: before extracting, archives are checked for bomb-like traits (huge expansion ratio, too little disk space,
  overlapping entries, deeply nested archives). If anything is found nothing is extracted unless --accept-risks.

TEST: reads every file and checks it against the archive's checksums (CRC-32 in ZIP and 7z, the stream checks for
  TAR); --sha256 also prints the SHA-256 of the archive file. Exit code 1 when anything is damaged.

REPAIR: extract --repair rebuilds the list of a damaged ZIP from its local headers (a cut-off download, a lost
  central directory) and extracts everything that can be read; damaged entries are kept as NAME.partial.

EXIT CODES: 0 success, 1 finished with errors or blocked entries, 2 bad usage or fatal error
";

struct Args(Vec<String>);

impl Args {
    fn flag(&mut self, name: &str) -> bool {
        match self.0.iter().position(|a| a == name) {
            Some(i) => {
                self.0.remove(i);
                true
            }
            None => false,
        }
    }

    fn value(&mut self, names: &[&str]) -> Result<Option<String>, String> {
        let Some(i) = self.0.iter().position(|a| names.contains(&a.as_str())) else {
            return Ok(None);
        };
        if i + 1 >= self.0.len() {
            return Err(format!("{} needs a value", self.0[i]));
        }
        let v = self.0.remove(i + 1);
        self.0.remove(i);
        Ok(Some(v))
    }

    /// Called once every known option has been taken: an argument that still looks like an option is a mistake, not
    /// a file name. Silently treating `--password secret` as a file to archive would produce an unprotected archive.
    fn reject_unknown(&self) -> Result<(), String> {
        let Some(bad) = self
            .0
            .iter()
            .find(|a| a.len() > 1 && a.starts_with('-') && !std::path::Path::new(a.as_str()).exists())
        else {
            return Ok(());
        };
        if bad.to_ascii_lowercase().contains("pass") {
            return Err(format!(
                "unknown option '{bad}': passwords are never taken from the command line; use --ask-password, \
                 --password-file FILE or the PACKRAT_PASSWORD environment variable"
            ));
        }
        Err(format!("unknown option '{bad}' (see --help)"))
    }

    /// Every occurrence of an option that may be repeated.
    fn values(&mut self, names: &[&str]) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        while let Some(v) = self.value(names)? {
            out.push(v);
        }
        Ok(out)
    }

    fn number(&mut self, names: &[&str]) -> Result<Option<usize>, String> {
        self.value(names)?
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("{} must be a number, got '{v}'", names[0]))
            })
            .transpose()
    }
}

/// 7-Zip spellings become ours (`-i!*.rs` -> `-i *.rs`, `-r-`, `-sdel`, `-so`) and `@FILE` arguments are replaced by
/// the lines of the file.
fn normalize_args(args: &mut Args) -> Result<(), String> {
    let mut out = Vec::with_capacity(args.0.len());
    let mut past_options = false;
    for a in args.0.drain(..) {
        if a == "--" && !past_options {
            past_options = true;
            continue;
        }
        if !past_options {
            let lower = a.to_ascii_lowercase();
            let mapped = ["-ir!", "-xr!", "-i!", "-x!"].iter().find(|p| lower.starts_with(*p));
            if let Some(p) = mapped {
                out.push(if p.starts_with("-i") { "-i" } else { "-x" }.to_owned());
                out.push(a[p.len()..].to_owned());
                continue;
            }
            let long = match a.as_str() {
                "-r-" => Some("--no-recursion"),
                "-sdel" => Some("--delete-source"),
                "-so" => Some("--stdout"),
                _ => None,
            };
            if let Some(l) = long {
                out.push(l.to_owned());
                continue;
            }
        }
        match a.strip_prefix('@') {
            Some(file) if !file.is_empty() => {
                let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
                for line in text.lines() {
                    let line = line.trim().trim_matches('"');
                    if !line.is_empty() {
                        out.push(line.to_owned());
                    }
                }
            }
            _ => out.push(a),
        }
    }
    args.0 = out;
    Ok(())
}

/// `-i` and `-x` masks (repeatable).
fn take_masks(args: &mut Args) -> Result<Masks, String> {
    let mut m = Masks::new();
    for i in args.values(&["-i", "--include"])? {
        m.include(&i);
    }
    for x in args.values(&["-x", "--exclude"])? {
        m.exclude(&x);
    }
    Ok(m)
}

fn select_entries(a: &dyn Archive, wanted: &[String], masks: &Masks) -> Vec<usize> {
    packrat_core::mask::select_entries(a.entries(), wanted, masks)
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn main() -> ExitCode {
    let mut args = Args(std::env::args().skip(1).collect());
    if args.0.is_empty() {
        print!("{HELP}");
        return ExitCode::from(2);
    }
    if args.flag("--help") || args.flag("-h") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args.flag("--version") || args.flag("-V") {
        println!("packrat-cli {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if let Err(m) = normalize_args(&mut args) {
        eprintln!("packrat-cli: {m}");
        return ExitCode::from(2);
    }
    let cmd = args.0.remove(0);
    let result = match cmd.as_str() {
        "list" | "l" => cmd_list(args),
        "extract" | "x" => cmd_extract(args),
        "create" | "c" => cmd_create(args, Mode::Create),
        "add" | "a" => cmd_create(args, Mode::Add),
        "update" | "u" => cmd_create(args, Mode::Update),
        "delete" | "d" => cmd_delete(args),
        "rename" | "rn" => cmd_rename(args),
        "repair" => cmd_repair(args),
        "test" | "t" => cmd_test(args),
        "hash" | "h" => cmd_hash(args),
        "bench" | "b" => cmd_bench(args),
        "bench-gen" => cmd_bench_gen(args),
        other => Err(format!("unknown command '{other}' (see --help)")),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(m) => {
            eprintln!("packrat-cli: {m}");
            ExitCode::from(2)
        }
    }
}

/// Reads a line without echoing it (a password prompt).
#[cfg(windows)]
fn read_hidden_line() -> std::io::Result<String> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };
    // SAFETY: plain console API calls on the process's own stdin handle.
    let (handle, old) = unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        let is_console = GetConsoleMode(h, &mut mode) != 0;
        if is_console {
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        }
        (h, is_console.then_some(mode))
    };
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    if let Some(mode) = old {
        // SAFETY: restores the mode read above.
        unsafe { SetConsoleMode(handle, mode) };
        eprintln!();
    }
    r.map(|_| line.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(not(windows))]
fn read_hidden_line() -> std::io::Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map(|_| line.trim_end_matches(['\r', '\n']).to_owned())
}

/// `--encoding NAME`, and a password from `--password-file FILE`, `--ask-password` or `PACKRAT_PASSWORD`.
/// There is deliberately no `--password VALUE`: command lines end up in shell history and process lists.
fn open_options(args: &mut Args) -> Result<OpenOptions, String> {
    let mut o = OpenOptions::default();
    if let Some(name) = args.value(&["--encoding"])? {
        o.encoding = Some(NameEncoding::from_name(&name).ok_or_else(|| {
            format!("unknown encoding '{name}' (try cp866, cp1251, cp437, shift_jis, gbk, big5, euc-kr, utf-8)")
        })?);
    }
    if let Some(file) = args.value(&["--password-file"])? {
        let text = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
        o.password = Some(Password::new(text.lines().next().unwrap_or("")));
    } else if args.flag("--ask-password") {
        eprint!("Password: ");
        o.password = Some(Password::new(&read_hidden_line().map_err(|e| e.to_string())?));
    } else if let Ok(p) = std::env::var("PACKRAT_PASSWORD") {
        o.password = Some(Password::new(&p));
    }
    Ok(o)
}

fn open_archive(path: &str, opts: &OpenOptions) -> Result<Box<dyn Archive>, String> {
    open::open_with(&PathBuf::from(path), opts).map_err(|e| match e {
        packrat_core::Error::PasswordRequired => {
            format!("{path}: a password is required (use --ask-password or --password-file)")
        }
        other => format!("{path}: {other}"),
    })
}

fn cmd_list(mut args: Args) -> Result<u8, String> {
    let oo = open_options(&mut args)?;
    let masks = take_masks(&mut args)?;
    args.reject_unknown()?;
    let path = args.0.first().cloned().ok_or("list: archive path is missing")?;
    let wanted: Vec<String> = args.0.iter().skip(1).cloned().collect();
    let a = open_archive(&path, &oo)?;
    let shown: std::collections::HashSet<usize> = select_entries(&*a, &wanted, &masks).into_iter().collect();
    if let Some(l) = a.legacy_names() {
        eprintln!(
            "note: {} names have no encoding information; decoded as {} (detected: {}). Use --encoding to change.",
            l.indices.len(),
            l.current.label(),
            l.detection.best.label()
        );
    }
    if a.entries().iter().any(|e| e.method.starts_with("ZipCrypto")) {
        eprintln!("warning: this archive uses ZipCrypto, a weak encryption (known-plaintext attacks recover the keys)");
    }
    println!("{} — {}", path, a.kind().label());
    println!("{:>12} {:>12}  {:<16}  Name", "Size", "Packed", "Modified");
    let (mut files, mut dirs, mut size, mut packed) = (0u64, 0u64, 0u64, 0u64);
    for e in a.entries().iter().filter(|e| shown.contains(&e.index)) {
        let date = e.mtime.map(timeutil::format_minutes).unwrap_or_default();
        let (s, p) = match e.kind {
            EntryKind::Dir => {
                dirs += 1;
                (String::new(), String::new())
            }
            _ => {
                files += 1;
                size += e.size;
                packed += e.packed.unwrap_or(0);
                (e.size.to_string(), e.packed.map(|p| p.to_string()).unwrap_or_default())
            }
        };
        let mark = match e.kind {
            EntryKind::Symlink => " [link]",
            EntryKind::Other => " [special]",
            _ => "",
        };
        let enc = if e.encrypted { " [encrypted]" } else { "" };
        println!("{s:>12} {p:>12}  {date:<16}  {}{mark}{enc}", e.path);
    }
    println!(
        "{files} files, {dirs} folders, {} unpacked, {} packed",
        human(size),
        human(packed)
    );
    Ok(0)
}

fn cmd_extract(mut args: Args) -> Result<u8, String> {
    let mut oo = open_options(&mut args)?;
    let repair = args.flag("--repair");
    oo.recover = repair;
    let accept_risks = args.flag("--accept-risks");
    let smart = args.flag("--smart");
    let overwrite = args.flag("--overwrite");
    let keep_both = args.flag("--keep-both");
    let skip = args.flag("--skip");
    if [overwrite, keep_both, skip].iter().filter(|b| **b).count() > 1 {
        return Err("choose only one of --skip, --overwrite, --keep-both".into());
    }
    let out = args.value(&["-o", "--output"])?.unwrap_or_else(|| ".".into());
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    let to_stdout = args.flag("--stdout");
    let masks = take_masks(&mut args)?;
    args.reject_unknown()?;
    let path = args.0.first().cloned().ok_or("extract: archive path is missing")?;
    let wanted: Vec<String> = args.0.iter().skip(1).cloned().collect();

    let a = open_archive(&path, &oo)?;
    if to_stdout {
        return extract_to_stdout(&*a, &wanted, &masks);
    }
    let name = PathBuf::from(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut opts = ExtractOptions::new(&out, name);
    opts.smart = smart;
    opts.threads = threads;
    opts.accept_risks = accept_risks;
    opts.keep_partial = repair;
    if a.is_recovered() {
        eprintln!(
            "note: the central directory is unusable; {} entries were found by scanning local headers",
            a.entries().len()
        );
    }
    opts.archive_len = std::fs::metadata(&path).map_or(0, |m| m.len());
    opts.default_resolution = if overwrite {
        Resolution::Replace
    } else if keep_both {
        Resolution::KeepBoth
    } else {
        Resolution::Skip
    };
    if !wanted.is_empty() || !masks.is_empty() {
        let sel = select_entries(&*a, &wanted, &masks);
        if sel.is_empty() {
            return Err("nothing in the archive matches the given names and masks".into());
        }
        opts.selection = Some(sel);
    }

    let progress = Progress::new();
    let started = std::time::Instant::now();
    let plan = extract::plan(&*a, &opts);
    if !plan.risks.is_empty() && !accept_risks {
        for r in &plan.risks {
            eprintln!("RISK: {}", r.describe());
        }
        eprintln!("nothing was extracted; run again with --accept-risks to continue at your own risk");
        return Ok(1);
    }
    println!("extracting to {}", plan.base.display());
    let report = extract::execute(&*a, &plan, &opts, &progress).map_err(|e| e.to_string())?;
    let secs = started.elapsed().as_secs_f64();
    println!(
        "{} files, {} folders, {} in {secs:.2} s",
        report.files,
        report.dirs,
        human(report.bytes)
    );
    for p in &report.skipped_existing {
        println!("skipped (exists): {p}");
    }
    for (from, to) in &report.kept_both {
        println!("kept both: {from} -> {to}");
    }
    for b in &report.blocked {
        eprintln!("BLOCKED {}: {}", b.path, b.message);
    }
    if let Some(m) = &report.stopped {
        eprintln!("STOPPED: {m}");
    }
    for f in &report.failed {
        eprintln!("FAILED {}: {}", f.path, f.message);
    }
    Ok(u8::from(
        !report.blocked.is_empty() || !report.failed.is_empty() || report.stopped.is_some(),
    ))
}

/// `extract --stdout`: the contents of the chosen files, one after another, on standard output.
fn extract_to_stdout(a: &dyn Archive, wanted: &[String], masks: &Masks) -> Result<u8, String> {
    use std::io::Write;
    let sel: std::collections::HashSet<usize> = select_entries(a, wanted, masks).into_iter().collect();
    if sel.is_empty() {
        return Err("nothing in the archive matches the given names and masks".into());
    }
    let mut out = std::io::BufWriter::with_capacity(256 << 10, std::io::stdout().lock());
    let mut failed = false;
    a.walk(
        &mut |e| sel.contains(&e.index) && matches!(e.kind, EntryKind::File),
        &mut |e, r| {
            if let Err(err) = std::io::copy(r, &mut out) {
                eprintln!("FAILED {}: {err}", e.path);
                failed = true;
            }
            Ok(())
        },
    )
    .map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    Ok(u8::from(failed))
}

/// Removes `dir` and the empty folders below it.
#[allow(clippy::too_many_arguments)]
fn add_to_existing(
    archive: &std::path::Path,
    inputs: &[PathBuf],
    mode: Mode,
    masks: Masks,
    recursive: bool,
    level: Option<usize>,
    threads: usize,
    recovery: Option<usize>,
    password: Option<Password>,
) -> Result<packrat_core::modify::ModifyReport, String> {
    use packrat_core::modify::{Change, ModifyOptions, modify_archive};
    let opts = ModifyOptions {
        masks,
        recursive,
        threads,
        level: level.map(|l| l.clamp(1, 9) as u32),
        password,
        recovery_percent: recovery.map(|r| r.min(100) as u32),
        ..Default::default()
    };
    let change = if mode == Mode::Update {
        Change::Update(inputs.to_vec())
    } else {
        Change::Add(inputs.to_vec())
    };
    let started = std::time::Instant::now();
    let r = modify_archive(archive, &change, &opts, &Progress::new()).map_err(|e| e.to_string())?;
    println!(
        "{}: {} added, {} replaced{} -> {} in {:.2} s",
        archive.display(),
        r.added,
        r.replaced,
        if r.skipped_older > 0 {
            format!(", {} not newer", r.skipped_older)
        } else {
            String::new()
        },
        human(r.bytes_out),
        started.elapsed().as_secs_f64()
    );
    Ok(r)
}

fn cmd_delete(mut args: Args) -> Result<u8, String> {
    use packrat_core::modify::{Change, ModifyOptions, modify_archive};
    let oo = open_options(&mut args)?;
    let masks = take_masks(&mut args)?;
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    args.reject_unknown()?;
    if args.0.len() < 2 {
        return Err("delete: need an archive and at least one name or mask".into());
    }
    let path = PathBuf::from(args.0.remove(0));
    let opts = ModifyOptions {
        masks,
        threads,
        password: oo.password,
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let r =
        modify_archive(&path, &Change::Delete(args.0.clone()), &opts, &Progress::new()).map_err(|e| e.to_string())?;
    println!(
        "{}: {} entries deleted -> {} in {:.2} s",
        path.display(),
        r.deleted,
        human(r.bytes_out),
        started.elapsed().as_secs_f64()
    );
    Ok(0)
}

fn cmd_rename(mut args: Args) -> Result<u8, String> {
    use packrat_core::modify::{Change, ModifyOptions, modify_archive};
    let oo = open_options(&mut args)?;
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    args.reject_unknown()?;
    if args.0.len() < 3 || args.0.len().is_multiple_of(2) {
        return Err("rename: need an archive and pairs of OLD NEW names".into());
    }
    let path = PathBuf::from(args.0.remove(0));
    let pairs: Vec<(String, String)> = args.0.chunks(2).map(|c| (c[0].clone(), c[1].clone())).collect();
    let opts = ModifyOptions {
        threads,
        password: oo.password,
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let r = modify_archive(&path, &Change::Rename(pairs), &opts, &Progress::new()).map_err(|e| e.to_string())?;
    println!(
        "{}: {} entries renamed -> {} in {:.2} s",
        path.display(),
        r.renamed,
        human(r.bytes_out),
        started.elapsed().as_secs_f64()
    );
    Ok(0)
}

fn prune_empty(dir: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                prune_empty(&e.path());
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `create`: the archive must not exist.
    Create,
    /// `add` (7-Zip's `a`): put files into the archive, creating it when it is not there.
    Add,
    /// `update`: like `add`, but only newer files replace archived ones.
    Update,
}

fn cmd_create(mut args: Args, mode: Mode) -> Result<u8, String> {
    let no_names = args.flag("--no-encrypt-names");
    let no_filters = args.flag("--no-filters");
    let dict_mb = args.number(&["--dict-mb"])?;
    let recovery = args.number(&["--recovery"])?;
    let kdf_mb = args.number(&["--kdf-mb"])?;
    let solid_mb = args.number(&["--solid-mb"])?;
    let oo = open_options(&mut args)?;
    let format_name = args.value(&["--format", "-f"])?;
    let level = args.number(&["--level", "-l"])?;
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    let no_recursion = args.flag("--no-recursion");
    let delete_source = args.flag("--delete-source");
    let stdin_name = args.value(&["--stdin"])?;
    let sfx = args.flag("--sfx");
    let method = args.value(&["--method", "-m"])?;
    let delta = args.number(&["--delta"])?;
    let fast_bytes = args.number(&["--fb"])?;
    let volume = args
        .value(&["--volume", "-v"])?
        .map(|v| {
            packrat_core::volume::parse_size(&v)
                .ok_or_else(|| format!("--volume: cannot read the size '{v}' (try 100m or 4g)"))
        })
        .transpose()?;
    let masks = take_masks(&mut args)?;
    if args.0.is_empty() || (args.0.len() < 2 && stdin_name.is_none()) {
        return Err("create: need an output file and at least one path".into());
    }
    let output = PathBuf::from(args.0.remove(0));
    args.reject_unknown()?;
    let mut inputs: Vec<PathBuf> = args.0.iter().map(PathBuf::from).collect();
    let spool = match &stdin_name {
        Some(name) => {
            if name.is_empty() || name.contains(['/', '\\']) {
                return Err("--stdin NAME: the name must be a plain file name".into());
            }
            let dir = std::env::temp_dir().join(format!("packrat-stdin-{}", std::process::id()));
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let file = dir.join(name);
            let mut f = std::fs::File::create(&file).map_err(|e| e.to_string())?;
            std::io::copy(&mut std::io::stdin().lock(), &mut f).map_err(|e| e.to_string())?;
            inputs.push(file);
            Some(dir)
        }
        None => None,
    };

    if mode != Mode::Create && output.exists() {
        let result = add_to_existing(
            &output,
            &inputs,
            mode,
            masks,
            !no_recursion,
            level,
            threads,
            recovery,
            oo.password,
        );
        if let Some(dir) = &spool {
            let _ = std::fs::remove_dir_all(dir);
        }
        let report = result?;
        if delete_source {
            let spooled = spool.as_deref();
            for f in report
                .added_files
                .iter()
                .filter(|f| !spooled.is_some_and(|d| f.starts_with(d)))
            {
                if let Err(e) = std::fs::remove_file(f) {
                    eprintln!("cannot delete {}: {e}", f.display());
                }
            }
            for d in inputs.iter().filter(|p| p.is_dir()) {
                prune_empty(d);
            }
        }
        return Ok(0);
    }
    let lower = output.to_string_lossy().to_ascii_lowercase();
    let format = match format_name {
        Some(n) => Format::from_name(&n).ok_or_else(|| format!("unknown format '{n}'"))?,
        None => [
            "tar.gz", "tar.zst", "tar.xz", "tar.lz4", "tar.bz2", "tgz", "tzst", "txz", "tbz2", "tar", "7z", "prat",
            "gz", "xz", "bz2", "zst", "lz4", "zip",
        ]
        .iter()
        .find(|e| lower.ends_with(&format!(".{e}")))
        .and_then(|e| Format::from_name(e))
        .unwrap_or(if sfx {
            Format::SevenZ
        } else {
            Format::Zip(packrat_core::zip::ZipMethod::Deflate)
        }),
    };
    let mut opts = CreateOptions::new(format);
    opts.sfx = sfx;
    if let Some(m) = &method {
        if format == Format::SevenZ {
            opts.sevenz_method = Some(
                packrat_core::sevenz::SevenZMethod::from_name(m)
                    .ok_or_else(|| format!("unknown 7z method '{m}' (lzma2, lzma, ppmd, bzip2, deflate, copy)"))?,
            );
        } else {
            return Err("--method applies to 7z archives".into());
        }
    }
    if (delta.is_some() || fast_bytes.is_some()) && format != Format::SevenZ {
        return Err("--delta and --fb apply to 7z archives".into());
    }
    opts.delta = delta.map(|d| d.clamp(1, 256) as u32);
    opts.fast_bytes = fast_bytes.map(|f| f.clamp(5, 273) as u32);
    opts.volume_bytes = volume;
    if let Some(l) = level {
        opts.level = l.clamp(1, 9) as u32;
    }
    opts.threads = threads;
    opts.masks = masks;
    opts.recursive = !no_recursion;
    opts.password = oo.password;
    opts.encrypt_names = !no_names;
    opts.smart = !no_filters;
    if let Some(mb) = dict_mb {
        // LZMA2 allows up to 1 GiB less one byte; the encoder checks the exact limit
        opts.dict_bytes =
            Some(u32::try_from(mb.saturating_mul(1 << 20)).map_err(|_| "--dict-mb is too large (the limit is 1023)")?);
    }
    opts.solid_bytes = solid_mb.map(|mb| (mb as u64).saturating_mul(1 << 20));
    opts.kdf_mib = kdf_mb
        .map(|mb| u32::try_from(mb).map_err(|_| "--kdf-mb is too large (the limit is 1024)"))
        .transpose()?;
    opts.recovery_percent =
        u32::try_from(recovery.unwrap_or(0)).map_err(|_| "--recovery is a percentage from 1 to 100")?;

    let started = std::time::Instant::now();
    let created = create_archive(&output, &inputs, &opts, &Progress::new());
    if let Some(dir) = &spool {
        let _ = std::fs::remove_dir_all(dir);
    }
    let report = created.map_err(|e| e.to_string())?;
    let secs = started.elapsed().as_secs_f64();
    println!(
        "{}: {} entries, {} -> {} in {secs:.2} s",
        output.display(),
        report.entries,
        human(report.bytes_in),
        human(report.bytes_out)
    );
    for (p, why) in &report.skipped {
        eprintln!("skipped {}: {why}", p.display());
    }
    if delete_source {
        if !report.skipped.is_empty() {
            eprintln!("--delete-source: some paths were skipped, nothing was deleted");
            return Ok(1);
        }
        let mut removed = 0usize;
        let spooled = spool.as_deref();
        for f in report
            .added
            .iter()
            .filter(|f| !spooled.is_some_and(|d| f.starts_with(d)))
        {
            match std::fs::remove_file(f) {
                Ok(()) => removed += 1,
                Err(e) => eprintln!("cannot delete {}: {e}", f.display()),
            }
        }
        for d in inputs.iter().filter(|p| p.is_dir()) {
            prune_empty(d);
        }
        println!("deleted {removed} source files");
    }
    Ok(u8::from(!report.skipped.is_empty()))
}

/// Deterministic benchmark data: many small text files, medium structured binaries and large incompressible files.
fn cmd_bench_gen(mut args: Args) -> Result<u8, String> {
    use std::io::Write;
    let mb = args.number(&["--mb"])?.unwrap_or(600) as u64;
    let dir = PathBuf::from(args.0.first().cloned().ok_or("bench-gen: target folder is missing")?);
    if dir.exists() && std::fs::read_dir(&dir).map_err(|e| e.to_string())?.next().is_some() {
        return Err(format!("{} is not empty", dir.display()));
    }
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    const WORDS: [&str; 32] = [
        "fn", "let", "mut", "impl", "struct", "return", "match", "self", "pub", "use", "async", "await", "Vec",
        "String", "Option", "Result", "value", "index", "buffer", "stream", "archive", "entry", "thread", "block",
        "name", "size", "path", "frame", "offset", "header", "crc", "limit",
    ];
    let mk = |sub: &str| -> Result<PathBuf, String> {
        let d = dir.join(sub);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        Ok(d)
    };
    let total = mb * 1024 * 1024;
    let (text_bytes, bin_bytes, noise_bytes) = (total * 40 / 100, total * 35 / 100, total * 25 / 100);

    let src = mk("src")?;
    let mut written = 0u64;
    let mut i = 0;
    while written < text_bytes {
        let size = 2_000 + next() % 38_000;
        let mut body = String::with_capacity(size as usize + 64);
        while (body.len() as u64) < size {
            for _ in 0..(3 + next() % 8) {
                body.push_str(WORDS[(next() % 32) as usize]);
                body.push(if next() % 5 == 0 { '_' } else { ' ' });
            }
            body.push_str(&format!(
                "{};
",
                next() % 10_000
            ));
        }
        let sub = src.join(format!("mod{:02}", i % 40));
        std::fs::create_dir_all(&sub).map_err(|e| e.to_string())?;
        std::fs::write(sub.join(format!("file{i:05}.rs")), &body).map_err(|e| e.to_string())?;
        written += body.len() as u64;
        i += 1;
    }

    let data = mk("data")?;
    let mut written = 0u64;
    let mut i = 0;
    while written < bin_bytes {
        let size = 2 * 1024 * 1024 + next() % (8 * 1024 * 1024);
        let mut f = std::fs::File::create(data.join(format!("table{i:03}.bin"))).map_err(|e| e.to_string())?;
        let mut left = size;
        while left > 0 {
            // records: a counter, small numbers and some noise
            let mut rec = Vec::with_capacity(64 * 1024);
            while rec.len() < 64 * 1024 {
                rec.extend((written + rec.len() as u64).to_le_bytes());
                rec.extend((next() % 1000).to_le_bytes());
                rec.extend(next().to_le_bytes());
                rec.extend([0u8; 16]);
            }
            let n = (rec.len() as u64).min(left) as usize;
            f.write_all(&rec[..n]).map_err(|e| e.to_string())?;
            left -= n as u64;
        }
        written += size;
        i += 1;
    }

    let media = mk("media")?;
    let mut written = 0u64;
    let mut i = 0;
    while written < noise_bytes {
        let size = (noise_bytes / 4).max(1 << 20);
        let mut f = std::fs::File::create(media.join(format!("clip{i}.bin"))).map_err(|e| e.to_string())?;
        let mut left = size;
        while left > 0 {
            let n = (1u64 << 20).min(left) as usize;
            let mut buf = vec![0u8; n];
            for b in buf.chunks_mut(8) {
                let v = next().to_le_bytes();
                b.copy_from_slice(&v[..b.len()]);
            }
            f.write_all(&buf).map_err(|e| e.to_string())?;
            left -= n as u64;
        }
        written += size;
        i += 1;
    }
    println!("wrote {} to {}", human(written + text_bytes + bin_bytes), dir.display());
    Ok(0)
}

fn cmd_repair(mut args: Args) -> Result<u8, String> {
    let out = args.value(&["-o", "--output"])?;
    args.reject_unknown()?;
    let path = args.0.first().cloned().ok_or("repair: archive path is missing")?;
    let src = PathBuf::from(&path);
    let dst = match out {
        Some(o) => PathBuf::from(o),
        None => {
            let stem = src
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let ext = src
                .extension()
                .map_or_else(|| "prat".to_owned(), |e| e.to_string_lossy().into_owned());
            src.with_file_name(format!("{stem}.repaired.{ext}"))
        }
    };
    let started = std::time::Instant::now();
    let mut magic = [0u8; 8];
    let is_zip = std::fs::File::open(&src)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .is_ok()
        && magic.starts_with(b"PK");
    let repaired = if is_zip {
        packrat_core::prat::zip_recover::repair(&src, &dst)
    } else {
        packrat_core::prat::recover::repair(&src, &dst)
    };
    match repaired {
        Ok(r) => {
            if r.repaired == 0 && !r.footer_rewritten && !r.recovery_rewritten {
                println!(
                    "{path}: no damage found ({} areas checked); the copy {} is identical",
                    r.shards,
                    dst.display()
                );
            } else {
                println!(
                    "{path}: repaired {} of {} areas of {} KiB{} in {:.2} s -> {}",
                    r.repaired,
                    r.shards,
                    r.shard_bytes >> 10,
                    match (r.footer_rewritten, r.recovery_rewritten) {
                        (true, true) => ", rewrote the end of the file and regenerated damaged recovery data",
                        (true, false) => " and rewrote the end of the file",
                        (false, true) => " and regenerated damaged recovery data",
                        (false, false) => "",
                    },
                    started.elapsed().as_secs_f64(),
                    dst.display()
                );
            }
            Ok(0)
        }
        Err(e) => {
            eprintln!("packrat-cli: {path}: {e}");
            Ok(1)
        }
    }
}

fn cmd_test(mut args: Args) -> Result<u8, String> {
    let oo = open_options(&mut args)?;
    let sha = args.flag("--sha256");
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    args.reject_unknown()?;
    let path = args.0.first().cloned().ok_or("test: archive path is missing")?;
    let a = open_archive(&path, &oo)?;
    let started = std::time::Instant::now();
    let report = packrat_core::verify::verify(&*a, None, threads, &Progress::new());
    for f in &report.failures {
        let name = if f.path.is_empty() { "(stream)" } else { f.path.as_str() };
        eprintln!("DAMAGED {name}: {}", f.message);
    }
    println!(
        "{path}: {} files checked ({}), {} damaged, {:.2} s",
        report.ok + report.failures.len() as u64,
        human(report.bytes),
        report.failures.len(),
        started.elapsed().as_secs_f64()
    );
    if sha {
        let hash =
            packrat_core::verify::sha256_file(&PathBuf::from(&path), &Progress::new()).map_err(|e| e.to_string())?;
        println!("SHA-256 {hash}");
    }
    Ok(u8::from(!report.is_clean()))
}

fn cmd_hash(mut args: Args) -> Result<u8, String> {
    use std::io::Read;
    let algo = args
        .value(&["--algo", "-a"])?
        .unwrap_or_else(|| "sha256".into())
        .to_ascii_lowercase();
    args.reject_unknown()?;
    if args.0.is_empty() {
        return Err("hash: give at least one file".into());
    }
    if !["crc32", "sha1", "sha256", "blake3"].contains(&algo.as_str()) {
        return Err(format!("unknown algorithm '{algo}' (crc32, sha1, sha256, blake3)"));
    }
    let mut failed = false;
    for path in &args.0 {
        let mut f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{path}: {e}");
                failed = true;
                continue;
            }
        };
        let mut crc = crc32fast::Hasher::new();
        let mut s1 = <sha1::Sha1 as sha1::Digest>::new();
        let mut s256 = <sha2::Sha256 as sha2::Digest>::new();
        let mut b3 = blake3::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf).map_err(|e| format!("{path}: {e}"))?;
            if n == 0 {
                break;
            }
            match algo.as_str() {
                "crc32" => crc.update(&buf[..n]),
                "sha1" => sha1::Digest::update(&mut s1, &buf[..n]),
                "sha256" => sha2::Digest::update(&mut s256, &buf[..n]),
                _ => {
                    b3.update(&buf[..n]);
                }
            }
        }
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let digest = match algo.as_str() {
            "crc32" => format!("{:08x}", crc.finalize()),
            "sha1" => hex(&sha1::Digest::finalize(s1)),
            "sha256" => hex(&sha2::Digest::finalize(s256)),
            _ => b3.finalize().to_hex().to_string(),
        };
        println!("{digest}  {path}");
    }
    Ok(u8::from(failed))
}

/// Speed and ratio of each compressor on one generated data set held in memory; nothing touches the disk.
fn cmd_bench(mut args: Args) -> Result<u8, String> {
    use packrat_core::codec::stream::{Compression, writer};
    use std::io::Write;
    let mb = args.number(&["--mb"])?.unwrap_or(16).clamp(1, 512);
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    args.reject_unknown()?;
    // mostly text-like with repeats and some binary runs: roughly what source trees look like
    let mut data = Vec::with_capacity(mb << 20);
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let words = [
        "fn", "let", "match", "struct", "impl", "return", "pub", "use", "self", "Result", "Vec", "String",
    ];
    while data.len() < mb << 20 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        data.extend_from_slice(words[(x % words.len() as u64) as usize].as_bytes());
        data.push(if x & 0x70 == 0 { b'\n' } else { b' ' });
        if x & 0xFFF == 0 {
            data.extend((0..64u32).map(|i| (x >> (i % 8)) as u8));
        }
    }
    data.truncate(mb << 20);
    println!("{:<8} {:>10} {:>8} {:>10}", "codec", "size", "ratio", "MiB/s");
    for (name, c) in [
        ("lz4", Compression::Lz4),
        ("zstd", Compression::Zst),
        ("gzip", Compression::Gz),
        ("xz", Compression::Xz),
    ] {
        let sink = CountingSink::default();
        let t = std::time::Instant::now();
        let mut w = writer(c, sink.clone(), 5, threads).map_err(|e| e.to_string())?;
        w.write_all(&data).map_err(|e| e.to_string())?;
        w.finish().map_err(|e| e.to_string())?;
        let secs = t.elapsed().as_secs_f64().max(1e-6);
        let size = sink.len();
        println!(
            "{name:<8} {:>10} {:>7.1}% {:>10.1}",
            human(size as u64),
            size as f64 * 100.0 / data.len() as f64,
            mb as f64 / secs
        );
    }
    Ok(0)
}

/// A `Write + Send + 'static` that keeps only the number of bytes written.
#[derive(Clone, Default)]
struct CountingSink(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl CountingSink {
    fn len(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::io::Write for CountingSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.fetch_add(b.len(), std::sync::atomic::Ordering::Relaxed);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
