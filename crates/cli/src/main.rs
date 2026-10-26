use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::encoding::NameEncoding;
use packrat_core::extract::{self, ExtractOptions, Resolution};
use packrat_core::{Archive, EntryKind, OpenOptions, Password, Progress, open, timeutil};
use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
packrat-cli — Packrat archive tool

USAGE:
  packrat-cli list <archive> [--encoding NAME] [PASSWORD OPTIONS]
  packrat-cli extract <archive> [NAMES...] [-o DIR] [--smart] [--threads N]
                      [--skip | --overwrite | --keep-both] [--accept-risks] [--repair]
                      [--encoding NAME] [PASSWORD OPTIONS]
  packrat-cli test <archive> [--sha256] [--threads N] [--encoding NAME] [PASSWORD OPTIONS]
  packrat-cli create <output> <paths...> [--format FMT] [--level N] [--threads N]
                      [PASSWORD OPTIONS] [--no-encrypt-names] [--no-filters]
  packrat-cli bench-gen <dir> [--mb N]     write the deterministic data set used by scripts/bench.ps1
  packrat-cli --version | --help

FORMATS (create): zip (deflate), zip-zstd, zip-store, 7z, tar, tar.gz, tar.zst, tar.xz, tar.lz4
  The format is taken from the output extension when --format is not given.

EXTRACT:
  --smart      one root folder goes straight to the target, one file lands next to it,
               loose items get a folder named after the archive
  existing files are skipped unless --overwrite or --keep-both is given

PASSWORD OPTIONS: --ask-password | --password-file FILE | env PACKRAT_PASSWORD
  Passwords are never taken from the command line. Creating: ZIP and 7z get AES-256; 7z also hides file names
  (--no-encrypt-names keeps them visible). TAR cannot be encrypted.
  7z sorts files by type, runs a BCJ filter over executables and stores already-packed files (JPEG, MP4, ZIP...)
  as they are; --no-filters keeps the input order and compresses everything the same way.

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

    fn number(&mut self, names: &[&str]) -> Result<Option<usize>, String> {
        self.value(names)?
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("{} must be a number, got '{v}'", names[0]))
            })
            .transpose()
    }
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
    let cmd = args.0.remove(0);
    let result = match cmd.as_str() {
        "list" | "l" => cmd_list(args),
        "extract" | "x" => cmd_extract(args),
        "create" | "c" | "a" => cmd_create(args),
        "test" | "t" => cmd_test(args),
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
    let path = args.0.first().cloned().ok_or("list: archive path is missing")?;
    let a = open_archive(&path, &oo)?;
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
    for e in a.entries() {
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
    let path = args.0.first().cloned().ok_or("extract: archive path is missing")?;
    let wanted: Vec<String> = args.0.iter().skip(1).map(|s| s.replace('\\', "/")).collect();

    let a = open_archive(&path, &oo)?;
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
    if !wanted.is_empty() {
        let sel: Vec<usize> = a
            .entries()
            .iter()
            .filter(|e| {
                let p = e.path.replace('\\', "/");
                wanted
                    .iter()
                    .any(|w| p == *w || p.starts_with(&format!("{}/", w.trim_end_matches('/'))))
            })
            .map(|e| e.index)
            .collect();
        if sel.is_empty() {
            return Err("none of the given names is in the archive".into());
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

fn cmd_create(mut args: Args) -> Result<u8, String> {
    let no_names = args.flag("--no-encrypt-names");
    let no_filters = args.flag("--no-filters");
    let oo = open_options(&mut args)?;
    let format_name = args.value(&["--format", "-f"])?;
    let level = args.number(&["--level", "-l"])?;
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
    if args.0.len() < 2 {
        return Err("create: need an output file and at least one path".into());
    }
    let output = PathBuf::from(args.0.remove(0));
    let inputs: Vec<PathBuf> = args.0.iter().map(PathBuf::from).collect();

    let lower = output.to_string_lossy().to_ascii_lowercase();
    let format = match format_name {
        Some(n) => Format::from_name(&n).ok_or_else(|| format!("unknown format '{n}'"))?,
        None => [
            "tar.gz", "tar.zst", "tar.xz", "tar.lz4", "tgz", "tzst", "txz", "tar", "7z", "zip",
        ]
        .iter()
        .find(|e| lower.ends_with(&format!(".{e}")))
        .and_then(|e| Format::from_name(e))
        .unwrap_or(Format::Zip(packrat_core::zip::ZipMethod::Deflate)),
    };
    let mut opts = CreateOptions::new(format);
    if let Some(l) = level {
        opts.level = l.clamp(1, 9) as u32;
    }
    opts.threads = threads;
    opts.password = oo.password;
    opts.encrypt_names = !no_names;
    opts.smart = !no_filters;

    let started = std::time::Instant::now();
    let report = create_archive(&output, &inputs, &opts, &Progress::new()).map_err(|e| e.to_string())?;
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

fn cmd_test(mut args: Args) -> Result<u8, String> {
    let oo = open_options(&mut args)?;
    let sha = args.flag("--sha256");
    let threads = args.number(&["--threads", "-j"])?.unwrap_or(0);
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
