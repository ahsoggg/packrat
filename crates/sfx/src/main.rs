//! The stub of Packrat's self-extracting archives. The archive lies after this program in the same file
//! (see `packrat_core::sfx`); running the file unpacks it.

use packrat_core::extract::{self, ExtractOptions, Resolution};
use packrat_core::source::{FileSource, SharedSource};
use packrat_core::volume::SliceSource;
use packrat_core::{EntryKind, OpenOptions, Password, Progress, open, sfx};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

const HELP: &str = "\
Self-extracting archive made by Packrat.

  -o DIR          unpack into DIR (default: a folder next to this file, named like it)
  -y              replace files that already exist (default: keep them)
  -l              only list what is inside
  --ask-password  ask for the password of an encrypted archive (also PACKRAT_PASSWORD, --password-file FILE)
  -h              this help
";

fn main() -> ExitCode {
    let code = match try_run() {
        Ok(c) => c,
        Err(m) => {
            eprintln!("{m}");
            2
        }
    };
    pause_if_alone();
    ExitCode::from(code)
}

struct Args(Vec<String>);

impl Args {
    fn flag(&mut self, names: &[&str]) -> bool {
        match self.0.iter().position(|a| names.contains(&a.as_str())) {
            Some(i) => {
                self.0.remove(i);
                true
            }
            None => false,
        }
    }

    fn value(&mut self, name: &str) -> Result<Option<String>, String> {
        match self.0.iter().position(|a| a == name) {
            Some(i) if i + 1 < self.0.len() => {
                let v = self.0.remove(i + 1);
                self.0.remove(i);
                Ok(Some(v))
            }
            Some(_) => Err(format!("{name} needs a value")),
            None => Ok(None),
        }
    }
}

fn try_run() -> Result<u8, String> {
    let mut args = Args(std::env::args().skip(1).collect());
    if args.flag(&["-h", "--help", "/?"]) {
        print!("{HELP}");
        return Ok(0);
    }
    let overwrite = args.flag(&["-y"]);
    let list_only = args.flag(&["-l"]);
    let ask = args.flag(&["--ask-password"]);
    let out_dir = args.value("-o")?;
    let password_file = args.value("--password-file")?;
    if let Some(bad) = args.0.first() {
        return Err(format!("unknown argument '{bad}' (try -h)"));
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let whole: SharedSource = Arc::new(FileSource::open(&exe).map_err(|e| format!("{}: {e}", exe.display()))?);
    let (off, len) =
        sfx::find_payload(&*whole).ok_or("this program holds no archive (the file is damaged or cut off)")?;
    let src: SharedSource = Arc::new(SliceSource::new(whole, off, len));

    let mut oo = OpenOptions::default();
    if let Some(f) = password_file {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}"))?;
        oo.password = Some(Password::new(text.lines().next().unwrap_or("")));
    } else if ask {
        oo.password = Some(Password::new(&prompt_password()?));
    } else if let Ok(p) = std::env::var("PACKRAT_PASSWORD") {
        oo.password = Some(Password::new(&p));
    }
    let stem = exe
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".into());
    let archive = match open::open_source_with(src.clone(), &stem, &oo) {
        Err(packrat_core::Error::PasswordRequired) if oo.password.is_none() => {
            oo.password = Some(Password::new(&prompt_password()?));
            open::open_source_with(src, &stem, &oo).map_err(|e| e.to_string())?
        }
        other => other.map_err(|e| e.to_string())?,
    };

    if list_only {
        for e in archive.entries() {
            let size = if e.kind == EntryKind::File {
                e.size.to_string()
            } else {
                String::new()
            };
            println!("{size:>12}  {}", e.path);
        }
        return Ok(0);
    }

    let base = exe.parent().map_or_else(|| PathBuf::from("."), PathBuf::from);
    let (dest, smart) = match out_dir {
        Some(d) => (PathBuf::from(d), false),
        None => (base, true),
    };
    let mut opts = ExtractOptions::new(&dest, format!("{stem}.sfx"));
    opts.smart = smart;
    opts.archive_len = len;
    opts.default_resolution = if overwrite {
        Resolution::Replace
    } else {
        Resolution::Skip
    };
    let progress = Progress::new();
    let plan = extract::plan(&*archive, &opts);
    if !plan.risks.is_empty() {
        for r in &plan.risks {
            eprintln!("RISK: {}", r.describe());
        }
        eprintln!("nothing was unpacked: the archive looks dangerous (huge expansion, too little disk space, ...)");
        return Ok(1);
    }
    println!("unpacking to {}", plan.base.display());
    let report = extract::execute(&*archive, &plan, &opts, &progress).map_err(|e| e.to_string())?;
    println!("{} files, {} folders", report.files, report.dirs);
    for p in &report.skipped_existing {
        println!("kept (exists): {p}");
    }
    for b in &report.blocked {
        eprintln!("BLOCKED {}: {}", b.path, b.message);
    }
    for f in &report.failed {
        eprintln!("FAILED {}: {}", f.path, f.message);
    }
    Ok(u8::from(!report.blocked.is_empty() || !report.failed.is_empty()))
}

fn prompt_password() -> Result<String, String> {
    eprint!("Password: ");
    read_hidden_line().map_err(|e| e.to_string())
}

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

/// Started by a double click, the console closes with the program: wait so that the result can be read.
#[cfg(windows)]
fn pause_if_alone() {
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    let mut ids = [0u32; 4];
    // SAFETY: the buffer is valid for 4 entries, as the length says.
    let n = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), 4) };
    if n == 1 {
        eprintln!("Press Enter to close.");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
}

#[cfg(not(windows))]
fn pause_if_alone() {}
