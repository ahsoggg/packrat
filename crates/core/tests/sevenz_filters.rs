use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::open::{open, open_with};
use packrat_core::{Error, OpenOptions, Progress};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const SECRET: &str = "filters-пароль";

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 33) as u8
        })
        .collect()
}

/// A PE image header for x64 followed by code-like bytes: CALLs from many places to a few functions. The
/// relative operand differs at every call site (target minus position), which is what BCJ undoes.
fn fake_exe(seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[..2].copy_from_slice(b"MZ");
    v[0x3c] = 0x80;
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    let mut rnd = noise(60_000, seed).into_iter();
    let mut next = move || rnd.next().unwrap();
    while v.len() < 150_000 {
        let target = 0x1000 + 0x40 * (next() as u32 % 16);
        let rel = target.wrapping_sub(v.len() as u32 + 5);
        v.push(0xe8);
        v.extend(rel.to_le_bytes());
        v.extend([0x48, 0x89, 0xc0 + next() % 8]);
    }
    v
}

fn sample_dir(root: &Path) -> PathBuf {
    let src = root.join("data");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("app.exe"), fake_exe(1)).unwrap();
    fs::write(src.join("sub").join("lib.dll"), fake_exe(2)).unwrap();
    fs::write(src.join("sub").join("photo.jpg"), noise(200_000, 5)).unwrap();
    fs::write(src.join("notes.txt"), "text ".repeat(5000)).unwrap();
    fs::write(src.join("empty.bin"), b"").unwrap();
    fs::write(src.join("fake.dll"), b"this is not a PE file").unwrap();
    src
}

fn read_entry(a: &dyn packrat_core::Archive, name: &str) -> Vec<u8> {
    let e = a
        .entries()
        .iter()
        .find(|e| e.path == name)
        .unwrap_or_else(|| panic!("{name} missing"));
    let mut v = Vec::new();
    a.open_entry(e.index).unwrap().read_to_end(&mut v).unwrap();
    v
}

fn seven_zip() -> Option<PathBuf> {
    let p = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
    p.exists().then_some(p)
}

fn run(exe: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(exe).args(args).output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn make(dir: &Path, name: &str, src: &Path, password: Option<&str>, smart: bool) -> PathBuf {
    let out = dir.join(name);
    let mut opts = CreateOptions::new(Format::SevenZ);
    opts.smart = smart;
    if let Some(p) = password {
        opts.password = Some(packrat_core::Password::new(p));
    }
    create_archive(&out, std::slice::from_ref(&src.to_path_buf()), &opts, &Progress::new()).unwrap();
    out
}

fn check_contents(a: &dyn packrat_core::Archive, src: &Path) {
    for rel in [
        "app.exe",
        "sub/lib.dll",
        "sub/photo.jpg",
        "notes.txt",
        "fake.dll",
        "empty.bin",
    ] {
        assert_eq!(
            read_entry(a, &format!("data/{rel}")),
            fs::read(src.join(rel)).unwrap(),
            "{rel}"
        );
    }
}

#[test]
fn filtered_7z_roundtrips_plain_and_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample_dir(dir.path());

    let plain = make(dir.path(), "plain.7z", &src, None, true);
    check_contents(&*open(&plain).unwrap(), &src);

    let enc = make(dir.path(), "enc.7z", &src, Some(SECRET), true);
    assert!(matches!(open(&enc).err(), Some(Error::PasswordRequired)));
    let a = open_with(&enc, &OpenOptions::default().with_password(SECRET)).unwrap();
    check_contents(&*a, &src);
}

#[test]
fn smart_off_still_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample_dir(dir.path());
    let out = make(dir.path(), "raw.7z", &src, None, false);
    check_contents(&*open(&out).unwrap(), &src);
}

#[test]
fn smart_mode_shrinks_executables() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample_dir(dir.path());
    let smart = fs::metadata(make(dir.path(), "s.7z", &src, None, true)).unwrap().len();
    let raw = fs::metadata(make(dir.path(), "r.7z", &src, None, false)).unwrap().len();
    assert!(smart < raw, "BCJ should help on call-heavy code: {smart} vs {raw}");
}

#[test]
fn seven_zip_reads_filtered_archives() {
    let Some(z) = seven_zip() else {
        eprintln!("7-Zip is not installed: skipped");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let src = sample_dir(dir.path());
    for password in [None, Some(SECRET)] {
        let out = make(
            dir.path(),
            &format!("seven-{}.7z", password.is_some()),
            &src,
            password,
            true,
        );
        let arch = out.to_str().unwrap();
        let pw = format!("-p{}", password.unwrap_or(""));

        let (ok, log) = run(&z, &["t", arch, &pw]);
        assert!(ok, "7z t failed: {log}");

        let (ok, list) = run(&z, &["l", "-slt", arch, &pw]);
        assert!(ok, "{list}");
        assert!(list.contains("BCJ"), "executables must use a BCJ filter:\n{list}");
        assert!(list.contains("Copy"), "packed data must be stored:\n{list}");

        let dest = dir.path().join("x");
        let _ = fs::remove_dir_all(&dest);
        let (ok, log) = run(&z, &["x", arch, &pw, &format!("-o{}", dest.display()), "-y"]);
        assert!(ok, "{log}");
        for rel in ["app.exe", "sub/lib.dll", "sub/photo.jpg", "notes.txt", "fake.dll"] {
            assert_eq!(
                fs::read(dest.join("data").join(rel)).unwrap(),
                fs::read(src.join(rel)).unwrap(),
                "{rel}"
            );
        }
    }
}

/// An early empty file followed by many directories made sevenz-rust2 write a too short "empty file" bit
/// vector, which 7-Zip rejects with "Headers Error" (Packrat itself still read such archives).
#[test]
fn empty_file_before_many_directories_gives_a_header_7zip_accepts() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("data");
    fs::create_dir_all(src.join("d00")).unwrap();
    fs::write(src.join("d00").join("empty.txt"), b"").unwrap();
    fs::write(src.join("d00").join("a.txt"), "alpha ".repeat(50)).unwrap();
    for i in 1..=12 {
        let d = src.join(format!("d{i:02}"));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("f.txt"), format!("file {i} ").repeat(30)).unwrap();
    }
    for smart in [true, false] {
        let out = make(dir.path(), &format!("dirs-{smart}.7z"), &src, None, smart);
        let a = open(&out).unwrap();
        assert!(read_entry(&*a, "data/d00/empty.txt").is_empty());
        assert_eq!(read_entry(&*a, "data/d12/f.txt"), "file 12 ".repeat(30).into_bytes());
        if let Some(z) = seven_zip() {
            let (ok, log) = run(&z, &["t", out.to_str().unwrap()]);
            assert!(ok, "7z t failed (smart={smart}): {log}");
        }
    }
}
