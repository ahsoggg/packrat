use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::zip::ZipMethod;
use packrat_core::{Password, Progress, open};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn stub() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_packrat-sfx"))
}

fn sample(root: &Path) -> PathBuf {
    let d = root.join("data");
    fs::create_dir_all(d.join("sub")).unwrap();
    fs::write(d.join("a.txt"), "alpha").unwrap();
    fs::write(d.join("sub/b.txt"), "beta".repeat(1000)).unwrap();
    d
}

fn build(root: &Path, name: &str, format: Format, tweak: impl FnOnce(&mut CreateOptions)) -> PathBuf {
    let d = sample(root);
    let out = root.join(name);
    let mut o = CreateOptions::new(format);
    o.sfx = true;
    o.sfx_stub = Some(stub());
    tweak(&mut o);
    create_archive(&out, &[d], &o, &Progress::new()).unwrap();
    out
}

#[test]
fn the_program_unpacks_itself() {
    for (name, format) in [
        ("a.exe", Format::SevenZ),
        ("b.exe", Format::Zip(ZipMethod::Deflate)),
        ("c.exe", Format::Prat),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let exe = build(dir.path(), name, format, |_| {});
        let dest = dir.path().join("out");
        let status = Command::new(&exe).arg("-o").arg(&dest).output().unwrap();
        assert!(
            status.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert_eq!(fs::read_to_string(dest.join("data/a.txt")).unwrap(), "alpha", "{name}");
        assert_eq!(
            fs::read_to_string(dest.join("data/sub/b.txt")).unwrap().len(),
            4000,
            "{name}"
        );

        // listing, and Packrat opens the program like any archive
        let list = Command::new(&exe).arg("-l").output().unwrap();
        assert!(
            String::from_utf8_lossy(&list.stdout).contains("data/sub/b.txt"),
            "{name}"
        );
        let a = open::open(&exe).unwrap();
        assert_eq!(a.entries().iter().filter(|e| e.is_file()).count(), 2, "{name}");
    }
}

#[test]
fn by_default_a_folder_next_to_the_program_is_made_and_nothing_is_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let exe = build(dir.path(), "pack.exe", Format::SevenZ, |_| {});
    let run = || Command::new(&exe).output().unwrap();
    assert!(run().status.success());
    // one root folder goes straight next to the program
    assert_eq!(fs::read_to_string(dir.path().join("data/a.txt")).unwrap(), "alpha");
    fs::write(dir.path().join("data/a.txt"), "mine").unwrap();
    assert!(run().status.success());
    assert_eq!(fs::read_to_string(dir.path().join("data/a.txt")).unwrap(), "mine");
    assert!(Command::new(&exe).arg("-y").output().unwrap().status.success());
    assert_eq!(fs::read_to_string(dir.path().join("data/a.txt")).unwrap(), "alpha");
}

#[test]
fn encrypted_program_takes_the_password_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let exe = build(dir.path(), "secret.exe", Format::Zip(ZipMethod::Deflate), |o| {
        o.password = Some(Password::new("pw"));
    });
    let dest = dir.path().join("out");
    let wrong = Command::new(&exe)
        .arg("-o")
        .arg(&dest)
        .env("PACKRAT_PASSWORD", "nope")
        .output()
        .unwrap();
    assert!(!wrong.status.success() || !dest.join("data/a.txt").exists());
    let ok = Command::new(&exe)
        .arg("-o")
        .arg(&dest)
        .env("PACKRAT_PASSWORD", "pw")
        .output()
        .unwrap();
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    assert_eq!(fs::read_to_string(dest.join("data/a.txt")).unwrap(), "alpha");
}

#[test]
fn a_program_that_was_cut_off_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let exe = build(dir.path(), "cut.exe", Format::SevenZ, |_| {});
    let bytes = fs::read(&exe).unwrap();
    fs::write(&exe, &bytes[..bytes.len() - 100]).unwrap();
    let out = Command::new(&exe).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no archive"));
}

#[test]
fn volumes_of_a_program_join_again() {
    let dir = tempfile::tempdir().unwrap();
    let exe = build(dir.path(), "v.exe", Format::SevenZ, |o| o.volume_bytes = Some(1 << 20));
    assert!(!exe.exists());
    let first = dir.path().join("v.exe.001");
    assert!(first.exists() && dir.path().join("v.exe.002").exists());
    let a = open::open(&first).unwrap();
    assert_eq!(a.entries().iter().filter(|e| e.is_file()).count(), 2);
}
