use std::fs;
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packrat-cli"))
}

#[test]
fn create_list_extract_smart_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("project");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), "alpha").unwrap();
    fs::write(src.join("sub/b.txt"), "beta").unwrap();
    let archive = dir.path().join("project.tar.zst");

    let out = cli()
        .args(["create"])
        .arg(&archive)
        .arg(&src)
        .args(["--threads", "2"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let out = cli().arg("list").arg(&archive).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("project/sub/b.txt"), "{text}");

    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let out = cli()
        .arg("extract")
        .arg(&archive)
        .arg("-o")
        .arg(&dest)
        .arg("--smart")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    // one root folder: no project/project
    assert_eq!(fs::read_to_string(dest.join("project/sub/b.txt")).unwrap(), "beta");
    assert!(!dest.join("project/project").exists());

    // second run must not overwrite anything
    fs::write(dest.join("project/a.txt"), "edited").unwrap();
    let out = cli()
        .arg("extract")
        .arg(&archive)
        .arg("-o")
        .arg(&dest)
        .arg("--smart")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(dest.join("project/a.txt")).unwrap(), "edited");
}

#[test]
fn bad_usage_exits_with_2() {
    assert_eq!(cli().arg("frobnicate").output().unwrap().status.code(), Some(2));
    assert_eq!(cli().output().unwrap().status.code(), Some(2));
    assert!(cli().arg("--version").output().unwrap().status.success());
}

#[test]
fn passwords_come_from_the_environment_or_a_file_never_from_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("secret");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), "classified").unwrap();
    let archive = dir.path().join("secret.7z");
    let out = cli()
        .arg("create")
        .arg(&archive)
        .arg(&src)
        .env("PACKRAT_PASSWORD", "pw123")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let out = cli()
        .arg("extract")
        .arg(&archive)
        .arg("-o")
        .arg(&dest)
        .env_remove("PACKRAT_PASSWORD")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("password is required"));

    let pwfile = dir.path().join("pw.txt");
    fs::write(&pwfile, "pw123\n").unwrap();
    let out = cli()
        .arg("extract")
        .arg(&archive)
        .arg("-o")
        .arg(&dest)
        .arg("--password-file")
        .arg(&pwfile)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read_to_string(dest.join("secret/a.txt")).unwrap(), "classified");

    let out = cli()
        .args(["list", "--password", "pw123"])
        .arg(&archive)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "there is no --password option");
}

#[test]
fn old_zip_names_can_be_decoded_with_an_explicit_encoding() {
    use packrat_core::testkit::{RawEntry, raw_zip};
    let dir = tempfile::tempdir().unwrap();
    let name = encoding_rs::IBM866.encode("Документы/Отчёт за 2024.txt").0.into_owned();
    let zip = dir.path().join("old.zip");
    fs::write(&zip, raw_zip(&[RawEntry::file(name, "x")])).unwrap();
    let out = cli().arg("list").arg(&zip).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Документы/Отчёт за 2024.txt"), "{text}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("CP866"));
    let out = cli()
        .arg("list")
        .arg(&zip)
        .args(["--encoding", "cp1251"])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("Документы"),
        "forcing another code page changes the names"
    );
    let out = cli()
        .arg("list")
        .arg(&zip)
        .args(["--encoding", "klingon"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn risky_archives_need_explicit_acceptance() {
    use packrat_core::testkit::{RawEntry, raw_zip};
    let dir = tempfile::tempdir().unwrap();
    let zip = dir.path().join("bomb.zip");
    fs::write(
        &zip,
        raw_zip(&[RawEntry::file("zeros.bin", vec![0u8; 80 << 20]).deflated()]),
    )
    .unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let out = cli().arg("extract").arg(&zip).arg("-o").arg(&dest).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("RISK"));
    assert_eq!(
        fs::read_dir(&dest).unwrap().count(),
        0,
        "nothing written before acceptance"
    );
    let out = cli()
        .arg("extract")
        .arg(&zip)
        .arg("-o")
        .arg(&dest)
        .arg("--accept-risks")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::metadata(dest.join("zeros.bin")).unwrap().len(), 80 << 20);
}

#[test]
fn test_command_finds_damage_and_repair_rescues_a_cut_zip() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("docs");
    fs::create_dir_all(&src).unwrap();
    for i in 0..8 {
        fs::write(
            src.join(format!("f{i}.txt")),
            format!("content of file {i} ").repeat(3000),
        )
        .unwrap();
    }
    let archive = dir.path().join("docs.zip");
    assert!(
        cli()
            .arg("create")
            .arg(&archive)
            .arg(&src)
            .output()
            .unwrap()
            .status
            .success()
    );

    let out = cli().arg("test").arg(&archive).arg("--sha256").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && text.contains("0 damaged") && text.contains("SHA-256 "),
        "{text}"
    );

    let mut bytes = fs::read(&archive).unwrap();
    let at = bytes.len() / 2;
    for b in &mut bytes[at..at + 30] {
        *b ^= 0x5A;
    }
    let damaged = dir.path().join("damaged.zip");
    fs::write(&damaged, &bytes).unwrap();
    let out = cli().arg("test").arg(&damaged).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DAMAGED"));

    let cut = dir.path().join("cut.zip");
    fs::write(&cut, &fs::read(&archive).unwrap()[..bytes.len() * 7 / 10]).unwrap();
    assert_eq!(
        cli().arg("list").arg(&cut).output().unwrap().status.code(),
        Some(2),
        "a cut ZIP does not open normally"
    );
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let out = cli()
        .arg("extract")
        .arg(&cut)
        .arg("-o")
        .arg(&dest)
        .arg("--repair")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("scanning local headers"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.join("docs/f0.txt").exists());
    assert_eq!(
        fs::read_to_string(dest.join("docs/f0.txt")).unwrap(),
        "content of file 0 ".repeat(3000)
    );
}

#[test]
fn a_password_option_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("secret");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), "classified").unwrap();
    let archive = dir.path().join("oops.prat");
    // `--password abc` used to be taken for a file named "abc" and an UNPROTECTED archive was made
    let out = cli()
        .arg("create")
        .arg(&archive)
        .arg(&src)
        .args(["--format", "prat", "--password", "abc"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("unknown option") && err.contains("PACKRAT_PASSWORD"),
        "{err}"
    );
    assert!(!archive.exists(), "no archive may be made when the options are wrong");
    // other typos are refused too, but a file that really is called like an option still works
    let out = cli().arg("list").arg("--frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown option"));
}

#[test]
fn encrypted_prat_roundtrips_through_the_cli_and_repairs_without_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), "classified ".repeat(2000)).unwrap();
    fs::write(
        src.join("sub/b.bin"),
        (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let archive = dir.path().join("vault.prat");
    let out = cli()
        .arg("create")
        .arg(&archive)
        .arg(&src)
        .args(["--format", "prat", "--recovery", "10", "--kdf-mb", "1"])
        .env("PACKRAT_PASSWORD", "pw 123 ключ")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let bytes = fs::read(&archive).unwrap();
    assert!(
        !bytes.windows(10).any(|w| w == b"classified"),
        "plaintext in the archive"
    );

    // no password and a wrong password: refused with a clear message
    let out = cli()
        .arg("list")
        .arg(&archive)
        .env_remove("PACKRAT_PASSWORD")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("password is required"));
    let out = cli()
        .arg("test")
        .arg(&archive)
        .env("PACKRAT_PASSWORD", "nope")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong password"));

    // damage it, repair it with no password at all, then extract with the password
    let mut damaged = bytes.clone();
    damaged[300] ^= 0xff;
    damaged[bytes.len() / 3] ^= 0xff;
    fs::write(&archive, &damaged).unwrap();
    let out = cli()
        .arg("repair")
        .arg(&archive)
        .env_remove("PACKRAT_PASSWORD")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let fixed = dir.path().join("vault.repaired.prat");
    assert!(
        fs::read(&fixed).unwrap() == bytes,
        "the repaired archive differs from the original"
    );
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let out = cli()
        .arg("extract")
        .arg(&fixed)
        .arg("-o")
        .arg(&dest)
        .env("PACKRAT_PASSWORD", "pw 123 ключ")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        fs::read_to_string(dest.join("vault/a.txt")).unwrap(),
        "classified ".repeat(2000)
    );
}

#[test]
fn masks_listfiles_stdout_hash_and_delete_source() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(src.join("node_modules/x")).unwrap();
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.rs"), "A").unwrap();
    fs::write(src.join("sub/b.rs"), "B").unwrap();
    fs::write(src.join("c.log"), "L").unwrap();
    fs::write(src.join("node_modules/x/i.js"), "N").unwrap();
    let list = dir.path().join("paths.txt");
    fs::write(&list, format!("{}\n", src.display())).unwrap();

    // 7-Zip spellings and a list file
    let zip = dir.path().join("o.zip");
    let out = cli()
        .arg("create")
        .arg(&zip)
        .arg(format!("@{}", list.display()))
        .args(["-x!node_modules", "-x", "*.log"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let listing = String::from_utf8_lossy(&cli().arg("list").arg(&zip).output().unwrap().stdout).into_owned();
    assert!(
        listing.contains("src/a.rs") && listing.contains("src/sub/b.rs"),
        "{listing}"
    );
    assert!(
        !listing.contains("c.log") && !listing.contains("node_modules"),
        "{listing}"
    );

    // names with wildcards select, --stdout streams the contents
    let out = cli()
        .arg("extract")
        .arg(&zip)
        .arg("src/sub/*.rs")
        .arg("-so")
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"B");

    // only the include mask, no recursion
    let flat = dir.path().join("flat.zip");
    assert!(
        cli()
            .arg("create")
            .arg(&flat)
            .arg(&src)
            .args(["-i", "*.rs", "-r-"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let listing = String::from_utf8_lossy(&cli().arg("list").arg(&flat).output().unwrap().stdout).into_owned();
    assert!(listing.contains("src/a.rs") && !listing.contains("b.rs"), "{listing}");

    // standard input becomes a file
    let tgz = dir.path().join("s.tar.gz");
    let mut child = cli()
        .arg("create")
        .arg(&tgz)
        .args(["--stdin", "note.txt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"from stdin").unwrap();
    assert!(child.wait().unwrap().success());
    let out = cli()
        .arg("extract")
        .arg(&tgz)
        .arg("note.txt")
        .arg("-so")
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"from stdin");

    // hash
    let out = cli()
        .arg("hash")
        .arg(src.join("a.rs"))
        .args(["--algo", "crc32"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("d3d99e8b"),
        "{:?}",
        out
    );

    // --delete-source removes what was added and the folders left empty
    let gone = dir.path().join("gone.7z");
    let out = cli().arg("create").arg(&gone).arg(&src).arg("-sdel").output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!src.exists());
    assert!(gone.exists());
}
