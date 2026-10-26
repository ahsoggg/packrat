use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::extract::{self, ExtractOptions};
use packrat_core::open::{open, open_with};
use packrat_core::prat::PratArchive;
use packrat_core::prat::recover;
use packrat_core::source::{CountingSource, FileSource};
use packrat_core::{Archive, Error, OpenOptions, Password, Progress};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PASSWORD: &str = "pa$$wörd-пароль-密码";
const MARKER: &[u8] = b"UNIQUE-MARKER-0123456789abcdef";

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

fn tree(root: &Path) -> PathBuf {
    let src = root.join("data");
    fs::create_dir_all(src.join("confidential-folder")).unwrap();
    let mut a = MARKER.to_vec();
    a.extend(noise(600_000, 1));
    fs::write(src.join("confidential-folder/secret-report-2026.bin"), a).unwrap();
    fs::write(src.join("notes.txt"), "plain words repeated\n".repeat(10_000)).unwrap();
    fs::write(src.join("empty.dat"), b"").unwrap();
    fs::write(src.join("tiny.txt"), "x").unwrap();
    for i in 0..4 {
        fs::write(src.join(format!("f{i}.bin")), noise(300_000, 10 + i)).unwrap();
    }
    src
}

fn make(dir: &Path, name: &str, src: &Path, password: Option<&str>, tweak: impl FnOnce(&mut CreateOptions)) -> PathBuf {
    let out = dir.join(name);
    let mut o = CreateOptions::new(Format::Prat);
    o.password = password.map(Password::new);
    o.kdf_mib = Some(1); // the tests are about the construction, not about the cost of guessing
    o.solid_bytes = Some(1 << 20);
    tweak(&mut o);
    create_archive(&out, std::slice::from_ref(&src.to_path_buf()), &o, &Progress::new()).unwrap();
    out
}

fn with_pw(p: &str) -> OpenOptions {
    OpenOptions::default().with_password(p)
}

fn read(a: &dyn Archive, name: &str) -> Result<Vec<u8>, Error> {
    let e = a
        .entries()
        .iter()
        .find(|e| e.path == name)
        .unwrap_or_else(|| panic!("{name} missing"));
    let mut v = Vec::new();
    a.open_entry(e.index)?.read_to_end(&mut v).map_err(Error::from)?;
    Ok(v)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn an_encrypted_archive_roundtrips_with_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {});
    let a = open_with(&out, &with_pw(PASSWORD)).unwrap();
    for e in a.entries().iter().filter(|e| e.is_file()) {
        let rel = e.path.strip_prefix("data/").unwrap();
        assert!(
            read(&*a, &e.path).unwrap() == fs::read(src.join(rel)).unwrap(),
            "{}",
            e.path
        );
        assert!(e.encrypted, "{} should be flagged encrypted", e.path);
    }
    assert!(
        a.entries()
            .iter()
            .any(|e| e.is_dir() && e.path == "data/confidential-folder")
    );
    assert!(a.entries().iter().all(|e| e.method == "PRAT+AEAD"));
}

#[test]
fn the_password_is_required_and_checked() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {});
    assert!(matches!(open(&out).err(), Some(Error::PasswordRequired)));
    for wrong in ["", "wrong", &PASSWORD.to_uppercase(), &format!("{PASSWORD} ")] {
        assert!(
            matches!(open_with(&out, &with_pw(wrong)).err(), Some(Error::WrongPassword)),
            "{wrong:?}"
        );
    }
    // an empty password cannot be used to create one
    let mut o = CreateOptions::new(Format::Prat);
    o.password = Some(Password::new(""));
    let p = dir.path().join("empty-pw.prat");
    assert!(create_archive(&p, &[src], &o, &Progress::new()).is_err());
    assert!(!p.exists());
}

#[test]
fn neither_content_nor_names_are_in_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let plain = fs::read(make(dir.path(), "p.prat", &src, None, |_| {})).unwrap();
    let enc = fs::read(make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {})).unwrap();
    assert!(
        contains(&plain, MARKER),
        "the check is meaningless if the marker is not visible without encryption"
    );
    assert!(
        !contains(&enc, MARKER),
        "file content is visible in the encrypted archive"
    );
    for name in ["secret-report-2026", "confidential-folder", "notes.txt", "data/"] {
        assert!(
            !contains(&enc, name.as_bytes()),
            "'{name}' is visible in the encrypted archive"
        );
    }
    // a plaintext hash of the data must not be recoverable either: no 32 bytes of it appear
    let hash = blake3::hash(&fs::read(src.join("f0.bin")).unwrap());
    assert!(!contains(&enc, hash.as_bytes()));
}

#[test]
fn two_archives_of_the_same_input_share_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let a = fs::read(make(dir.path(), "a.prat", &src, Some(PASSWORD), |_| {})).unwrap();
    let b = fs::read(make(dir.path(), "b.prat", &src, Some(PASSWORD), |_| {})).unwrap();
    assert_eq!(a.len(), b.len());
    // salt and nonce prefix differ, so even the first sealed block differs
    let first_block = 16 + 80;
    assert!(a[first_block + 52..first_block + 252] != b[first_block + 52..first_block + 252]);
}

#[test]
fn a_changed_byte_never_yields_wrong_data() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {});
    let good = fs::read(&out).unwrap();
    let originals: Vec<(String, Vec<u8>)> = {
        let a = open_with(&out, &with_pw(PASSWORD)).unwrap();
        a.entries()
            .iter()
            .filter(|e| e.is_file())
            .map(|e| (e.path.clone(), read(&*a, &e.path).unwrap()))
            .collect()
    };
    let mut x = 99u32;
    let probe = dir.path().join("probe.prat");
    for round in 0..60 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // the whole file, with the encryption header, the blocks, the index and the footer all in reach
        let at = if round < 40 {
            (x >> 8) as usize % 96
        } else {
            (x >> 8) as usize % good.len()
        };
        let mut b = good.clone();
        b[at] ^= 1 << (x & 7);
        fs::write(&probe, &b).unwrap();
        let Ok(a) = open_with(&probe, &with_pw(PASSWORD)) else {
            continue;
        };
        for (name, want) in &originals {
            if let Ok(got) = read(&*a, name) {
                assert!(
                    got == *want,
                    "{name}: a flipped byte at {at} produced wrong data without an error"
                );
            }
        }
    }
}

#[test]
fn damage_inside_a_sealed_block_is_an_authentication_error() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {});
    let mut b = fs::read(&out).unwrap();
    b[16 + 80 + 52 + 1000] ^= 0xff; // inside the first block's ciphertext
    fs::write(&out, &b).unwrap();
    let a = open_with(&out, &with_pw(PASSWORD)).unwrap();
    let mut errors = 0;
    for e in a.entries().iter().filter(|e| e.is_file()) {
        // a failed read inside the reader comes out as an I/O error that carries the message
        let message = match read(&*a, &e.path) {
            Err(Error::Corrupt(m)) => m,
            Err(Error::Io(io)) => io.to_string(),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => continue,
        };
        assert!(message.contains("authentication"), "{message}");
        errors += 1;
    }
    assert!(errors >= 1);
}

#[test]
fn deduplication_and_random_access_still_work_when_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let copies = dir.path().join("copies");
    fs::create_dir_all(&copies).unwrap();
    let data = noise(2_000_000, 5);
    for i in 0..6 {
        fs::write(copies.join(format!("c{i}.bin")), &data).unwrap();
    }
    let six = fs::metadata(make(dir.path(), "six.prat", &copies, Some(PASSWORD), |_| {}))
        .unwrap()
        .len();
    assert!(six < 2_000_000 + 600_000, "six copies took {six} bytes");

    let many = dir.path().join("many");
    fs::create_dir_all(&many).unwrap();
    for i in 0..24 {
        fs::write(many.join(format!("f{i:02}.bin")), noise(500_000, 100 + i)).unwrap();
    }
    let out = make(dir.path(), "many.prat", &many, Some(PASSWORD), |_| {});
    let counting = Arc::new(CountingSource::new(FileSource::open(&out).unwrap()));
    let a = PratArchive::from_source_with(counting.clone(), &with_pw(PASSWORD)).unwrap();
    counting.reset();
    assert!(read(&a, "many/f13.bin").unwrap() == fs::read(many.join("f13.bin")).unwrap());
    let total = fs::metadata(&out).unwrap().len();
    assert!(
        counting.bytes_read() < total / 3,
        "read {} of {total}",
        counting.bytes_read()
    );
}

#[test]
fn extraction_on_many_threads_works_with_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {});
    for threads in [1, 6] {
        let dest = dir.path().join(format!("out{threads}"));
        let a = open_with(&out, &with_pw(PASSWORD)).unwrap();
        let mut opts = ExtractOptions::new(&dest, "e.prat");
        opts.threads = threads;
        let report = extract::extract(&*a, &opts, &Progress::new()).unwrap();
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert!(
            fs::read(dest.join("data/confidential-folder/secret-report-2026.bin")).unwrap()
                == fs::read(src.join("confidential-folder/secret-report-2026.bin")).unwrap()
        );
    }
}

#[test]
fn recovery_works_on_encrypted_archives_and_needs_no_password() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |o| o.recovery_percent = 10);
    let original = fs::read(&out).unwrap();
    let plan = recover::recovery_info(&out).unwrap();
    let mut b = original.clone();
    for f in [0.2, 0.5, 0.8] {
        b[(plan.protected as f64 * f) as usize] ^= 0xff;
    }
    fs::write(&out, &b).unwrap();
    let fixed = dir.path().join("fixed.prat");
    let report = recover::repair(&out, &fixed).unwrap(); // no password anywhere
    assert!(report.repaired >= 1);
    assert!(fs::read(&fixed).unwrap() == original);
    let a = open_with(&fixed, &with_pw(PASSWORD)).unwrap();
    assert!(read(&*a, "data/notes.txt").unwrap() == fs::read(src.join("notes.txt")).unwrap());
}

#[test]
fn hostile_key_derivation_settings_are_refused_quickly() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {});
    let mut b = fs::read(&out).unwrap();
    // the encryption header follows the 16-byte file header: memory at +12, with a valid CRC at the end
    b[16 + 12..16 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    let crc = crc32fast::hash(&b[16..16 + 76]);
    b[16 + 76..16 + 80].copy_from_slice(&crc.to_le_bytes());
    let p = dir.path().join("hostile.prat");
    fs::write(&p, &b).unwrap();
    let start = std::time::Instant::now();
    let err = open_with(&p, &with_pw(PASSWORD)).err().expect("must be refused");
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert!(start.elapsed().as_secs() < 3, "refusing took {:?}", start.elapsed());
}

#[test]
fn the_version_tells_old_readers_to_stay_away_and_plain_archives_stay_readable_by_all() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let enc = fs::read(make(dir.path(), "e.prat", &src, Some(PASSWORD), |_| {})).unwrap();
    let plain = fs::read(make(dir.path(), "p.prat", &src, None, |_| {})).unwrap();
    assert_eq!(u16::from_le_bytes([enc[8], enc[9]]), 2);
    assert_eq!(u16::from_le_bytes([plain[8], plain[9]]), 1);
}
