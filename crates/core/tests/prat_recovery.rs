use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::extract::{self, ExtractOptions};
use packrat_core::open::open;
use packrat_core::prat::recover::{self, Plan};
use packrat_core::{Error, Progress};
use std::fs;
use std::path::{Path, PathBuf};

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
    fs::create_dir_all(src.join("sub")).unwrap();
    for i in 0..10 {
        fs::write(src.join(format!("f{i}.bin")), noise(700_000, 40 + i)).unwrap();
    }
    fs::write(src.join("sub/text.txt"), "recoverable text\n".repeat(30_000)).unwrap();
    src
}

fn make(dir: &Path, name: &str, src: &Path, percent: u32) -> PathBuf {
    let out = dir.join(name);
    let mut o = CreateOptions::new(Format::Prat);
    o.solid_bytes = Some(1 << 20);
    o.recovery_percent = percent;
    create_archive(&out, std::slice::from_ref(&src.to_path_buf()), &o, &Progress::new()).unwrap();
    out
}

fn same_tree(archive: &Path, src: &Path, dest: &Path) {
    let a = open(archive).unwrap();
    let report = extract::extract(&*a, &ExtractOptions::new(dest, "x.prat"), &Progress::new()).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    for e in fs::read_dir(src).unwrap().flatten() {
        if e.path().is_file() {
            let name = e.file_name();
            assert_eq!(
                fs::read(dest.join("data").join(&name)).unwrap(),
                fs::read(e.path()).unwrap(),
                "{name:?}"
            );
        }
    }
    assert_eq!(
        fs::read(dest.join("data/sub/text.txt")).unwrap(),
        fs::read(src.join("sub/text.txt")).unwrap()
    );
}

fn flip(path: &Path, offsets: &[u64]) {
    let mut b = fs::read(path).unwrap();
    for &o in offsets {
        b[o as usize] ^= 0x5a;
    }
    fs::write(path, b).unwrap();
}

fn smash(path: &Path, from: u64, len: u64) {
    let mut b = fs::read(path).unwrap();
    for x in &mut b[from as usize..(from + len) as usize] {
        *x = 0xee;
    }
    fs::write(path, b).unwrap();
}

#[test]
fn an_archive_with_recovery_opens_and_extracts_as_usual() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.prat", &src, 10);
    let plan = recover::recovery_info(&out).expect("recovery data is present");
    assert!(plan.parity_shards >= 1);
    same_tree(&out, &src, &dir.path().join("x"));
    let plain = make(dir.path(), "plain.prat", &src, 0);
    assert!(recover::recovery_info(&plain).is_none());
    let (with, without) = (fs::metadata(&out).unwrap().len(), fs::metadata(&plain).unwrap().len());
    assert!(with > without && with < without + without / 5, "{with} vs {without}");
}

#[test]
fn scattered_damage_is_repaired_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.prat", &src, 10);
    let original = fs::read(&out).unwrap();
    let plan: Plan = recover::recovery_info(&out).unwrap();
    let spots: Vec<u64> = [0.07, 0.31, 0.52, 0.8]
        .iter()
        .map(|f| (plan.protected as f64 * f) as u64)
        .collect();
    flip(&out, &spots);
    assert_ne!(fs::read(&out).unwrap(), original);
    let before = fs::read(&out).unwrap();

    let fixed = dir.path().join("fixed.prat");
    let report = recover::repair(&out, &fixed).unwrap();
    assert!(report.repaired >= 1 && report.repaired <= 4, "{report:?}");
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired file must equal the original"
    );
    assert!(
        fs::read(&out).unwrap() == before,
        "the damaged file must not be changed"
    );
    same_tree(&fixed, &src, &dir.path().join("x"));
}

#[test]
fn a_damaged_footer_is_rewritten_and_damaged_headers_are_survived() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.prat", &src, 8);
    let original = fs::read(&out).unwrap();
    let len = original.len() as u64;
    let plan = recover::recovery_info(&out).unwrap();

    // footer
    flip(&out, &[len - 10, len - 40]);
    let fixed = dir.path().join("f1.prat");
    let r = recover::repair(&out, &fixed).unwrap();
    assert!(r.footer_rewritten);
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired file differs from the original"
    );

    // footer and the first recovery header at once: the copy in front of the footer is used
    fs::write(&out, &original).unwrap();
    flip(&out, &[len - 10, plan.protected + 20]);
    let fixed = dir.path().join("f2.prat");
    recover::repair(&out, &fixed).unwrap();
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired file differs from the original"
    );

    // footer and the second header: found by scanning for the first one
    fs::write(&out, &original).unwrap();
    flip(&out, &[len - 10, len - 68 - 50]);
    let fixed = dir.path().join("f3.prat");
    recover::repair(&out, &fixed).unwrap();
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired file differs from the original"
    );
}

#[test]
fn damaged_repair_data_is_tolerated_up_to_what_is_left() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.prat", &src, 20);
    let original = fs::read(&out).unwrap();
    let plan = recover::recovery_info(&out).unwrap();
    let table_len = 4 * (u64::from(plan.data_shards) + u64::from(plan.parity_shards)) + 4;
    let parity_at = plan.protected + 104 + 2 * table_len;
    // one checksum table is damaged, the first parity shard is damaged, and two data areas are damaged
    flip(
        &out,
        &[
            plan.protected + 104 + 3,
            parity_at + 7,
            (plan.protected as f64 * 0.2) as u64,
            (plan.protected as f64 * 0.6) as u64,
        ],
    );
    let fixed = dir.path().join("fixed.prat");
    recover::repair(&out, &fixed).unwrap();
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired file differs from the original"
    );
}

#[test]
fn damage_beyond_the_recovery_amount_is_reported_and_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.prat", &src, 3);
    let plan = recover::recovery_info(&out).unwrap();
    // wipe far more than 3 percent
    smash(&out, 100_000, plan.protected / 4);
    let before = fs::read(&out).unwrap();
    let fixed = dir.path().join("fixed.prat");
    let err = recover::repair(&out, &fixed).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert!(err.to_string().contains("cannot be repaired"), "{err}");
    assert!(!fixed.exists(), "a failed repair must not leave a file");
    assert!(fs::read(&out).unwrap() == before);
}

#[test]
fn an_undamaged_archive_is_reported_as_such() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.prat", &src, 5);
    let fixed = dir.path().join("same.prat");
    let r = recover::repair(&out, &fixed).unwrap();
    assert_eq!((r.repaired, r.footer_rewritten), (0, false));
    assert!(fs::read(&fixed).unwrap() == fs::read(&out).unwrap());
}

#[test]
fn archives_without_recovery_data_say_so() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "plain.prat", &src, 0);
    let err = recover::repair(&out, &dir.path().join("x.prat")).unwrap_err();
    assert!(err.to_string().contains("no usable recovery data"), "{err}");
}

#[test]
fn tiny_archives_get_meaningful_protection() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("tiny");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), "hello recovery").unwrap();
    fs::write(src.join("b.bin"), noise(30_000, 3)).unwrap();
    let out = dir.path().join("tiny.prat");
    let mut o = CreateOptions::new(Format::Prat);
    o.recovery_percent = 10;
    create_archive(&out, &[src], &o, &Progress::new()).unwrap();
    let original = fs::read(&out).unwrap();
    flip(&out, &[20, 100]); // two bytes of one area: a 10% budget on a tiny archive is one area
    let fixed = dir.path().join("t.prat");
    recover::repair(&out, &fixed).unwrap();
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired file differs from the original"
    );
}

#[test]
fn recovery_is_refused_for_formats_that_cannot_hold_it() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let mut o = CreateOptions::new(Format::SevenZ);
    o.recovery_percent = 5;
    let out = dir.path().join("x.7z");
    let err = create_archive(&out, &[src], &o, &Progress::new()).unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
    assert!(!out.exists());
}

#[test]
fn bad_percentages_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let mut o = CreateOptions::new(Format::Prat);
    o.recovery_percent = 101;
    let out = dir.path().join("x.prat");
    assert!(create_archive(&out, &[src], &o, &Progress::new()).is_err());
    assert!(!out.exists());
}
