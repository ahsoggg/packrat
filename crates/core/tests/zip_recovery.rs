use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::extract::{self, ExtractOptions};
use packrat_core::open::open;
use packrat_core::prat::zip_recover;
use packrat_core::zip::ZipMethod;
use packrat_core::{Error, Progress};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    for i in 0..8 {
        fs::write(src.join(format!("f{i}.bin")), noise(400_000, 70 + i)).unwrap();
    }
    fs::write(src.join("sub/text.txt"), "zip recovery text\n".repeat(20_000)).unwrap();
    fs::write(src.join("empty.txt"), b"").unwrap();
    src
}

fn make(dir: &Path, name: &str, src: &Path, method: ZipMethod, percent: u32) -> PathBuf {
    let out = dir.join(name);
    let mut o = CreateOptions::new(Format::Zip(method));
    o.recovery_percent = percent;
    create_archive(&out, std::slice::from_ref(&src.to_path_buf()), &o, &Progress::new()).unwrap();
    out
}

fn extracts_like(archive: &Path, src: &Path, dest: &Path) {
    let a = open(archive).unwrap();
    let report = extract::extract(&*a, &ExtractOptions::new(dest, "x.zip"), &Progress::new()).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    for i in 0..8 {
        assert!(
            fs::read(dest.join(format!("data/f{i}.bin"))).unwrap() == fs::read(src.join(format!("f{i}.bin"))).unwrap(),
            "f{i}.bin"
        );
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

fn seven_zip() -> Option<PathBuf> {
    let p = PathBuf::from(r"C:\Program Files\7-Zip\7z.exe");
    p.exists().then_some(p)
}

#[test]
fn a_zip_with_recovery_data_is_an_ordinary_zip() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    for method in [ZipMethod::Deflate, ZipMethod::Zstd, ZipMethod::Store] {
        let out = make(dir.path(), &format!("r-{method:?}.zip"), &src, method, 8);
        let plan = zip_recover::recovery_info(&out).expect("recovery data present");
        assert!(plan.parity_shards >= 1);
        extracts_like(&out, &src, &dir.path().join(format!("x-{method:?}")));
        // 7-Zip cannot read the zstd method, so it checks the others
        if method != ZipMethod::Zstd
            && let Some(z) = seven_zip()
        {
            let o = Command::new(&z).args(["t", out.to_str().unwrap()]).output().unwrap();
            let text = String::from_utf8_lossy(&o.stdout);
            assert!(o.status.success() && text.contains("Everything is Ok"), "7-Zip: {text}");
            assert!(!text.to_lowercase().contains("warning"), "7-Zip warns: {text}");
        }
    }
    let plain = make(dir.path(), "plain.zip", &src, ZipMethod::Deflate, 0);
    let with = fs::metadata(dir.path().join("r-Deflate.zip")).unwrap().len();
    let without = fs::metadata(&plain).unwrap().len();
    assert!(with > without && with < without + without / 5, "{with} vs {without}");
    assert!(zip_recover::recovery_info(&plain).is_none());
}

#[test]
fn damaged_file_data_is_repaired_to_the_exact_original() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.zip", &src, ZipMethod::Deflate, 10);
    let original = fs::read(&out).unwrap();
    let plan = zip_recover::recovery_info(&out).unwrap();
    let spots: Vec<u64> = [0.05, 0.4, 0.77]
        .iter()
        .map(|f| (plan.protected as f64 * f) as u64)
        .collect();
    flip(&out, &spots);
    let before = fs::read(&out).unwrap();
    let fixed = dir.path().join("fixed.zip");
    let report = zip_recover::repair(&out, &fixed).unwrap();
    assert!(report.repaired >= 1 && report.repaired <= 3, "{report:?}");
    assert!(
        fs::read(&fixed).unwrap() == original,
        "the repaired ZIP differs from the original"
    );
    assert!(fs::read(&out).unwrap() == before, "the damaged file was changed");
    extracts_like(&fixed, &src, &dir.path().join("x"));
}

/// Where the pieces of the recovery section are, read from header A (the layout is documented in `zip_recover`).
struct Layout {
    start: u64,
    tail_len: u64,
    header_b: u64,
}

fn layout(file: &[u8], start: u64) -> Layout {
    let at = start as usize;
    let tail_len = u64::from_le_bytes(file[at + 32..at + 40].try_into().unwrap());
    Layout {
        start,
        tail_len,
        header_b: file.len() as u64 - tail_len - 80,
    }
}

#[test]
fn a_damaged_central_directory_is_rebuilt_from_its_copy() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.zip", &src, ZipMethod::Deflate, 8);
    let original = fs::read(&out).unwrap();
    let len = original.len() as u64;
    let plan = zip_recover::recovery_info(&out).unwrap();
    let l = layout(&original, plan.protected);
    let live_tail = len - l.tail_len;

    for (label, offsets) in [
        ("end record", vec![len - 6, len - 12]),
        ("directory body", vec![live_tail + 10, live_tail + 40]),
        (
            "whole tail start",
            vec![live_tail, live_tail + 1, live_tail + 2, live_tail + 3],
        ),
    ] {
        let fixed = dir.path().join(format!("{}.zip", label.replace(' ', "_")));
        fs::write(&out, &original).unwrap();
        flip(&out, &offsets);
        let report = zip_recover::repair(&out, &fixed).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(
            fs::read(&fixed).unwrap() == original,
            "{label}: the repaired ZIP differs from the original"
        );
        assert!(report.footer_rewritten, "{label}: {report:?}");
    }
}

#[test]
fn one_damaged_header_copy_is_survived_even_with_the_end_record_gone() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.zip", &src, ZipMethod::Deflate, 8);
    let original = fs::read(&out).unwrap();
    let len = original.len() as u64;
    let plan = zip_recover::recovery_info(&out).unwrap();
    let l = layout(&original, plan.protected);
    // the end record is damaged, so the section has to be found without it: by scanning
    for (label, header) in [("header A", l.start + 20), ("header B", l.header_b + 20)] {
        let fixed = dir.path().join(format!("{}.zip", label.replace(' ', "_")));
        fs::write(&out, &original).unwrap();
        flip(&out, &[header, len - 6]);
        zip_recover::repair(&out, &fixed).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(
            fs::read(&fixed).unwrap() == original,
            "{label}: the repaired ZIP differs from the original"
        );
    }
}

#[test]
fn damaged_repair_data_is_regenerated() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.zip", &src, ZipMethod::Deflate, 20);
    let original = fs::read(&out).unwrap();
    let plan = zip_recover::recovery_info(&out).unwrap();
    let l = layout(&original, plan.protected);
    let table_len = 4 * (u64::from(plan.data_shards) + u64::from(plan.parity_shards)) + 4;
    let tables_at = l.start + 80 + l.tail_len;
    let parity_at = tables_at + 2 * table_len;
    // a checksum table, a parity shard, the tail copy, and two damaged data areas
    flip(
        &out,
        &[
            tables_at + 3,
            parity_at + 9,
            l.start + 80 + 5,
            (plan.protected as f64 * 0.2) as u64,
            (plan.protected as f64 * 0.55) as u64,
        ],
    );
    let fixed = dir.path().join("fixed.zip");
    let report = zip_recover::repair(&out, &fixed).unwrap();
    assert!(report.recovery_rewritten && report.repaired >= 1, "{report:?}");
    assert!(fs::read(&fixed).unwrap() == original);
}

#[test]
fn too_much_damage_and_missing_recovery_data_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.zip", &src, ZipMethod::Deflate, 3);
    let plan = zip_recover::recovery_info(&out).unwrap();
    let mut b = fs::read(&out).unwrap();
    for x in &mut b[1000..1000 + (plan.protected / 4) as usize] {
        *x = 0xee;
    }
    fs::write(&out, &b).unwrap();
    let fixed = dir.path().join("fixed.zip");
    let err = zip_recover::repair(&out, &fixed).unwrap_err();
    assert!(err.to_string().contains("cannot be repaired"), "{err}");
    assert!(!fixed.exists());

    let plain = make(dir.path(), "plain.zip", &src, ZipMethod::Deflate, 0);
    let err = zip_recover::repair(&plain, &dir.path().join("p.zip")).unwrap_err();
    assert!(err.to_string().contains("no usable recovery data"), "{err}");
}

#[test]
fn an_undamaged_zip_is_reported_as_such_and_adding_twice_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let src = tree(dir.path());
    let out = make(dir.path(), "r.zip", &src, ZipMethod::Deflate, 5);
    let same = dir.path().join("same.zip");
    let r = zip_recover::repair(&out, &same).unwrap();
    assert_eq!(
        (r.repaired, r.footer_rewritten, r.recovery_rewritten),
        (0, false, false)
    );
    assert!(fs::read(&same).unwrap() == fs::read(&out).unwrap());
    let err = zip_recover::add_recovery(&out, 5).unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
}
