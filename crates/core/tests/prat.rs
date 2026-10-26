use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat_core::extract::{self, ExtractOptions};
use packrat_core::open::open;
use packrat_core::prat::PratArchive;
use packrat_core::source::{CountingSource, FileSource};
use packrat_core::{Archive, Error, Kind, Progress};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

fn make(dir: &Path, name: &str, src: &Path, tweak: impl FnOnce(&mut CreateOptions)) -> PathBuf {
    let out = dir.join(name);
    let mut opts = CreateOptions::new(Format::Prat);
    tweak(&mut opts);
    create_archive(&out, std::slice::from_ref(&src.to_path_buf()), &opts, &Progress::new()).unwrap();
    out
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

fn sample(root: &Path) -> PathBuf {
    let src = root.join("data");
    fs::create_dir_all(src.join("sub/deeper")).unwrap();
    fs::write(src.join("notes.txt"), "line of text\n".repeat(20_000)).unwrap();
    fs::write(src.join("tiny.txt"), "x").unwrap();
    fs::write(src.join("empty.bin"), b"").unwrap();
    fs::write(src.join("sub/noise.bin"), noise(3_000_000, 1)).unwrap();
    fs::write(src.join("sub/deeper/small.dat"), noise(5_000, 2)).unwrap();
    fs::write(src.join("sub/deeper/medium.dat"), noise(150_000, 3)).unwrap();
    src
}

fn files_of(src: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    fn walk(base: &Path, dir: &Path, v: &mut Vec<(String, Vec<u8>)>) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, v);
            } else {
                let rel = p.strip_prefix(base.parent().unwrap()).unwrap();
                v.push((rel.to_string_lossy().replace('\\', "/"), fs::read(&p).unwrap()));
            }
        }
    }
    walk(src, src, &mut v);
    v
}

#[test]
fn roundtrip_of_a_mixed_tree() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample(dir.path());
    let out = make(dir.path(), "a.prat", &src, |_| {});
    let a = open(&out).unwrap();
    assert_eq!(a.kind(), Kind::Prat);
    assert!(a.entries().iter().any(|e| e.is_dir() && e.path == "data/sub/deeper"));
    for (name, bytes) in files_of(&src) {
        assert_eq!(read(&*a, &name).unwrap(), bytes, "{name}");
    }
    let e = a.entries().iter().find(|e| e.path == "data/notes.txt").unwrap();
    assert_eq!(e.size, 13 * 20_000);
    assert!(e.mtime.is_some());
}

#[test]
fn identical_files_are_stored_once() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("copies");
    fs::create_dir_all(&src).unwrap();
    let block = noise(2_000_000, 9);
    for i in 0..6 {
        fs::write(src.join(format!("copy{i}.bin")), &block).unwrap();
    }
    let one = {
        let single = dir.path().join("single");
        fs::create_dir_all(&single).unwrap();
        fs::write(single.join("copy0.bin"), &block).unwrap();
        fs::metadata(make(dir.path(), "one.prat", &single, |_| {}))
            .unwrap()
            .len()
    };
    let six = fs::metadata(make(dir.path(), "six.prat", &src, |_| {})).unwrap().len();
    assert!(six < one + one / 10, "six copies took {six} bytes, one copy {one}");
    let a = open(&dir.path().join("six.prat")).unwrap();
    for i in 0..6 {
        assert_eq!(read(&*a, &format!("copies/copy{i}.bin")).unwrap(), block);
    }
}

#[test]
fn shifted_content_is_still_deduplicated() {
    // content-defined chunking: inserting a few bytes at the front must not make the rest "new"
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("shift");
    fs::create_dir_all(&src).unwrap();
    let base = noise(3_000_000, 21);
    let mut shifted = b"a few bytes in front".to_vec();
    shifted.extend_from_slice(&base);
    fs::write(src.join("a.bin"), &base).unwrap();
    fs::write(src.join("b.bin"), &shifted).unwrap();
    let both = fs::metadata(make(dir.path(), "shift.prat", &src, |_| {}))
        .unwrap()
        .len();
    assert!(both < 3_300_000, "the shifted copy was stored again: {both}");
}

#[test]
fn one_file_is_read_without_decoding_the_whole_archive() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("many");
    fs::create_dir_all(&src).unwrap();
    for i in 0..24 {
        fs::write(src.join(format!("f{i:02}.bin")), noise(500_000, 100 + i)).unwrap();
    }
    let out = make(dir.path(), "many.prat", &src, |o| o.solid_bytes = Some(1 << 20));
    let counting = Arc::new(CountingSource::new(FileSource::open(&out).unwrap()));
    let a = PratArchive::from_source(counting.clone()).unwrap();
    assert!(a.block_count() >= 8, "{} blocks", a.block_count());
    counting.reset();
    let want = fs::read(src.join("f13.bin")).unwrap();
    assert_eq!(read(&a, "many/f13.bin").unwrap(), want);
    let total = fs::metadata(&out).unwrap().len();
    assert!(
        counting.bytes_read() < total / 3,
        "read {} of {total} bytes for one file",
        counting.bytes_read()
    );
}

#[test]
fn damage_in_a_block_is_found_and_stays_local() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("dmg");
    fs::create_dir_all(&src).unwrap();
    for i in 0..8 {
        fs::write(src.join(format!("f{i}.bin")), noise(800_000, 200 + i)).unwrap();
    }
    let out = make(dir.path(), "dmg.prat", &src, |o| o.solid_bytes = Some(1 << 20));
    let mut bytes = fs::read(&out).unwrap();
    let at = 20_000; // inside the first block's payload
    bytes[at] ^= 0xff;
    fs::write(&out, &bytes).unwrap();
    let a = open(&out).unwrap(); // the index is intact
    let mut bad = 0;
    let mut good = 0;
    for i in 0..8 {
        match read(&*a, &format!("dmg/f{i}.bin")) {
            Ok(v) => {
                assert_eq!(v, fs::read(src.join(format!("f{i}.bin"))).unwrap());
                good += 1;
            }
            Err(Error::Corrupt(_)) | Err(Error::Io(_)) => bad += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(bad >= 1, "the damaged block was not noticed");
    assert!(good >= 1, "the damage spread to files that are not in that block");
}

#[test]
fn damaged_footer_index_and_truncation_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample(dir.path());
    let out = make(dir.path(), "x.prat", &src, |_| {});
    let good = fs::read(&out).unwrap();

    for cut in [good.len() - 1, good.len() - 68, good.len() / 2, 20, 0] {
        let p = dir.path().join(format!("cut{cut}.prat"));
        fs::write(&p, &good[..cut]).unwrap();
        assert!(open(&p).is_err(), "truncated to {cut} bytes opened");
    }
    // flip bytes across the last 400 bytes (index and footer)
    for back in 1..400 {
        let mut b = good.clone();
        let i = b.len() - back;
        b[i] ^= 0x01;
        let p = dir.path().join("flip.prat");
        fs::write(&p, &b).unwrap();
        assert!(open(&p).is_err(), "a flipped byte {back} from the end went unnoticed");
    }
}

#[test]
fn random_bytes_after_the_magic_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample(dir.path());
    let out = make(dir.path(), "r.prat", &src, |_| {});
    let good = fs::read(&out).unwrap();
    let mut x = 777u32;
    for round in 0..200 {
        let mut b = good.clone();
        for _ in 0..8 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let i = 8 + (x >> 4) as usize % (b.len() - 8);
            b[i] = (x >> 24) as u8;
        }
        let p = dir.path().join(format!("fuzz{}.prat", round % 4));
        fs::write(&p, &b).unwrap();
        if let Ok(a) = open(&p) {
            for e in a.entries() {
                if let Ok(mut r) = a.open_entry(e.index) {
                    let _ = r.read_to_end(&mut Vec::new());
                }
            }
        }
    }
}

#[test]
fn extraction_works_on_many_threads_and_matches_the_source() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("tree");
    for d in 0..6 {
        fs::create_dir_all(src.join(format!("d{d}"))).unwrap();
        for f in 0..40 {
            let n = 1000 + (d * 40 + f) * 700;
            fs::write(src.join(format!("d{d}/f{f}.bin")), noise(n, (d * 100 + f) as u64)).unwrap();
        }
    }
    fs::write(src.join("dup.bin"), noise(100_000, 5)).unwrap();
    fs::write(src.join("d3/dup2.bin"), noise(100_000, 5)).unwrap();
    let out = make(dir.path(), "tree.prat", &src, |o| o.solid_bytes = Some(1 << 20));
    for threads in [1, 8] {
        let dest = dir.path().join(format!("out{threads}"));
        let a = open(&out).unwrap();
        let mut opts = ExtractOptions::new(&dest, "tree.prat");
        opts.threads = threads;
        let report = extract::extract(&*a, &opts, &Progress::new()).unwrap();
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(report.files, 242);
        for (name, bytes) in files_of(&src) {
            assert_eq!(fs::read(dest.join(&name)).unwrap(), bytes, "{name} ({threads} threads)");
        }
    }
}

#[test]
fn passwords_are_refused_until_encryption_exists() {
    let dir = tempfile::tempdir().unwrap();
    let src = sample(dir.path());
    let mut opts = CreateOptions::new(Format::Prat);
    opts.password = Some(packrat_core::Password::new("secret"));
    let out = dir.path().join("p.prat");
    let err = create_archive(&out, &[src], &opts, &Progress::new()).unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
    assert!(!out.exists());
}
