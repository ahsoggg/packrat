//! Drives the plugin through the same calls 7-Zip makes, with stand-ins for 7-Zip's stream and callback objects.
//! No 7-Zip is needed. The stand-ins also do what 7-Zip does that matters here: the extract callback asks the
//! archive object for properties while the extraction is running (a lock held across that call deadlocks).
#![cfg(windows)]

use packrat_core::Progress;
use packrat_core::create::{CreateOptions, Format, create_archive};
use packrat7z::{CreateObject, GetHandlerProperty2, GetNumberOfFormats, Guid, PropVariant};
use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use windows_sys::Win32::Foundation::SysAllocStringLen;

type Hr = i32;
const S_OK: Hr = 0;
const S_FALSE: Hr = 1;
const E_NOINTERFACE: Hr = 0x8000_4002u32 as i32;

const IID_IIN_ARCHIVE: Guid = guid(6, 0x60);
const fn guid(group: u8, id: u8) -> Guid {
    Guid::new(0x2317_0F69, 0x40C1, 0x278A, [0, 0, 0, group, 0, id, 0, 0])
}
const CLSID: Guid = Guid::new(
    0x5052_4154,
    0x5A37,
    0x4C4B,
    [0xA1, 0x2B, 0x50, 0x52, 0x41, 0x54, 0x37, 0x5A],
);

// ---- the plugin's archive object, seen from the outside --------------------------------------------------------

#[repr(C)]
struct Unknown {
    qi: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Hr,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct InArchive {
    base: Unknown,
    open: unsafe extern "system" fn(*mut c_void, *mut c_void, *const u64, *mut c_void) -> Hr,
    close: unsafe extern "system" fn(*mut c_void) -> Hr,
    num_items: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hr,
    get_property: unsafe extern "system" fn(*mut c_void, u32, u32, *mut PropVariant) -> Hr,
    extract: unsafe extern "system" fn(*mut c_void, *const u32, u32, i32, *mut c_void) -> Hr,
    get_archive_property: unsafe extern "system" fn(*mut c_void, u32, *mut PropVariant) -> Hr,
    num_props: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hr,
    prop_info: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16, *mut u32, *mut u16) -> Hr,
    num_archive_props: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hr,
    archive_prop_info: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16, *mut u32, *mut u16) -> Hr,
}

unsafe fn vt<T>(p: *mut c_void) -> &'static T {
    unsafe { &*(*(p as *const *const T)) }
}

// ---- stand-in for 7-Zip's IInStream ----------------------------------------------------------------------------

#[repr(C)]
struct InStreamVtbl {
    base: Unknown,
    read: unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut u32) -> Hr,
    seek: unsafe extern "system" fn(*mut c_void, i64, u32, *mut u64) -> Hr,
}

#[repr(C)]
struct FakeStream {
    vtbl: *const InStreamVtbl,
    refs: AtomicU32,
    data: Vec<u8>,
    pos: Mutex<u64>,
}

unsafe extern "system" fn s_qi(_: *mut c_void, _: *const Guid, out: *mut *mut c_void) -> Hr {
    unsafe { *out = null_mut() };
    E_NOINTERFACE
}
unsafe extern "system" fn s_add_ref(p: *mut c_void) -> u32 {
    unsafe { &*(p as *const FakeStream) }
        .refs
        .fetch_add(1, Ordering::SeqCst)
        + 1
}
unsafe extern "system" fn s_release(p: *mut c_void) -> u32 {
    unsafe { &*(p as *const FakeStream) }
        .refs
        .fetch_sub(1, Ordering::SeqCst)
        - 1
}
unsafe extern "system" fn s_read(p: *mut c_void, buf: *mut c_void, size: u32, done: *mut u32) -> Hr {
    let s = unsafe { &*(p as *const FakeStream) };
    let mut pos = s.pos.lock().unwrap();
    let start = (*pos as usize).min(s.data.len());
    let n = (size as usize).min(s.data.len() - start);
    unsafe { std::ptr::copy_nonoverlapping(s.data.as_ptr().add(start), buf.cast::<u8>(), n) };
    *pos += n as u64;
    if !done.is_null() {
        unsafe { *done = n as u32 };
    }
    S_OK
}
unsafe extern "system" fn s_seek(p: *mut c_void, off: i64, origin: u32, newpos: *mut u64) -> Hr {
    let s = unsafe { &*(p as *const FakeStream) };
    let mut pos = s.pos.lock().unwrap();
    let base = match origin {
        0 => 0i64,
        1 => *pos as i64,
        _ => s.data.len() as i64,
    };
    let to = base + off;
    if to < 0 {
        return 0x8007_0057u32 as i32;
    }
    *pos = to as u64;
    if !newpos.is_null() {
        unsafe { *newpos = to as u64 };
    }
    S_OK
}

static STREAM_VTBL: InStreamVtbl = InStreamVtbl {
    base: Unknown {
        qi: s_qi,
        add_ref: s_add_ref,
        release: s_release,
    },
    read: s_read,
    seek: s_seek,
};

fn fake_stream(data: Vec<u8>) -> Box<FakeStream> {
    Box::new(FakeStream {
        vtbl: &STREAM_VTBL,
        refs: AtomicU32::new(1),
        data,
        pos: Mutex::new(0),
    })
}

// ---- stand-ins for 7-Zip's extract callback and output streams -------------------------------------------------

#[repr(C)]
struct OutVtbl {
    base: Unknown,
    write: unsafe extern "system" fn(*mut c_void, *const c_void, u32, *mut u32) -> Hr,
}

#[repr(C)]
struct FakeOut {
    vtbl: *const OutVtbl,
    refs: AtomicU32,
    index: u32,
    sink: *const Mutex<Vec<(u32, Vec<u8>)>>,
    buf: Mutex<Vec<u8>>,
}

unsafe extern "system" fn o_qi(_: *mut c_void, _: *const Guid, out: *mut *mut c_void) -> Hr {
    unsafe { *out = null_mut() };
    E_NOINTERFACE
}
unsafe extern "system" fn o_add_ref(p: *mut c_void) -> u32 {
    unsafe { &*(p as *const FakeOut) }.refs.fetch_add(1, Ordering::SeqCst) + 1
}
unsafe extern "system" fn o_release(p: *mut c_void) -> u32 {
    let o = unsafe { &*(p as *const FakeOut) };
    let left = o.refs.fetch_sub(1, Ordering::SeqCst) - 1;
    if left == 0 {
        // the file is "closed": hand over what was written, then free the object
        let data = std::mem::take(&mut *o.buf.lock().unwrap());
        unsafe { &*o.sink }.lock().unwrap().push((o.index, data));
        drop(unsafe { Box::from_raw(p as *mut FakeOut) });
    }
    left
}
unsafe extern "system" fn o_write(p: *mut c_void, data: *const c_void, size: u32, done: *mut u32) -> Hr {
    let o = unsafe { &*(p as *const FakeOut) };
    o.buf
        .lock()
        .unwrap()
        .extend_from_slice(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size as usize) });
    if !done.is_null() {
        unsafe { *done = size };
    }
    S_OK
}
static OUT_VTBL: OutVtbl = OutVtbl {
    base: Unknown {
        qi: o_qi,
        add_ref: o_add_ref,
        release: o_release,
    },
    write: o_write,
};

#[repr(C)]
struct CallbackVtbl {
    base: Unknown,
    set_total: unsafe extern "system" fn(*mut c_void, u64) -> Hr,
    set_completed: unsafe extern "system" fn(*mut c_void, *const u64) -> Hr,
    get_stream: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void, i32) -> Hr,
    prepare: unsafe extern "system" fn(*mut c_void, i32) -> Hr,
    set_result: unsafe extern "system" fn(*mut c_void, i32) -> Hr,
}

#[repr(C)]
struct FakeCallback {
    vtbl: *const CallbackVtbl,
    archive: *mut c_void,
    total: Mutex<u64>,
    completed: Mutex<Vec<u64>>,
    asks: Mutex<Vec<i32>>,
    results: Mutex<Vec<i32>>,
    paths: Mutex<Vec<String>>,
    sink: Mutex<Vec<(u32, Vec<u8>)>>,
}

unsafe extern "system" fn c_set_total(p: *mut c_void, t: u64) -> Hr {
    *unsafe { &*(p as *const FakeCallback) }.total.lock().unwrap() = t;
    S_OK
}
unsafe extern "system" fn c_set_completed(p: *mut c_void, done: *const u64) -> Hr {
    unsafe { &*(p as *const FakeCallback) }
        .completed
        .lock()
        .unwrap()
        .push(unsafe { *done });
    S_OK
}
unsafe extern "system" fn c_get_stream(p: *mut c_void, index: u32, out: *mut *mut c_void, ask: i32) -> Hr {
    let c = unsafe { &*(p as *const FakeCallback) };
    c.asks.lock().unwrap().push(ask);
    // what 7-Zip does here: it asks the archive for the item's path, while the extraction is in progress
    let mut v = PropVariant::empty();
    let hr = unsafe { (vt::<InArchive>(c.archive).get_property)(c.archive, index, 3, &mut v) };
    assert_eq!(hr, S_OK);
    c.paths.lock().unwrap().push(unsafe { v.take_string() });
    if ask == 0 {
        let o = Box::new(FakeOut {
            vtbl: &OUT_VTBL,
            refs: AtomicU32::new(1),
            index,
            sink: &c.sink,
            buf: Mutex::new(Vec::new()),
        });
        unsafe { *out = Box::into_raw(o).cast() };
    } else {
        unsafe { *out = null_mut() };
    }
    S_OK
}
unsafe extern "system" fn c_prepare(_: *mut c_void, _: i32) -> Hr {
    S_OK
}
unsafe extern "system" fn c_set_result(p: *mut c_void, r: i32) -> Hr {
    unsafe { &*(p as *const FakeCallback) }.results.lock().unwrap().push(r);
    S_OK
}
static CALLBACK_VTBL: CallbackVtbl = CallbackVtbl {
    base: Unknown {
        qi: o_qi,
        add_ref: o_add_ref,
        release: o_release,
    },
    set_total: c_set_total,
    set_completed: c_set_completed,
    get_stream: c_get_stream,
    prepare: c_prepare,
    set_result: c_set_result,
};

fn callback(archive: *mut c_void) -> Box<FakeCallback> {
    Box::new(FakeCallback {
        vtbl: &CALLBACK_VTBL,
        archive,
        total: Mutex::new(0),
        completed: Mutex::new(Vec::new()),
        asks: Mutex::new(Vec::new()),
        results: Mutex::new(Vec::new()),
        paths: Mutex::new(Vec::new()),
        sink: Mutex::new(Vec::new()),
    })
}

// ---- stand-in for 7-Zip's open callback, which offers the password interface ------------------------------------

const IID_CRYPTO_GET_TEXT_PASSWORD: Guid = guid(5, 0x10);

#[repr(C)]
struct PasswordVtbl {
    base: Unknown,
    get_text_password: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> Hr,
}

enum Answer {
    Password(String),
    Cancel,
}

#[repr(C)]
struct FakeOpenCallback {
    vtbl: *const PasswordVtbl,
    /// `None` models a callback that has no password interface at all.
    answer: Option<Answer>,
    asked: AtomicU32,
    refs: AtomicU32,
}

unsafe extern "system" fn p_qi(p: *mut c_void, iid: *const Guid, out: *mut *mut c_void) -> Hr {
    let me = unsafe { &*(p as *const FakeOpenCallback) };
    if me.answer.is_some() && unsafe { *iid } == IID_CRYPTO_GET_TEXT_PASSWORD {
        me.refs.fetch_add(1, Ordering::SeqCst);
        unsafe { *out = p };
        S_OK
    } else {
        unsafe { *out = null_mut() };
        E_NOINTERFACE
    }
}
unsafe extern "system" fn p_add_ref(p: *mut c_void) -> u32 {
    unsafe { &*(p as *const FakeOpenCallback) }
        .refs
        .fetch_add(1, Ordering::SeqCst)
        + 1
}
unsafe extern "system" fn p_release(p: *mut c_void) -> u32 {
    unsafe { &*(p as *const FakeOpenCallback) }
        .refs
        .fetch_sub(1, Ordering::SeqCst)
        - 1
}
unsafe extern "system" fn p_get(p: *mut c_void, out: *mut *mut u16) -> Hr {
    let me = unsafe { &*(p as *const FakeOpenCallback) };
    me.asked.fetch_add(1, Ordering::SeqCst);
    match &me.answer {
        Some(Answer::Password(pw)) => {
            let wide: Vec<u16> = pw.encode_utf16().collect();
            unsafe { *out = SysAllocStringLen(wide.as_ptr(), wide.len() as u32) as *mut u16 };
            S_OK
        }
        _ => 0x8000_4004u32 as i32, // E_ABORT: the user cancelled the box
    }
}
static PASSWORD_VTBL: PasswordVtbl = PasswordVtbl {
    base: Unknown {
        qi: p_qi,
        add_ref: p_add_ref,
        release: p_release,
    },
    get_text_password: p_get,
};

fn open_callback(answer: Option<Answer>) -> Box<FakeOpenCallback> {
    Box::new(FakeOpenCallback {
        vtbl: &PASSWORD_VTBL,
        answer,
        asked: AtomicU32::new(0),
        refs: AtomicU32::new(1),
    })
}

// ---- helpers ---------------------------------------------------------------------------------------------------

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

fn make_archive(dir: &Path) -> (PathBuf, PathBuf) {
    let src = dir.join("data");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), "alpha beta gamma\n".repeat(5000)).unwrap();
    fs::write(src.join("empty.bin"), b"").unwrap();
    fs::write(src.join("sub/noise.bin"), noise(900_000, 5)).unwrap();
    fs::write(src.join("sub/copy.bin"), noise(900_000, 5)).unwrap(); // a duplicate
    fs::write(src.join("sub/small.dat"), noise(3_000, 6)).unwrap();
    let out = dir.join("t.prat");
    let mut o = CreateOptions::new(Format::Prat);
    o.solid_bytes = Some(1 << 20);
    create_archive(&out, std::slice::from_ref(&src), &o, &Progress::new()).unwrap();
    (src, out)
}

fn make_encrypted(dir: &Path, password: &str) -> PathBuf {
    let (src, _) = make_archive(dir);
    let out = dir.join("enc.prat");
    let mut o = CreateOptions::new(Format::Prat);
    o.solid_bytes = Some(1 << 20);
    o.password = Some(packrat_core::Password::new(password));
    o.kdf_mib = Some(1);
    create_archive(&out, std::slice::from_ref(&src), &o, &Progress::new()).unwrap();
    out
}

struct Opened {
    archive: *mut c_void,
    stream: Box<FakeStream>,
}

fn open_archive(file: Vec<u8>) -> Result<Opened, Hr> {
    open_archive_with(file, null_mut())
}

fn open_archive_with(file: Vec<u8>, open_callback: *mut c_void) -> Result<Opened, Hr> {
    let mut obj: *mut c_void = null_mut();
    assert_eq!(unsafe { CreateObject(&CLSID, &IID_IIN_ARCHIVE, &mut obj) }, S_OK);
    let mut stream = fake_stream(file);
    let sp: *mut c_void = (&mut *stream as *mut FakeStream).cast();
    let hr = unsafe { (vt::<InArchive>(obj).open)(obj, sp, std::ptr::null(), open_callback) };
    if hr != S_OK {
        unsafe { (vt::<InArchive>(obj).base.release)(obj) };
        return Err(hr);
    }
    Ok(Opened { archive: obj, stream })
}

fn items(a: *mut c_void) -> u32 {
    let mut n = 0u32;
    assert_eq!(unsafe { (vt::<InArchive>(a).num_items)(a, &mut n) }, S_OK);
    n
}

fn prop(a: *mut c_void, index: u32, id: u32) -> PropVariant {
    let mut v = PropVariant::empty();
    assert_eq!(unsafe { (vt::<InArchive>(a).get_property)(a, index, id, &mut v) }, S_OK);
    v
}

/// Runs `f` on a thread and fails the test instead of hanging when it does not finish.
fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs))
        .expect("the call did not return (deadlock?)")
}

fn wrap<T>(p: *mut T) -> usize {
    p as usize
}

// ---- tests -----------------------------------------------------------------------------------------------------

#[test]
fn the_handler_describes_itself_the_way_7zip_expects() {
    let mut n = 0u32;
    assert_eq!(unsafe { GetNumberOfFormats(&mut n) }, S_OK);
    assert_eq!(n, 1);
    let get = |id: u32| {
        let mut v = PropVariant::empty();
        assert_eq!(unsafe { GetHandlerProperty2(0, id, &mut v) }, S_OK);
        v
    };
    assert_eq!(unsafe { get(0).take_string() }, "Packrat");
    assert_eq!(unsafe { get(2).take_string() }, "prat");
    assert_eq!(unsafe { get(1).take_bytes() }.len(), 16, "the class id is 16 bytes");
    assert_eq!(unsafe { get(6).take_bytes() }, b"PRAT\r\n\x1a\n");
    assert_eq!(get(8).as_u32(), Some(0));
    assert_eq!(get(4).as_bool(), Some(false), "read-only handler");
    assert!(get(999).is_empty());
    let mut v = PropVariant::empty();
    assert_ne!(
        unsafe { GetHandlerProperty2(1, 0, &mut v) },
        S_OK,
        "there is only one format"
    );
}

#[test]
fn only_our_class_and_the_read_interface_can_be_created() {
    let mut obj: *mut c_void = null_mut();
    let other = Guid::new(1, 2, 3, [4; 8]);
    assert_eq!(
        unsafe { CreateObject(&other, &IID_IIN_ARCHIVE, &mut obj) },
        E_NOINTERFACE
    );
    assert!(obj.is_null());
    let out_archive = guid(6, 0xA0); // IOutArchive
    assert_eq!(unsafe { CreateObject(&CLSID, &out_archive, &mut obj) }, E_NOINTERFACE);
    assert!(obj.is_null());
    assert_ne!(
        unsafe { CreateObject(std::ptr::null(), &IID_IIN_ARCHIVE, &mut obj) },
        S_OK
    );
}

#[test]
fn listing_reports_names_sizes_and_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let (_, arc) = make_archive(dir.path());
    let o = open_archive(fs::read(&arc).unwrap()).unwrap();
    let n = items(o.archive);
    assert!(n >= 7, "{n} items");
    let mut seen = Vec::new();
    for i in 0..n {
        let path = unsafe { prop(o.archive, i, 3).take_string() };
        let is_dir = prop(o.archive, i, 6).as_bool().unwrap();
        let size = prop(o.archive, i, 7).as_u64();
        assert_eq!(size.is_some(), !is_dir, "{path}");
        seen.push((path, is_dir, size));
    }
    let find = |p: &str| {
        seen.iter()
            .find(|(n, ..)| n == p)
            .unwrap_or_else(|| panic!("{p} missing: {seen:?}"))
    };
    assert_eq!(find("data\\a.txt").2, Some(17 * 5000));
    assert_eq!(find("data\\sub\\noise.bin").2, Some(900_000));
    assert!(find("data\\sub").1);
    assert_eq!(find("data\\empty.bin").2, Some(0));
    // out-of-range and unknown properties
    let mut v = PropVariant::empty();
    assert_ne!(
        unsafe { (vt::<InArchive>(o.archive).get_property)(o.archive, n, 3, &mut v) },
        S_OK
    );
    assert!(prop(o.archive, 0, 4242).is_empty());
    // the archive's own size
    let mut v = PropVariant::empty();
    assert_eq!(
        unsafe { (vt::<InArchive>(o.archive).get_archive_property)(o.archive, 44, &mut v) },
        S_OK
    );
    assert_eq!(v.as_u64(), Some(fs::metadata(&arc).unwrap().len()));
    unsafe { (vt::<InArchive>(o.archive).base.release)(o.archive) };
}

#[test]
fn extraction_delivers_every_file_unchanged_and_survives_the_callback_asking_for_properties() {
    let dir = tempfile::tempdir().unwrap();
    let (src, arc) = make_archive(dir.path());
    let file = fs::read(&arc).unwrap();
    let (archive, cb_ptr, results, sink, completed, total) = within(60, move || {
        let o = open_archive(file).unwrap();
        let archive = o.archive;
        let mut cb = callback(archive);
        let cp: *mut c_void = (&mut *cb as *mut FakeCallback).cast();
        let hr = unsafe { (vt::<InArchive>(archive).extract)(archive, std::ptr::null(), u32::MAX, 0, cp) };
        assert_eq!(hr, S_OK);
        let r = cb.results.lock().unwrap().clone();
        let s = std::mem::take(&mut *cb.sink.lock().unwrap());
        let c = cb.completed.lock().unwrap().clone();
        let t = *cb.total.lock().unwrap();
        let paths = cb.paths.lock().unwrap().clone();
        assert_eq!(paths.len(), items(archive) as usize, "every item was asked for");
        unsafe { (vt::<InArchive>(archive).base.release)(archive) };
        let _keep = o.stream;
        (wrap(archive), wrap(cp), r, s, c, t)
    });
    let _ = (archive, cb_ptr);
    assert!(results.iter().all(|&r| r == 0), "{results:?}");
    let want: u64 = [17 * 5000u64, 0, 900_000, 900_000, 3_000].iter().sum();
    assert_eq!(total, want);
    assert!(completed.windows(2).all(|w| w[0] <= w[1]), "progress goes backwards");
    assert_eq!(*completed.last().unwrap(), want);
    // every file that 7-Zip received equals the original; the written index maps to the entry order
    let mut got = std::collections::HashMap::new();
    for (idx, data) in sink {
        got.insert(idx, data);
    }
    let a = packrat_core::open::open(&arc).unwrap();
    let mut checked = 0;
    for e in a.entries().iter().filter(|e| e.is_file()) {
        let rel = e.path.strip_prefix("data/").unwrap();
        assert!(
            got[&(e.index as u32)] == fs::read(src.join(rel)).unwrap(),
            "{} differs",
            e.path
        );
        checked += 1;
    }
    assert_eq!(checked, 5);
}

#[test]
fn testing_reads_and_verifies_but_writes_nothing_and_a_subset_can_be_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let (_, arc) = make_archive(dir.path());
    let file = fs::read(&arc).unwrap();
    within(60, move || {
        let o = open_archive(file).unwrap();
        let a = o.archive;
        // test mode: ask kind 1, the callback returns no stream, all results are OK
        let mut cb = callback(a);
        let cp: *mut c_void = (&mut *cb as *mut FakeCallback).cast();
        assert_eq!(
            unsafe { (vt::<InArchive>(a).extract)(a, std::ptr::null(), u32::MAX, 1, cp) },
            S_OK
        );
        assert!(cb.asks.lock().unwrap().iter().all(|&k| k == 1));
        assert!(cb.results.lock().unwrap().iter().all(|&r| r == 0));
        assert!(cb.sink.lock().unwrap().is_empty());
        assert!(
            *cb.completed.lock().unwrap().last().unwrap() > 0,
            "test mode still reads the data"
        );
        // two chosen items
        let mut cb = callback(a);
        let cp: *mut c_void = (&mut *cb as *mut FakeCallback).cast();
        let want = [1u32, 3];
        assert_eq!(
            unsafe { (vt::<InArchive>(a).extract)(a, want.as_ptr(), 2, 0, cp) },
            S_OK
        );
        assert_eq!(cb.results.lock().unwrap().len(), 2);
        // an index past the end is refused
        let bad = [9999u32];
        let mut cb = callback(a);
        let cp: *mut c_void = (&mut *cb as *mut FakeCallback).cast();
        assert_ne!(unsafe { (vt::<InArchive>(a).extract)(a, bad.as_ptr(), 1, 0, cp) }, S_OK);
        unsafe { (vt::<InArchive>(a).base.release)(a) };
        drop(o.stream);
    });
}

#[test]
fn damage_is_reported_as_a_data_error_for_the_affected_files_only() {
    let dir = tempfile::tempdir().unwrap();
    let (_, arc) = make_archive(dir.path());
    let mut file = fs::read(&arc).unwrap();
    file[40_000] ^= 0xff; // inside a block payload
    within(60, move || {
        let o = open_archive(file).unwrap();
        let a = o.archive;
        let mut cb = callback(a);
        let cp: *mut c_void = (&mut *cb as *mut FakeCallback).cast();
        let hr = unsafe { (vt::<InArchive>(a).extract)(a, std::ptr::null(), u32::MAX, 1, cp) };
        assert_eq!(hr, S_OK, "damage is a per-file result, not a failure of the whole call");
        let r = cb.results.lock().unwrap().clone();
        assert!(r.contains(&2), "no data error reported: {r:?}");
        assert!(r.contains(&0), "every file was reported as damaged: {r:?}");
        unsafe { (vt::<InArchive>(a).base.release)(a) };
        drop(o.stream);
    });
}

#[test]
fn things_that_are_not_archives_are_declined_and_the_stream_is_released() {
    for bytes in [
        Vec::new(),
        b"PRAT\r\n\x1a\n".to_vec(),
        noise(5000, 1),
        b"PK\x03\x04 a zip, not ours".to_vec(),
    ] {
        let mut obj: *mut c_void = null_mut();
        assert_eq!(unsafe { CreateObject(&CLSID, &IID_IIN_ARCHIVE, &mut obj) }, S_OK);
        let mut stream = fake_stream(bytes);
        let sp: *mut c_void = (&mut *stream as *mut FakeStream).cast();
        let hr = unsafe { (vt::<InArchive>(obj).open)(obj, sp, std::ptr::null(), null_mut()) };
        assert_eq!(hr, S_FALSE);
        unsafe { (vt::<InArchive>(obj).base.release)(obj) };
        assert_eq!(
            stream.refs.load(Ordering::SeqCst),
            1,
            "the plugin kept a reference to the stream"
        );
    }
}

#[test]
fn the_stream_is_released_when_the_archive_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (_, arc) = make_archive(dir.path());
    let o = open_archive(fs::read(&arc).unwrap()).unwrap();
    assert!(
        o.stream.refs.load(Ordering::SeqCst) >= 2,
        "the plugin holds the stream while it is open"
    );
    assert_eq!(unsafe { (vt::<InArchive>(o.archive).close)(o.archive) }, S_OK);
    assert_eq!(o.stream.refs.load(Ordering::SeqCst), 1);
    // after Close there is nothing to list
    let mut n = 7u32;
    assert_ne!(
        unsafe { (vt::<InArchive>(o.archive).num_items)(o.archive, &mut n) },
        S_OK
    );
    unsafe { (vt::<InArchive>(o.archive).base.release)(o.archive) };
}

#[test]
fn query_interface_answers_for_the_archive_interface_and_refuses_others() {
    let dir = tempfile::tempdir().unwrap();
    let (_, arc) = make_archive(dir.path());
    let o = open_archive(fs::read(&arc).unwrap()).unwrap();
    let a = o.archive;
    let mut out: *mut c_void = null_mut();
    assert_eq!(
        unsafe { (vt::<InArchive>(a).base.qi)(a, &IID_IIN_ARCHIVE, &mut out) },
        S_OK
    );
    assert_eq!(out, a);
    unsafe { (vt::<InArchive>(a).base.release)(a) }; // the reference QueryInterface gave
    let mut other: *mut c_void = a;
    assert_eq!(
        unsafe { (vt::<InArchive>(a).base.qi)(a, &guid(6, 0x40), &mut other) },
        E_NOINTERFACE
    );
    assert!(other.is_null());
    unsafe { (vt::<InArchive>(a).base.release)(a) };
}

#[test]
fn an_encrypted_archive_asks_7zip_for_the_password_and_opens_with_the_right_one() {
    let dir = tempfile::tempdir().unwrap();
    let arc = make_encrypted(dir.path(), "pässword 密码");
    let file = fs::read(&arc).unwrap();
    within(60, move || {
        let mut cb = open_callback(Some(Answer::Password("pässword 密码".into())));
        let cp: *mut c_void = (&mut *cb as *mut FakeOpenCallback).cast();
        let o = open_archive_with(file, cp).expect("the right password opens it");
        assert_eq!(cb.asked.load(Ordering::SeqCst), 1, "asked exactly once");
        assert_eq!(
            cb.refs.load(Ordering::SeqCst),
            1,
            "the plugin released the password interface"
        );
        let a = o.archive;
        assert!(items(a) >= 7);
        // the columns say so: encrypted files, a method that names the cipher
        let mut enc = 0;
        for i in 0..items(a) {
            if prop(a, i, 15).as_bool() == Some(true) {
                enc += 1;
                assert_eq!(unsafe { prop(a, i, 22).take_string() }, "PRAT+AEAD");
            }
        }
        assert_eq!(enc, 5, "every file is encrypted, the folders are not");
        // and the data comes out
        let mut ecb = callback(a);
        let ep: *mut c_void = (&mut *ecb as *mut FakeCallback).cast();
        assert_eq!(
            unsafe { (vt::<InArchive>(a).extract)(a, std::ptr::null(), u32::MAX, 0, ep) },
            S_OK
        );
        assert!(ecb.results.lock().unwrap().iter().all(|&r| r == 0));
        // the stand-in hands out a stream for every item, folders included; the files carry the data
        let sink = ecb.sink.lock().unwrap();
        assert_eq!(sink.len(), items(a) as usize);
        assert_eq!(
            sink.iter().filter(|(_, data)| !data.is_empty()).count(),
            4,
            "four files are not empty"
        );
        drop(sink);
        unsafe { (vt::<InArchive>(a).base.release)(a) };
        drop(o.stream);
    });
}

#[test]
fn a_wrong_password_a_cancelled_box_and_a_missing_callback_all_leave_the_archive_closed() {
    let dir = tempfile::tempdir().unwrap();
    let arc = make_encrypted(dir.path(), "right");
    let file = fs::read(&arc).unwrap();
    within(60, move || {
        let mut wrong = open_callback(Some(Answer::Password("wrong".into())));
        let wp: *mut c_void = (&mut *wrong as *mut FakeOpenCallback).cast();
        assert_eq!(
            open_archive_with(file.clone(), wp).err(),
            Some(S_FALSE),
            "wrong password"
        );
        assert_eq!(wrong.asked.load(Ordering::SeqCst), 1);

        let mut cancel = open_callback(Some(Answer::Cancel));
        let cp: *mut c_void = (&mut *cancel as *mut FakeOpenCallback).cast();
        assert_eq!(
            open_archive_with(file.clone(), cp).err(),
            Some(0x8000_4004u32 as i32),
            "cancelled"
        );

        assert_eq!(open_archive(file.clone()).err(), Some(S_FALSE), "no callback to ask");

        let mut none = open_callback(None);
        let np: *mut c_void = (&mut *none as *mut FakeOpenCallback).cast();
        assert_eq!(
            open_archive_with(file, np).err(),
            Some(S_FALSE),
            "a callback without a password interface"
        );
        assert_eq!(none.refs.load(Ordering::SeqCst), 1);
    });
}
