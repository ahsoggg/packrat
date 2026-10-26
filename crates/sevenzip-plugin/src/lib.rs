//! `packrat7z.dll`: a format plugin for 7-Zip. Put it in `7-Zip\Formats\` and 7-Zip lists, tests and extracts
//! `.prat` archives (it does not create them; use Packrat for that).
//!
//! 7-Zip talks to plugins through COM-style interfaces (`IInArchive` and friends, declared in 7-Zip's
//! `CPP/7zip/Archive/IArchive.h`). The layouts below follow those headers: every interface is a table of function
//! pointers that starts with `QueryInterface`, `AddRef` and `Release`, and the methods follow in declaration order.
//! Everything that crosses the boundary is checked for null and for range; a panic never unwinds into 7-Zip.
#![cfg(windows)]
#![allow(clippy::missing_safety_doc)]

use packrat_core::archive::Archive;
use packrat_core::entry::{Entry, EntryKind};
use packrat_core::prat::PratArchive;
use packrat_core::source::Source;
use std::ffi::c_void;
use std::io::Read;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{SysAllocStringByteLen, SysAllocStringLen, SysFreeString};

type Hr = i32;
const S_OK: Hr = 0;
const S_FALSE: Hr = 1;
const E_NOINTERFACE: Hr = 0x8000_4002u32 as i32;
const E_ABORT: Hr = 0x8000_4004u32 as i32;
const E_FAIL: Hr = 0x8000_4005u32 as i32;
const E_INVALIDARG: Hr = 0x8007_0057u32 as i32;
const E_OUTOFMEMORY: Hr = 0x8007_000Eu32 as i32;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

impl Guid {
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        Self { d1, d2, d3, d4 }
    }
}

/// 7-Zip's interface ids look like `23170F69-40C1-278A-0000-000<group>00<id>0000`.
const fn sz_guid(group: u8, id: u8) -> Guid {
    Guid {
        d1: 0x2317_0F69,
        d2: 0x40C1,
        d3: 0x278A,
        d4: [0, 0, 0, group, 0, id, 0, 0],
    }
}

const IID_IUNKNOWN: Guid = Guid {
    d1: 0,
    d2: 0,
    d3: 0,
    d4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
};
const IID_IIN_ARCHIVE: Guid = sz_guid(6, 0x60);
/// The class id of this handler (any value that no other 7-Zip format uses).
const CLSID_PRAT: Guid = Guid {
    d1: 0x5052_4154,
    d2: 0x5A37,
    d3: 0x4C4B,
    d4: [0xA1, 0x2B, 0x50, 0x52, 0x41, 0x54, 0x37, 0x5A],
};

// property ids (PropID.h)
const KPID_PATH: u32 = 3;
const KPID_IS_DIR: u32 = 6;
const KPID_SIZE: u32 = 7;
const KPID_ATTRIB: u32 = 9;
const KPID_MTIME: u32 = 12;
const KPID_METHOD: u32 = 22;
const KPID_PHY_SIZE: u32 = 44;

// handler property ids (IArchive.h, NArchive::NHandlerPropID)
const H_NAME: u32 = 0;
const H_CLASS_ID: u32 = 1;
const H_EXTENSION: u32 = 2;
const H_UPDATE: u32 = 4;
const H_KEEP_NAME: u32 = 5;
const H_SIGNATURE: u32 = 6;
const H_SIGNATURE_OFFSET: u32 = 8;

// VARENUM
const VT_EMPTY: u16 = 0;
const VT_BSTR: u16 = 8;
const VT_BOOL: u16 = 11;
const VT_UI4: u16 = 19;
const VT_UI8: u16 = 21;
const VT_FILETIME: u16 = 64;

// NArchive::NExtract
const ASK_EXTRACT: i32 = 0;
const ASK_TEST: i32 = 1;
const RESULT_OK: i32 = 0;
const RESULT_UNSUPPORTED: i32 = 1;
const RESULT_DATA_ERROR: i32 = 2;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

/// PROPVARIANT: a type tag and an 8-byte value.
#[repr(C)]
pub struct PropVariant {
    vt: u16,
    w1: u16,
    w2: u16,
    w3: u16,
    value: u64,
}

impl PropVariant {
    pub fn empty() -> Self {
        Self {
            vt: VT_EMPTY,
            w1: 0,
            w2: 0,
            w3: 0,
            value: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vt == VT_EMPTY
    }

    pub fn as_u32(&self) -> Option<u32> {
        (self.vt == VT_UI4).then_some(self.value as u32)
    }

    pub fn as_u64(&self) -> Option<u64> {
        (self.vt == VT_UI8).then_some(self.value)
    }

    pub fn as_bool(&self) -> Option<bool> {
        (self.vt == VT_BOOL).then_some(self.value & 0xFFFF != 0)
    }

    /// The bytes of a BSTR value, which is freed.
    pub unsafe fn take_bytes(&mut self) -> Vec<u8> {
        if self.vt != VT_BSTR || self.value == 0 {
            return Vec::new();
        }
        let b = self.value as usize as *const u8;
        // a BSTR is preceded by its length in bytes
        let len = unsafe { *(b.sub(4) as *const u32) } as usize;
        let bytes = unsafe { std::slice::from_raw_parts(b, len) }.to_vec();
        unsafe { SysFreeString(self.value as usize as *const u16) };
        *self = Self::empty();
        bytes
    }

    /// The text of a BSTR value, which is freed.
    pub unsafe fn take_string(&mut self) -> String {
        let bytes = unsafe { self.take_bytes() };
        let wide: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&wide)
    }
}

unsafe fn set_empty(v: *mut PropVariant) {
    unsafe {
        (*v).vt = VT_EMPTY;
        (*v).value = 0;
    }
}

unsafe fn set_u32(v: *mut PropVariant, x: u32) {
    unsafe {
        (*v).vt = VT_UI4;
        (*v).value = u64::from(x);
    }
}

unsafe fn set_u64(v: *mut PropVariant, x: u64) {
    unsafe {
        (*v).vt = VT_UI8;
        (*v).value = x;
    }
}

unsafe fn set_bool(v: *mut PropVariant, x: bool) {
    unsafe {
        (*v).vt = VT_BOOL;
        // VARIANT_BOOL is -1 for true
        (*v).value = if x { 0xFFFF } else { 0 };
    }
}

unsafe fn set_filetime(v: *mut PropVariant, unix_secs: i64) {
    let ticks = unix_secs
        .saturating_mul(10_000_000)
        .saturating_add(116_444_736_000_000_000)
        .max(0) as u64;
    unsafe {
        (*v).vt = VT_FILETIME;
        (*v).value = ticks;
    }
}

unsafe fn set_bstr(v: *mut PropVariant, s: &str) -> Hr {
    let wide: Vec<u16> = s.encode_utf16().collect();
    let b = unsafe { SysAllocStringLen(wide.as_ptr(), wide.len() as u32) };
    if b.is_null() {
        return E_OUTOFMEMORY;
    }
    unsafe {
        (*v).vt = VT_BSTR;
        (*v).value = b as usize as u64;
    }
    S_OK
}

unsafe fn set_bstr_bytes(v: *mut PropVariant, bytes: &[u8]) -> Hr {
    let b = unsafe { SysAllocStringByteLen(bytes.as_ptr(), bytes.len() as u32) };
    if b.is_null() {
        return E_OUTOFMEMORY;
    }
    unsafe {
        (*v).vt = VT_BSTR;
        (*v).value = b as usize as u64;
    }
    S_OK
}

fn guid_bytes(g: &Guid) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.d1.to_le_bytes());
    b[4..6].copy_from_slice(&g.d2.to_le_bytes());
    b[6..8].copy_from_slice(&g.d3.to_le_bytes());
    b[8..].copy_from_slice(&g.d4);
    b
}

// ---------------------------------------------------------------------------------------------------------------
// the interfaces 7-Zip hands us

#[repr(C)]
struct UnknownVtbl {
    query_interface: unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Hr,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct InStreamVtbl {
    base: UnknownVtbl,
    read: unsafe extern "system" fn(*mut c_void, *mut c_void, u32, *mut u32) -> Hr,
    seek: unsafe extern "system" fn(*mut c_void, i64, u32, *mut u64) -> Hr,
}

#[repr(C)]
struct OutStreamVtbl {
    base: UnknownVtbl,
    write: unsafe extern "system" fn(*mut c_void, *const c_void, u32, *mut u32) -> Hr,
}

#[repr(C)]
struct ExtractCallbackVtbl {
    base: UnknownVtbl,
    set_total: unsafe extern "system" fn(*mut c_void, u64) -> Hr,
    set_completed: unsafe extern "system" fn(*mut c_void, *const u64) -> Hr,
    get_stream: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void, i32) -> Hr,
    prepare_operation: unsafe extern "system" fn(*mut c_void, i32) -> Hr,
    set_operation_result: unsafe extern "system" fn(*mut c_void, i32) -> Hr,
}

/// Any COM object starts with a pointer to its table.
#[repr(C)]
struct ComObject<V> {
    vtbl: *const V,
}

unsafe fn vtbl<V>(p: *mut c_void) -> &'static V {
    unsafe { &*(*(p as *const ComObject<V>)).vtbl }
}

unsafe fn release(p: *mut c_void) {
    if !p.is_null() {
        unsafe { (vtbl::<UnknownVtbl>(p).release)(p) };
    }
}

/// Reads the archive through 7-Zip's `IInStream`. The stream has one position, so reads are serialized.
struct StreamSource {
    stream: *mut c_void,
    len: u64,
    lock: Mutex<()>,
}

// SAFETY: the raw pointer is only used under `lock`, and 7-Zip's streams may be used from any thread one at a time.
unsafe impl Send for StreamSource {}
unsafe impl Sync for StreamSource {}

impl StreamSource {
    unsafe fn new(stream: *mut c_void) -> Option<Self> {
        unsafe {
            (vtbl::<UnknownVtbl>(stream).add_ref)(stream);
            let mut len = 0u64;
            let hr = (vtbl::<InStreamVtbl>(stream).seek)(stream, 0, 2, &mut len);
            if hr != S_OK {
                release(stream);
                return None;
            }
            Some(Self {
                stream,
                len,
                lock: Mutex::new(()),
            })
        }
    }
}

impl Drop for StreamSource {
    fn drop(&mut self) {
        unsafe { release(self.stream) };
    }
}

impl Source for StreamSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(off) = i64::try_from(offset) else {
            return Ok(0);
        };
        let want = buf.len().min(1 << 30) as u32;
        let mut pos = 0u64;
        let mut got = 0u32;
        unsafe {
            let v = vtbl::<InStreamVtbl>(self.stream);
            if (v.seek)(self.stream, off, 0, &mut pos) != S_OK {
                return Err(std::io::Error::other("7-Zip could not seek in the archive"));
            }
            if (v.read)(self.stream, buf.as_mut_ptr().cast(), want, &mut got) != S_OK {
                return Err(std::io::Error::other("7-Zip could not read the archive"));
            }
        }
        Ok(got as usize)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// the archive object we give to 7-Zip

#[repr(C)]
struct InArchiveVtbl {
    base: UnknownVtbl,
    open: unsafe extern "system" fn(*mut c_void, *mut c_void, *const u64, *mut c_void) -> Hr,
    close: unsafe extern "system" fn(*mut c_void) -> Hr,
    get_number_of_items: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hr,
    get_property: unsafe extern "system" fn(*mut c_void, u32, u32, *mut PropVariant) -> Hr,
    extract: unsafe extern "system" fn(*mut c_void, *const u32, u32, i32, *mut c_void) -> Hr,
    get_archive_property: unsafe extern "system" fn(*mut c_void, u32, *mut PropVariant) -> Hr,
    get_number_of_properties: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hr,
    get_property_info: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16, *mut u32, *mut u16) -> Hr,
    get_number_of_archive_properties: unsafe extern "system" fn(*mut c_void, *mut u32) -> Hr,
    get_archive_property_info: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16, *mut u32, *mut u16) -> Hr,
}

#[repr(C)]
struct InArchive {
    vtbl: *const InArchiveVtbl,
    refs: AtomicU32,
    /// Shared out of the lock before any call into 7-Zip: its callbacks ask this same object for properties,
    /// so a lock held across them would wait for itself.
    state: Mutex<Option<Arc<State>>>,
}

struct State {
    archive: PratArchive,
    len: u64,
}

static IN_ARCHIVE_VTBL: InArchiveVtbl = InArchiveVtbl {
    base: UnknownVtbl {
        query_interface: ia_query_interface,
        add_ref: ia_add_ref,
        release: ia_release,
    },
    open: ia_open,
    close: ia_close,
    get_number_of_items: ia_get_number_of_items,
    get_property: ia_get_property,
    extract: ia_extract,
    get_archive_property: ia_get_archive_property,
    get_number_of_properties: ia_get_number_of_properties,
    get_property_info: ia_get_property_info,
    get_number_of_archive_properties: ia_get_number_of_archive_properties,
    get_archive_property_info: ia_get_archive_property_info,
};

/// Runs `f`, turning a panic into an error code instead of letting it unwind into 7-Zip.
fn guarded(f: impl FnOnce() -> Hr) -> Hr {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(E_FAIL)
}

unsafe fn this<'a>(p: *mut c_void) -> &'a InArchive {
    unsafe { &*(p as *const InArchive) }
}

unsafe extern "system" fn ia_query_interface(p: *mut c_void, iid: *const Guid, out: *mut *mut c_void) -> Hr {
    if iid.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    let iid = unsafe { *iid };
    if iid == IID_IUNKNOWN || iid == IID_IIN_ARCHIVE {
        unsafe {
            ia_add_ref(p);
            *out = p;
        }
        S_OK
    } else {
        unsafe { *out = null_mut() };
        E_NOINTERFACE
    }
}

unsafe extern "system" fn ia_add_ref(p: *mut c_void) -> u32 {
    unsafe { this(p) }.refs.fetch_add(1, Ordering::AcqRel) + 1
}

unsafe extern "system" fn ia_release(p: *mut c_void) -> u32 {
    let left = unsafe { this(p) }.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: the object was created by `Box::into_raw` in `create_in_archive` and nobody holds it any more.
        drop(unsafe { Box::from_raw(p as *mut InArchive) });
    }
    left
}

unsafe extern "system" fn ia_open(p: *mut c_void, stream: *mut c_void, _max: *const u64, _cb: *mut c_void) -> Hr {
    guarded(|| {
        if stream.is_null() {
            return E_INVALIDARG;
        }
        let Some(src) = (unsafe { StreamSource::new(stream) }) else {
            return S_FALSE;
        };
        let len = src.len;
        match PratArchive::from_source(Arc::new(src)) {
            Ok(archive) => {
                *unsafe { this(p) }.state.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Arc::new(State { archive, len }));
                S_OK
            }
            // not an archive for this handler (7-Zip tries the next one) rather than a failure
            Err(_) => S_FALSE,
        }
    })
}

unsafe extern "system" fn ia_close(p: *mut c_void) -> Hr {
    guarded(|| {
        *unsafe { this(p) }.state.lock().unwrap_or_else(|e| e.into_inner()) = None;
        S_OK
    })
}

fn current(p: *mut c_void) -> Option<Arc<State>> {
    unsafe { this(p) }
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn with_archive<T>(p: *mut c_void, f: impl FnOnce(&State) -> T) -> Option<T> {
    current(p).map(|s| f(&s))
}

unsafe extern "system" fn ia_get_number_of_items(p: *mut c_void, n: *mut u32) -> Hr {
    guarded(|| {
        if n.is_null() {
            return E_INVALIDARG;
        }
        match with_archive(p, |s| s.archive.entries().len()) {
            Some(c) => {
                unsafe { *n = c as u32 };
                S_OK
            }
            None => E_FAIL,
        }
    })
}

fn display_path(e: &Entry) -> String {
    e.path.trim_start_matches('/').replace('/', "\\")
}

unsafe extern "system" fn ia_get_property(p: *mut c_void, index: u32, prop: u32, v: *mut PropVariant) -> Hr {
    guarded(|| {
        if v.is_null() {
            return E_INVALIDARG;
        }
        unsafe { set_empty(v) };
        let Some(r) = with_archive(p, |s| {
            let e = s.archive.entries().get(index as usize)?;
            Some(unsafe {
                match prop {
                    KPID_PATH => set_bstr(v, &display_path(e)),
                    KPID_IS_DIR => {
                        set_bool(v, e.kind == EntryKind::Dir);
                        S_OK
                    }
                    KPID_SIZE if e.kind != EntryKind::Dir => {
                        set_u64(v, e.size);
                        S_OK
                    }
                    KPID_ATTRIB => {
                        set_u32(
                            v,
                            if e.kind == EntryKind::Dir {
                                FILE_ATTRIBUTE_DIRECTORY
                            } else {
                                FILE_ATTRIBUTE_ARCHIVE
                            },
                        );
                        S_OK
                    }
                    KPID_MTIME => {
                        if let Some(t) = e.mtime {
                            set_filetime(v, t);
                        }
                        S_OK
                    }
                    KPID_METHOD => set_bstr(v, "PRAT"),
                    _ => S_OK,
                }
            })
        }) else {
            return E_FAIL;
        };
        r.unwrap_or(E_INVALIDARG)
    })
}

unsafe extern "system" fn ia_get_archive_property(p: *mut c_void, prop: u32, v: *mut PropVariant) -> Hr {
    guarded(|| {
        if v.is_null() {
            return E_INVALIDARG;
        }
        unsafe { set_empty(v) };
        if prop == KPID_PHY_SIZE
            && let Some(len) = with_archive(p, |s| s.len)
        {
            unsafe { set_u64(v, len) };
        }
        S_OK
    })
}

/// The columns 7-Zip may show: (property id, variant type).
const COLUMNS: [(u32, u16); 6] = [
    (KPID_PATH, VT_BSTR),
    (KPID_IS_DIR, VT_BOOL),
    (KPID_SIZE, VT_UI8),
    (KPID_MTIME, VT_FILETIME),
    (KPID_ATTRIB, VT_UI4),
    (KPID_METHOD, VT_BSTR),
];

unsafe extern "system" fn ia_get_number_of_properties(_p: *mut c_void, n: *mut u32) -> Hr {
    if n.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *n = COLUMNS.len() as u32 };
    S_OK
}

unsafe extern "system" fn ia_get_property_info(
    _p: *mut c_void,
    index: u32,
    name: *mut *mut u16,
    id: *mut u32,
    vt: *mut u16,
) -> Hr {
    let Some(&(pid, ty)) = COLUMNS.get(index as usize) else {
        return E_INVALIDARG;
    };
    if id.is_null() || vt.is_null() {
        return E_INVALIDARG;
    }
    unsafe {
        if !name.is_null() {
            *name = null_mut(); // 7-Zip uses its own names for the standard properties
        }
        *id = pid;
        *vt = ty;
    }
    S_OK
}

unsafe extern "system" fn ia_get_number_of_archive_properties(_p: *mut c_void, n: *mut u32) -> Hr {
    if n.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *n = 1 };
    S_OK
}

unsafe extern "system" fn ia_get_archive_property_info(
    _p: *mut c_void,
    index: u32,
    name: *mut *mut u16,
    id: *mut u32,
    vt: *mut u16,
) -> Hr {
    if index != 0 || id.is_null() || vt.is_null() {
        return E_INVALIDARG;
    }
    unsafe {
        if !name.is_null() {
            *name = null_mut();
        }
        *id = KPID_PHY_SIZE;
        *vt = VT_UI8;
    }
    S_OK
}

unsafe fn write_all(out: *mut c_void, mut data: &[u8]) -> Hr {
    while !data.is_empty() {
        let n = data.len().min(1 << 30) as u32;
        let mut done = 0u32;
        let hr = unsafe { (vtbl::<OutStreamVtbl>(out).write)(out, data.as_ptr().cast(), n, &mut done) };
        if hr != S_OK {
            return hr;
        }
        if done == 0 {
            return E_FAIL;
        }
        data = &data[(done as usize).min(data.len())..];
    }
    S_OK
}

/// Maps a read error onto 7-Zip's result codes.
fn result_code(e: &std::io::Error) -> i32 {
    let msg = e.to_string().to_lowercase();
    if msg.contains("unsupported") {
        RESULT_UNSUPPORTED
    } else {
        RESULT_DATA_ERROR
    }
}

unsafe extern "system" fn ia_extract(
    p: *mut c_void,
    indices: *const u32,
    count: u32,
    test: i32,
    cb: *mut c_void,
) -> Hr {
    guarded(|| {
        if cb.is_null() {
            return E_INVALIDARG;
        }
        let Some(state) = current(p) else {
            return E_FAIL;
        };
        let entries = state.archive.entries();
        let wanted: Vec<u32> = if count == u32::MAX {
            (0..entries.len() as u32).collect()
        } else if indices.is_null() {
            return E_INVALIDARG;
        } else {
            unsafe { std::slice::from_raw_parts(indices, count as usize) }.to_vec()
        };
        if wanted.iter().any(|&i| i as usize >= entries.len()) {
            return E_INVALIDARG;
        }
        let ask = if test != 0 { ASK_TEST } else { ASK_EXTRACT };
        let total: u64 = wanted
            .iter()
            .map(|&i| &entries[i as usize])
            .filter(|e| e.kind != EntryKind::Dir)
            .map(|e| e.size)
            .sum();
        let cbv = unsafe { vtbl::<ExtractCallbackVtbl>(cb) };
        let hr = unsafe { (cbv.set_total)(cb, total) };
        if hr != S_OK {
            return hr;
        }

        let mut done = 0u64;
        let mut buf = vec![0u8; 256 << 10];
        for &index in &wanted {
            let e = &entries[index as usize];
            let mut out: *mut c_void = null_mut();
            let hr = unsafe { (cbv.get_stream)(cb, index, &mut out, ask) };
            if hr != S_OK {
                unsafe { release(out) };
                return hr;
            }
            if e.kind == EntryKind::Dir {
                unsafe { release(out) };
                let hr = unsafe { (cbv.prepare_operation)(cb, ask) };
                if hr != S_OK {
                    return hr;
                }
                let hr = unsafe { (cbv.set_operation_result)(cb, RESULT_OK) };
                if hr != S_OK {
                    return hr;
                }
                continue;
            }
            if test == 0 && out.is_null() {
                continue; // 7-Zip does not want this one
            }
            let hr = unsafe { (cbv.prepare_operation)(cb, ask) };
            if hr != S_OK {
                unsafe { release(out) };
                return hr;
            }

            let mut result = RESULT_OK;
            match state.archive.open_entry(e.index) {
                Err(err) => result = result_code(&std::io::Error::other(err)),
                Ok(mut r) => loop {
                    match r.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if !out.is_null() {
                                let hr = unsafe { write_all(out, &buf[..n]) };
                                if hr != S_OK {
                                    unsafe { release(out) };
                                    return hr;
                                }
                            }
                            done += n as u64;
                            let hr = unsafe { (cbv.set_completed)(cb, &done) };
                            if hr != S_OK {
                                unsafe { release(out) };
                                return if hr == S_FALSE { E_ABORT } else { hr };
                            }
                        }
                        Err(err) => {
                            result = result_code(&err);
                            break;
                        }
                    }
                },
            }
            // 7-Zip finishes the file (times, attributes) when the stream is released, before the result arrives
            unsafe { release(out) };
            let hr = unsafe { (cbv.set_operation_result)(cb, result) };
            if hr != S_OK {
                return hr;
            }
        }
        S_OK
    })
}

fn create_in_archive() -> *mut c_void {
    let obj = Box::new(InArchive {
        vtbl: &IN_ARCHIVE_VTBL,
        refs: AtomicU32::new(1),
        state: Mutex::new(None),
    });
    Box::into_raw(obj).cast()
}

// ---------------------------------------------------------------------------------------------------------------
// what 7-Zip looks for in a format plugin

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CreateObject(clsid: *const Guid, iid: *const Guid, out: *mut *mut c_void) -> Hr {
    if clsid.is_null() || iid.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *out = null_mut() };
    if unsafe { *clsid } != CLSID_PRAT {
        return E_NOINTERFACE;
    }
    let iid = unsafe { *iid };
    if iid != IID_IIN_ARCHIVE && iid != IID_IUNKNOWN {
        // there is no IOutArchive: this handler only reads
        return E_NOINTERFACE;
    }
    unsafe { *out = create_in_archive() };
    S_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetNumberOfFormats(n: *mut u32) -> Hr {
    if n.is_null() {
        return E_INVALIDARG;
    }
    unsafe { *n = 1 };
    S_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetHandlerProperty2(index: u32, prop: u32, v: *mut PropVariant) -> Hr {
    if v.is_null() || index != 0 {
        return E_INVALIDARG;
    }
    unsafe {
        set_empty(v);
        match prop {
            H_NAME => set_bstr(v, "Packrat"),
            H_CLASS_ID => set_bstr_bytes(v, &guid_bytes(&CLSID_PRAT)),
            H_EXTENSION => set_bstr(v, "prat"),
            H_UPDATE | H_KEEP_NAME => {
                set_bool(v, false);
                S_OK
            }
            H_SIGNATURE => set_bstr_bytes(v, &packrat_core::prat::format::MAGIC),
            H_SIGNATURE_OFFSET => {
                set_u32(v, 0);
                S_OK
            }
            _ => S_OK,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetHandlerProperty(prop: u32, v: *mut PropVariant) -> Hr {
    unsafe { GetHandlerProperty2(0, prop, v) }
}
