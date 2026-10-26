//! Decides how a file should be packed: executables get a branch converter (BCJ) in front of the compressor,
//! files that are already compressed are stored as they are, everything else is plain data. The class also
//! drives the order of files inside solid blocks, so that similar files sit next to each other.

use crate::input::InputItem;
use std::io::Read;
use std::path::Path;

/// The branch converter that suits an executable's machine code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bcj {
    X86,
    Arm,
    ArmThumb,
    Arm64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Executable code: a BCJ filter before the compressor.
    Code(Bcj),
    /// Nothing to gain from compressing (JPEG, MP4, ZIP, ...).
    Packed,
    Data,
}

const CODE_EXTS: &[&str] = &[
    "exe", "dll", "sys", "ocx", "scr", "efi", "cpl", "ax", "drv", "mui", "node", "pyd", "winmd",
];

const PACKED_EXTS: &[&str] = &[
    "zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "zst", "lz4", "lzma", "cab", "jar", "apk", "whl", "docx", "xlsx",
    "pptx", "odt", "ods", "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif", "mp3", "m4a", "aac", "ogg",
    "opus", "mp4", "m4v", "mkv", "webm", "mov", "avi", "wmv", "woff2", "br",
];

fn ext_of(name: &str) -> String {
    let file = name.rsplit('/').next().unwrap_or(name);
    match file.rfind('.') {
        Some(i) if i > 0 => file[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Reads the machine type out of a PE header; `None` when the file is not a PE image.
fn pe_machine(path: &Path) -> Option<u16> {
    let mut head = [0u8; 1024];
    let mut f = std::fs::File::open(path).ok()?;
    let mut got = 0;
    while got < head.len() {
        match f.read(&mut head[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    machine_of(&head[..got])
}

fn machine_of(head: &[u8]) -> Option<u16> {
    if head.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(head.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if head.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(head.get(pe + 4..pe + 6)?.try_into().ok()?))
}

fn bcj_for_machine(machine: u16) -> Option<Bcj> {
    match machine {
        0x014c | 0x8664 => Some(Bcj::X86),
        0x01c0 => Some(Bcj::Arm),
        0x01c4 => Some(Bcj::ArmThumb),
        0xaa64 => Some(Bcj::Arm64),
        _ => None,
    }
}

pub fn classify(item: &InputItem) -> Class {
    let ext = ext_of(&item.name);
    if CODE_EXTS.contains(&ext.as_str()) {
        return pe_machine(&item.disk_path)
            .and_then(bcj_for_machine)
            .map_or(Class::Data, Class::Code);
    }
    if PACKED_EXTS.contains(&ext.as_str()) {
        return Class::Packed;
    }
    Class::Data
}

/// Sort key for solid blocks: class first (a block has one filter chain), then extension, then name.
pub fn solid_key(item: &InputItem, class: Class) -> (Class, String, String) {
    (class, ext_of(&item.name), item.name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe(machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 256];
        h[..2].copy_from_slice(b"MZ");
        h[0x3c] = 0x80;
        h[0x80..0x84].copy_from_slice(b"PE\0\0");
        h[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        h
    }

    #[test]
    fn machine_types_pick_the_right_filter() {
        assert_eq!(machine_of(&pe(0x8664)).and_then(bcj_for_machine), Some(Bcj::X86));
        assert_eq!(machine_of(&pe(0x014c)).and_then(bcj_for_machine), Some(Bcj::X86));
        assert_eq!(machine_of(&pe(0xaa64)).and_then(bcj_for_machine), Some(Bcj::Arm64));
        assert_eq!(machine_of(&pe(0x0200)).and_then(bcj_for_machine), None);
    }

    #[test]
    fn non_pe_and_truncated_headers_are_not_code() {
        assert_eq!(machine_of(b"plain text, nothing to see"), None);
        assert_eq!(machine_of(b"MZ"), None);
        let mut broken = pe(0x8664);
        broken[0x3c] = 0xff; // e_lfanew points past the buffer
        assert_eq!(machine_of(&broken), None);
    }

    #[test]
    fn extensions() {
        assert_eq!(ext_of("a/b/Photo.JPG"), "jpg");
        assert_eq!(ext_of("a.b/readme"), "");
        assert_eq!(ext_of(".gitignore"), "");
    }
}
