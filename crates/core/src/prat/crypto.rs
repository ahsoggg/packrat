//! Encryption for `.prat` (format version 2). Design, in short:
//!
//! - The password goes through Argon2id (parameters and a random salt are stored in the encryption header), and the
//!   32-byte result is split with BLAKE3 into separate keys for blocks, the index, the block hashes and the password
//!   check, so no key is ever used for two purposes.
//! - Every block and the index is sealed with XChaCha20-Poly1305. The nonce is a random per-archive prefix and the
//!   block number, so no nonce repeats; the associated data binds a block to its number, codec, size and to the
//!   encryption header, so blocks cannot be swapped, re-labelled or moved into another archive, and the parameters
//!   cannot be tampered with.
//! - Data is compressed first and encrypted after. The index (names, sizes, times, chunk hashes) is encrypted as a
//!   whole; the hashes in block headers become keyed hashes, because a plain hash of the plaintext would let anyone
//!   confirm that a known file is inside.
//!
//! What stays visible: the archive size, the number and sizes of blocks and their codec. See `docs/PRAT_FORMAT.md`.

use crate::error::{Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub const ENC_MAGIC: [u8; 8] = *b"PRATENC\x01";
pub const ENC_HEADER_LEN: usize = 80;
pub const TAG_LEN: usize = 16;

const KDF_ARGON2ID: u8 = 1;
const CIPHER_XCHACHA20_POLY1305: u8 = 1;

/// What a hostile file may ask of the key derivation: bounded, so opening it cannot eat the machine.
pub const MAX_KDF_MEM_KIB: u32 = 1 << 20;
pub const MAX_KDF_TIME: u32 = 32;
pub const MAX_KDF_LANES: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub mem_kib: u32,
    pub time: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes: a fraction of a second per guess for the owner, expensive for an attacker.
    fn default() -> Self {
        Self {
            mem_kib: 64 << 10,
            time: 3,
            lanes: 4,
        }
    }
}

impl KdfParams {
    pub fn validate(&self) -> Result<()> {
        let ok = (1..=MAX_KDF_LANES).contains(&self.lanes)
            && (1..=MAX_KDF_TIME).contains(&self.time)
            && self.mem_kib >= 8 * self.lanes
            && self.mem_kib <= MAX_KDF_MEM_KIB;
        if ok {
            Ok(())
        } else {
            Err(Error::Corrupt(
                "the key derivation settings in the archive are out of range".into(),
            ))
        }
    }
}

fn kdf_error(e: impl std::fmt::Display) -> Error {
    Error::Other(format!("key derivation failed: {e}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EncHeader {
    params: KdfParams,
    salt: [u8; 16],
    nonce_prefix: [u8; 16],
    verifier: [u8; 16],
}

impl EncHeader {
    fn encode(&self) -> [u8; ENC_HEADER_LEN] {
        let mut h = [0u8; ENC_HEADER_LEN];
        h[..8].copy_from_slice(&ENC_MAGIC);
        h[8] = KDF_ARGON2ID;
        h[9] = CIPHER_XCHACHA20_POLY1305;
        h[12..16].copy_from_slice(&self.params.mem_kib.to_le_bytes());
        h[16..20].copy_from_slice(&self.params.time.to_le_bytes());
        h[20..24].copy_from_slice(&self.params.lanes.to_le_bytes());
        h[24..40].copy_from_slice(&self.salt);
        h[40..56].copy_from_slice(&self.nonce_prefix);
        h[56..72].copy_from_slice(&self.verifier);
        let crc = crc32fast::hash(&h[..ENC_HEADER_LEN - 4]);
        h[ENC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        h
    }

    fn decode(h: &[u8]) -> Result<Self> {
        if h.len() < ENC_HEADER_LEN || h[..8] != ENC_MAGIC {
            return Err(Error::Corrupt("the encryption header is missing".into()));
        }
        let crc = u32::from_le_bytes(h[ENC_HEADER_LEN - 4..ENC_HEADER_LEN].try_into().unwrap());
        if crc != crc32fast::hash(&h[..ENC_HEADER_LEN - 4]) {
            return Err(Error::Corrupt("the encryption header is damaged".into()));
        }
        if h[8] != KDF_ARGON2ID || h[9] != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::Unsupported(
                "this archive uses an encryption method this Packrat does not know".into(),
            ));
        }
        let params = KdfParams {
            mem_kib: u32::from_le_bytes(h[12..16].try_into().unwrap()),
            time: u32::from_le_bytes(h[16..20].try_into().unwrap()),
            lanes: u32::from_le_bytes(h[20..24].try_into().unwrap()),
        };
        params.validate()?;
        Ok(Self {
            params,
            salt: h[24..40].try_into().unwrap(),
            nonce_prefix: h[40..56].try_into().unwrap(),
            verifier: h[56..72].try_into().unwrap(),
        })
    }
}

struct Keys {
    block: Zeroizing<[u8; 32]>,
    index: Zeroizing<[u8; 32]>,
    hash: Zeroizing<[u8; 32]>,
    verify: Zeroizing<[u8; 32]>,
}

fn derive_keys(password: &str, salt: &[u8; 16], params: &KdfParams) -> Result<Keys> {
    params.validate()?;
    let p = Params::new(params.mem_kib, params.time, params.lanes, Some(32)).map_err(kdf_error)?;
    let mut master = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password.as_bytes(), salt, &mut master[..])
        .map_err(kdf_error)?;
    let sub = |context: &str| Zeroizing::new(blake3::derive_key(context, &master[..]));
    Ok(Keys {
        block: sub("packrat prat v2 block key"),
        index: sub("packrat prat v2 index key"),
        hash: sub("packrat prat v2 block hash key"),
        verify: sub("packrat prat v2 password check key"),
    })
}

fn verifier_of(keys: &Keys) -> [u8; 16] {
    let full = blake3::keyed_hash(&keys.verify, b"packrat prat v2 password check");
    full.as_bytes()[..16].try_into().unwrap()
}

/// Everything needed to seal and open the blocks and the index of one archive. Cheap to share between threads.
pub struct Cipher {
    header: EncHeader,
    /// BLAKE3 of the encryption header: part of every associated data.
    digest: [u8; 32],
    keys: Keys,
    blocks: XChaCha20Poly1305,
    index: XChaCha20Poly1305,
}

/// Index number used for the nonce of the index, which no block can have.
const INDEX_COUNTER: u64 = u64::MAX;

impl Cipher {
    /// `raw` is the header exactly as stored: the associated data covers every byte of it, reserved ones included.
    fn from_parts(header: EncHeader, keys: Keys, raw: &[u8]) -> Result<Self> {
        let blocks = XChaCha20Poly1305::new_from_slice(&keys.block[..]).map_err(|_| Error::Other("bad key".into()))?;
        let index = XChaCha20Poly1305::new_from_slice(&keys.index[..]).map_err(|_| Error::Other("bad key".into()))?;
        let digest = *blake3::hash(raw).as_bytes();
        Ok(Self {
            header,
            digest,
            keys,
            blocks,
            index,
        })
    }

    /// A new cipher for a new archive: random salt and nonce prefix. Returns the header bytes to store.
    pub fn create(password: &str, params: KdfParams) -> Result<(Self, [u8; ENC_HEADER_LEN])> {
        params.validate().map_err(|_| {
            Error::Other(
                "the key derivation settings are out of range (memory 8 KiB..1 GiB, time 1..32, lanes 1..16)".into(),
            )
        })?;
        let mut salt = [0u8; 16];
        let mut nonce_prefix = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| Error::Other(format!("no random numbers available: {e}")))?;
        getrandom::fill(&mut nonce_prefix).map_err(|e| Error::Other(format!("no random numbers available: {e}")))?;
        let keys = derive_keys(password, &salt, &params)?;
        let header = EncHeader {
            params,
            salt,
            nonce_prefix,
            verifier: verifier_of(&keys),
        };
        let bytes = header.encode();
        Ok((Self::from_parts(header, keys, &bytes)?, bytes))
    }

    /// Validates the encryption header (magic, CRC, method, settings) without needing the password.
    pub fn check_header(header_bytes: &[u8]) -> Result<()> {
        EncHeader::decode(header_bytes).map(|_| ())
    }

    /// Opens an existing archive's cipher from its header bytes and a password.
    pub fn open(header_bytes: &[u8], password: &str) -> Result<Self> {
        let header = EncHeader::decode(header_bytes)?;
        let keys = derive_keys(password, &header.salt, &header.params)?;
        if verifier_of(&keys) != header.verifier {
            return Err(Error::WrongPassword);
        }
        Self::from_parts(header, keys, &header_bytes[..ENC_HEADER_LEN])
    }

    fn nonce(&self, counter: u64) -> XNonce {
        let mut n = [0u8; 24];
        n[..16].copy_from_slice(&self.header.nonce_prefix);
        n[16..].copy_from_slice(&counter.to_le_bytes());
        *XNonce::from_slice(&n)
    }

    fn aad(&self, kind: u8, number: u32, codec: u8, ulen: u32) -> [u8; 42] {
        let mut a = [0u8; 42];
        a[..32].copy_from_slice(&self.digest);
        a[32] = kind;
        a[33..37].copy_from_slice(&number.to_le_bytes());
        a[37] = codec;
        // ulen is 4 bytes: 37 + 1 + 4 = 42
        a[38..42].copy_from_slice(&ulen.to_le_bytes());
        a
    }

    /// Hash of a block's plaintext, keyed so that it reveals nothing to someone without the password.
    pub fn block_hash(&self, plain: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.keys.hash, plain).as_bytes()
    }

    pub fn seal_block(&self, number: u32, codec: u8, ulen: u32, payload: &[u8]) -> Result<Vec<u8>> {
        self.blocks
            .encrypt(
                &self.nonce(u64::from(number)),
                Payload {
                    msg: payload,
                    aad: &self.aad(0, number, codec, ulen),
                },
            )
            .map_err(|_| Error::Other("encryption failed".into()))
    }

    pub fn open_block(&self, number: u32, codec: u8, ulen: u32, sealed: &[u8]) -> Result<Vec<u8>> {
        self.blocks
            .decrypt(
                &self.nonce(u64::from(number)),
                Payload {
                    msg: sealed,
                    aad: &self.aad(0, number, codec, ulen),
                },
            )
            .map_err(|_| {
                Error::Corrupt(format!(
                    "block {number} failed its authentication (damaged or tampered with)"
                ))
            })
    }

    pub fn seal_index(&self, ulen: u32, stored: &[u8]) -> Result<Vec<u8>> {
        self.index
            .encrypt(
                &self.nonce(INDEX_COUNTER),
                Payload {
                    msg: stored,
                    aad: &self.aad(1, 0, 0, ulen),
                },
            )
            .map_err(|_| Error::Other("encryption failed".into()))
    }

    pub fn open_index(&self, ulen: u32, sealed: &[u8]) -> Result<Vec<u8>> {
        self.index
            .decrypt(
                &self.nonce(INDEX_COUNTER),
                Payload {
                    msg: sealed,
                    aad: &self.aad(1, 0, 0, ulen),
                },
            )
            .map_err(|_| Error::Corrupt("the index failed its authentication (damaged or tampered with)".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap settings: the tests are about the construction, not about the cost of guessing.
    const FAST: KdfParams = KdfParams {
        mem_kib: 64,
        time: 1,
        lanes: 1,
    };

    fn pair() -> (Cipher, [u8; ENC_HEADER_LEN]) {
        Cipher::create("correct horse", FAST).unwrap()
    }

    #[test]
    fn blocks_and_the_index_roundtrip() {
        let (c, header) = pair();
        let sealed = c.seal_block(3, 1, 1000, b"some compressed bytes").unwrap();
        assert_eq!(sealed.len(), 21 + TAG_LEN);
        assert_eq!(c.open_block(3, 1, 1000, &sealed).unwrap(), b"some compressed bytes");
        let again = Cipher::open(&header, "correct horse").unwrap();
        assert_eq!(again.open_block(3, 1, 1000, &sealed).unwrap(), b"some compressed bytes");
        let idx = c.seal_index(77, b"index bytes").unwrap();
        assert_eq!(again.open_index(77, &idx).unwrap(), b"index bytes");
    }

    #[test]
    fn a_wrong_password_is_told_apart_from_damage() {
        let (_, header) = pair();
        assert!(matches!(
            Cipher::open(&header, "Correct horse"),
            Err(Error::WrongPassword)
        ));
        assert!(matches!(Cipher::open(&header, ""), Err(Error::WrongPassword)));
        let mut damaged = header;
        damaged[30] ^= 1;
        assert!(matches!(
            Cipher::open(&damaged, "correct horse"),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn a_block_cannot_be_moved_relabelled_or_taken_to_another_archive() {
        let (c, _) = pair();
        let sealed = c.seal_block(5, 1, 4096, b"payload").unwrap();
        assert!(c.open_block(6, 1, 4096, &sealed).is_err(), "another position");
        assert!(c.open_block(5, 0, 4096, &sealed).is_err(), "another codec");
        assert!(c.open_block(5, 1, 4097, &sealed).is_err(), "another size");
        let (other, _) = pair();
        assert!(
            other.open_block(5, 1, 4096, &sealed).is_err(),
            "another archive, same password"
        );
        let mut flipped = sealed.clone();
        flipped[0] ^= 1;
        assert!(c.open_block(5, 1, 4096, &flipped).is_err(), "a changed byte");
        assert!(
            c.open_block(5, 1, 4096, &sealed[..sealed.len() - 1]).is_err(),
            "a cut tag"
        );
        // the index is a different domain from any block
        let idx = c.seal_index(4096, b"payload").unwrap();
        assert!(c.open_block(0, 0, 4096, &idx).is_err());
        assert!(c.open_index(4096, &sealed).is_err());
    }

    #[test]
    fn nothing_repeats_between_archives_or_between_blocks() {
        let (a, ha) = pair();
        let (b, hb) = pair();
        assert_ne!(ha[24..56], hb[24..56], "salt and nonce prefix are random");
        let s1 = a.seal_block(0, 0, 10, b"same data").unwrap();
        let s2 = a.seal_block(1, 0, 10, b"same data").unwrap();
        let s3 = b.seal_block(0, 0, 10, b"same data").unwrap();
        assert!(s1 != s2 && s1 != s3, "equal plaintext must not give equal ciphertext");
    }

    #[test]
    fn the_keyed_hash_depends_on_the_password_and_the_archive() {
        let (a, _) = pair();
        let (b, _) = pair();
        assert_ne!(a.block_hash(b"x"), b.block_hash(b"x"));
        assert_eq!(a.block_hash(b"x"), a.block_hash(b"x"));
        assert_ne!(
            a.block_hash(b"x"),
            *blake3::hash(b"x").as_bytes(),
            "not a plain hash of the data"
        );
    }

    #[test]
    fn hostile_key_derivation_settings_are_refused_before_any_work() {
        let (_, header) = pair();
        for (mem, time, lanes) in [
            (u32::MAX, 3u32, 4u32),
            (MAX_KDF_MEM_KIB + 1, 3, 4),
            (64, 0, 1),
            (64, MAX_KDF_TIME + 1, 1),
            (64, 1, 0),
            (64, 1, MAX_KDF_LANES + 1),
            (7, 1, 1),
        ] {
            let mut h = header;
            h[12..16].copy_from_slice(&mem.to_le_bytes());
            h[16..20].copy_from_slice(&time.to_le_bytes());
            h[20..24].copy_from_slice(&lanes.to_le_bytes());
            let crc = crc32fast::hash(&h[..ENC_HEADER_LEN - 4]);
            h[ENC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
            let start = std::time::Instant::now();
            assert!(
                matches!(Cipher::open(&h, "correct horse"), Err(Error::Corrupt(_))),
                "{mem} {time} {lanes}"
            );
            assert!(start.elapsed().as_secs() < 2, "refusing must not take work");
        }
        assert!(
            Cipher::create(
                "x",
                KdfParams {
                    mem_kib: 1,
                    time: 1,
                    lanes: 1
                }
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_methods_are_unsupported_not_corrupt() {
        let (_, mut h) = pair();
        h[9] = 9;
        let crc = crc32fast::hash(&h[..ENC_HEADER_LEN - 4]);
        h[ENC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(Cipher::open(&h, "correct horse"), Err(Error::Unsupported(_))));
        assert!(matches!(Cipher::open(b"short", "x"), Err(Error::Corrupt(_))));
    }

    #[test]
    fn header_fields_are_authenticated_through_the_associated_data() {
        let (c, header) = pair();
        let sealed = c.seal_block(0, 1, 9, b"abc").unwrap();
        // change a field that the key derivation does not depend on and fix the CRC: the header is still valid, the
        // password still checks out, but the block no longer opens
        let mut h = header;
        h[10] = 0xAA; // a reserved byte
        let crc = crc32fast::hash(&h[..ENC_HEADER_LEN - 4]);
        h[ENC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        let tampered = Cipher::open(&h, "correct horse").unwrap();
        assert!(tampered.open_block(0, 1, 9, &sealed).is_err());
    }
}
