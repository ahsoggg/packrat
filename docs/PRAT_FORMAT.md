# The `.prat` format, versions 1 and 2

`.prat` is Packrat's own archive format. It exists for what ZIP, 7z and RAR cannot do together: store repeated
data once, open a single file without decoding everything before it, and detect any damaged byte.

All integers are little-endian. "Hash" is BLAKE3 (32 bytes). A *varint* is LEB128 (7 bits per byte, low bits
first); a *zigzag varint* maps signed numbers to unsigned (`(n << 1) ^ (n >> 63)`).

## Layout

```
Header (16 bytes)
Block 0 .. Block N-1          each: block header (52 bytes) + payload
Index                         stored (zstd, or raw when that is not smaller)
Footer (68 bytes)
```

### Header

| offset | size | |
|---|---|---|
| 0 | 8 | magic `50 52 41 54 0D 0A 1A 0A` (`PRAT` then the PNG-style line-ending and EOF guards) |
| 8 | 2 | version (1) |
| 10 | 6 | reserved, zero |

Version 1 is a plain archive. Version 2 is an encrypted one (see *Encryption*): an older Packrat that knows only
version 1 refuses it with a message that says so instead of misreading ciphertext. A reader refuses any version it
does not know.

### Block

A block holds the bytes of many *chunks* back to back and is compressed as one unit. Each block can be decoded
on its own, so one file costs at most the blocks its chunks live in.

| offset | size | |
|---|---|---|
| 0 | 4 | sync `PrBk` |
| 4 | 1 | codec: 0 = stored, 1 = zstd |
| 5 | 3 | reserved |
| 8 | 4 | `clen`, payload length |
| 12 | 4 | `ulen`, uncompressed length (at most 256 MiB) |
| 16 | 32 | hash of the uncompressed data |
| 48 | 4 | CRC-32 of bytes 0..48 |

The payload follows. A writer stores a block raw when compression does not make it smaller. Because every block
header is complete and carries a sync marker and a CRC, an archive whose index is lost can still be scanned from
block to block.

### Footer

| offset | size | |
|---|---|---|
| 0 | 8 | `index_offset` |
| 8 | 8 | `index_clen`, stored index length |
| 16 | 8 | `index_ulen`, uncompressed index length (at most 512 MiB) |
| 24 | 32 | hash of the stored index bytes |
| 56 | 4 | CRC-32 of bytes 0..56 |
| 60 | 8 | magic `PRATEND\x01` |

A reader finds the footer at `file_len - 68`. If `index_clen == index_ulen` the index is raw, otherwise zstd
(a writer only compresses when the result is smaller, so the two cannot coincide).

### Index

```
"PIDX"
varint nblocks
  per block:  varint offset, varint clen, varint ulen, u8 codec
varint nchunks
  per chunk:  varint block, varint offset_in_block, varint len, hash[32]
varint nentries
  per entry:  u8 kind (0 file, 1 directory)
              varint path_len, path (UTF-8, '/' separators, no trailing slash)
              varint size
              u8 flags (bit 0: has mtime, bit 1: has mode)
              [zigzag varint mtime, Unix seconds]   if bit 0
              [varint mode]                         if bit 1
              varint nrefs, then nrefs zigzag varints: chunk ids, each as the difference from the previous id
```

A file is the concatenation of its chunks in order. Directories and empty files have no chunks.

## Deduplication

Files are cut with FastCDC (normalized, 2020 variant; minimum 16 KiB, average 64 KiB, maximum 256 KiB by
default). Files of at most the minimum size are one chunk. A chunk whose hash was seen before is not stored again:
the entry just refers to the existing chunk id. Because the cut points depend on the content, inserting bytes at
the front of a file leaves the chunks after the first few unchanged.

New chunks are appended to the block being built; when it reaches the block size (16 MiB by default, 1 to 128 MiB
with `--solid-mb`) it is compressed on a worker thread and a new one starts. Chunks stay in file order, so files
that belong together are compressed together.

## What a reader verifies

Everything read from a file is treated as hostile:

- the header magic and version; the footer's CRC and magic; the index hash before it is decoded;
- counts in the index cannot exceed the bytes that remain, every block lies inside the file, every chunk lies
  inside its block, every chunk id exists, and the size of each file equals the sum of its chunk lengths;
- a block header must agree with the index; the decoded size must equal `ulen` (the decoder is given exactly that
  much room, so a block cannot expand beyond it); the hash of the decoded data must match.

A damaged block makes the files that use it fail with a "corrupt" error. Files that live in other blocks are
unaffected.

## Reading cost

Opening an archive reads the header, the footer and the index. Extracting one file decodes the blocks that hold its
chunks. Decoded blocks are kept in a small cache shared by all threads; threads that need the same block wait for
one decode instead of repeating it.

## Encryption (version 2)

An archive made with a password is version 2. Right after the 16-byte file header comes the **encryption header**
(80 bytes), and the first block follows it.

| offset | size | |
|---|---|---|
| 0 | 8 | magic `PRATENC\x01` |
| 8 | 1 | key derivation: 1 = Argon2id (v1.3) |
| 9 | 1 | cipher: 1 = XChaCha20-Poly1305 |
| 12 | 4 | Argon2 memory in KiB |
| 16 | 4 | Argon2 passes |
| 20 | 4 | Argon2 lanes |
| 24 | 16 | salt (random) |
| 40 | 16 | nonce prefix (random) |
| 56 | 16 | password check |
| 76 | 4 | CRC-32 of bytes 0..76 |

**Keys.** `Argon2id(password as UTF-8, salt, memory, passes, lanes)` gives 32 bytes, from which four independent keys are
derived with BLAKE3 `derive_key` under four different context strings: blocks, index, block hashes, password check.
The password check is the first 16 bytes of the keyed BLAKE3 hash of a fixed string under the check key; it lets a
wrong password be told from a damaged archive. A reader refuses settings outside memory 8 KiB to 1 GiB (and at least
8 KiB per lane), 1 to 32 passes and 1 to 16 lanes *before* doing any work, so a hostile file cannot make opening it
expensive. The defaults are 64 MiB, 3 passes and 4 lanes.

**Sealing.** Blocks and the index are sealed with XChaCha20-Poly1305 after compression. The nonce is the 16-byte prefix
followed by the block number (the index uses the number 2^64 - 1, which no block has), so no nonce repeats within an
archive and the prefix is random per archive. The associated data is the BLAKE3 hash of the whole encryption header,
a kind byte (block or index), the block number, the codec and the uncompressed length. As a result a block cannot be
moved to another position, given another codec or size, or taken into another archive, and changing any field of the
encryption header (even one the key derivation ignores) makes every block fail.

**What changes in the rest of the format.**

- `clen` of a block is the length of the ciphertext, which is 16 bytes (the tag) longer than the compressed data.
- The 32-byte hash in the block header is a *keyed* BLAKE3 hash under the hash key. A plain hash of the plaintext would
  let anyone who has a candidate file confirm that it is in the archive.
- The stored index is the sealed index. After decryption it is compressed or raw as in version 1 (its length tells which).
  The footer's hash covers the sealed bytes, so it can be checked without the password. Names, sizes, times, chunk
  hashes and the file list are all inside the index, hence encrypted; a separate switch for hiding names does not exist.
- Recovery data (below) protects the ciphertext. Checking and repairing an archive therefore needs no password.

**What stays visible:** the size of the file, the number of blocks and their sizes and codec, the length of the index and
the encryption settings. Compression happens before encryption, so the size of a block reveals how well its content
compresses. Deduplication works as before, inside the encrypted index. There is no protection against someone replacing
the whole file with an older valid archive of yours, and nothing signs an archive: this is encryption with integrity,
not authorship.

## Recovery data (optional)

`--recovery PCT` appends Reed-Solomon recovery data between the index and the footer. It protects everything
before it (header, blocks, index): that region of `protected_len` bytes is cut into `K` equal shards (the last one
padded with zeros), `M` parity shards are computed (GF(2^16), `reed-solomon-simd`), and any `M` damaged shards can
be rebuilt. A shard is 4 KiB to 64 KiB for most archives (about 256 shards for a small one, 64 KiB beyond 16 MiB,
larger only if there would be more than 16384 shards); `M` is `PCT` percent of `K`, rounded up, at least 1.

```
HeaderA (104)   "PRATREC", u32 version (1), u32 shard size, u32 K, u32 M, u64 protected_len,
                a copy of the 68-byte footer, CRC-32 of the first 100 bytes
TableA          K CRC-32 values of the data shards, M of the parity shards, CRC-32 of the table
TableB          the same again
parity          M shards
HeaderB (104)   a copy of HeaderA, at a fixed distance (172 bytes) before the end of the file
```

The footer is unchanged, and `index_offset + index_clen` is where the section starts, so a reader that does not
know about recovery data skips it. To repair, `repair` finds the section through the footer, or through HeaderB, or
by scanning for the magic (a candidate counts only if its numbers agree with where it sits and the file's length);
it checks every data shard against its CRC, takes as many intact parity shards as there are damaged data shards,
rebuilds the damaged shards, verifies each against its CRC, and writes a **new file**; the damaged original is never
modified. Damaged tables, parity shards or headers are regenerated from the repaired data, a damaged footer is
rewritten from its copy, so the result is byte-for-byte the archive that was written. If more areas are damaged than
there are intact parity shards, nothing is written and the error says so.

Repair holds the protected bytes and the decoder's work area in memory; archives above 3 GiB are refused for that
reason.

## Not implemented yet

Planned as additions that older readers can tell apart (new codec ids, new flag bits, a version bump where the
layout changes):

- multi-volume archives;
- other block codecs (LZMA2) and filters (BCJ) per block;
- NTFS metadata (attributes, streams, ACLs) and links;
- rebuilding the index of an archive that has neither an index nor recovery data, by scanning the blocks.

## A note on ratios

An archive of many repeated files can legitimately expand by a factor far above what an ordinary archive does.
Packrat's "archive bomb" check looks at the ratio of unpacked data to archive size, so a very repetitive `.prat`
may ask for confirmation before extraction; that is the safe default.
