# Recovery data in ordinary ZIP files

`packrat-cli create out.zip files... --format zip --recovery 5` makes a normal ZIP file with Reed-Solomon recovery
data added. It is meant for people who have to hand an archive to someone who does not use Packrat: WinRAR, 7-Zip,
Windows Explorer, Python and every other ZIP reader open it, and only Packrat uses the extra data to repair it.

## What this is, and what it is not

- It is **not** the `.prat` format. A ZIP cannot hold deduplicated data, and `.prat` features (deduplication, one
  block per read, BLAKE3 everywhere) stay in `.prat` (see `PRAT_FORMAT.md`). What a ZIP gets is the part of `.prat`
  that does not depend on the container: repairable damage.
- It does not change how the files are stored. Compression, AES encryption and names are whatever the ZIP writer
  produced; the recovery data is added afterwards and works for any method.

## Layout

A ZIP is read from its end: the end-of-central-directory record (EOCD) says where the central directory is, and the
directory says where each local header is. Nothing reads the bytes between the last file and the directory, so the
recovery section is placed there and the directory moves back by the size of the section:

```
[ file data ... ][ HeaderA | tail copy | TableA | TableB | parity | HeaderB ][ central directory ... EOCD ]
  protected                  recovery section                                 tail (offsets moved)
```

- **Protected bytes**: everything in front of the section (local headers and data, and anything before them such as
  a self-extractor stub). They are cut into equal shards (4 to 64 KiB, see `PRAT_FORMAT.md` for the sizing) and
  `M` parity shards are computed, `M` being the requested percentage of the shard count, rounded up. Any `M` damaged
  shards can be rebuilt.
- **Header** (80 bytes, two copies): magic `PRATZRC\x01`, version, shard size, `K`, `M`, protected length, length and
  CRC-32 of the tail, CRC-32 of the header. Header A sits where the protected bytes end, header B immediately in
  front of the central directory.
- **Tail copy**: the original central directory and end records, as they were before the section was inserted.
- **Tables** (two copies): a CRC-32 for every data shard and every parity shard, and a CRC-32 of the table.
- Only the end records change when the section is inserted: the offset of the central directory in the EOCD, and for
  ZIP64 archives the offset in the ZIP64 locator and in the ZIP64 end record. Entries point at local headers, and
  those do not move. A plain ZIP that would cross 4 GiB because of the section is refused with a message that asks
  for ZIP64.

## Compatibility

Checked: 7-Zip (`7z t`, no warning), Python `zipfile`, and .NET `System.IO.Compression.ZipFile` (the basis of
PowerShell's `Expand-Archive`) all read such a file; sections of 1 KB and of 70 KB were tried as well as real ones.
WinRAR was **not** tested (it is not installed here); it reads ZIP files through the central directory like the
readers above, so it should behave the same, but that is an expectation, not a result.

## Repair

`packrat-cli repair archive.zip` writes `archive.repaired.zip` next to it and never modifies the original. It finds
the section through the end records, or, if they are damaged, by scanning for a header (a candidate counts only if
its numbers agree with where it sits and with the length of the file). It checks every shard against its CRC,
rebuilds the damaged ones from as many intact parity shards, and then regenerates everything after the protected
bytes (section and moved directory) from the repaired shards and the tail copy. The result is byte-for-byte the file
that was written. The tail can come from either copy: the one inside the section, or the live directory moved back
to its old offsets.

Limits: the damage must not exceed what the parity covers; both headers and the end records together being gone,
or both copies of a table and the tail, cannot be recovered; archives above 3 GiB are refused because repair holds
the protected bytes and the decoder's work area in memory.
