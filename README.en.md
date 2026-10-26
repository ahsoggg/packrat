# Packrat

[English](README.en.md) · [Русский](README.md)

An archive manager for Windows (a replacement for 7-Zip + Bandizip + PeaZip): compression and extraction on all
cores, "smart" extraction without nested `Folder\Folder`, protection against hostile archives, correct names in old
ZIP files, passwords, and a preview of files right inside the archive. Written in Rust; the native code is the RAR
decoder (unrar), libzstd and the SIMD parts of BLAKE3 (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

![Archive window: tree, sizes, compression ratio and a code preview](docs/screenshots/02-archive-code.png)

*All screenshots were taken with made-up data (`Packrat.exe --demo`) — no real file names appear on them.*

## Features (version 0.6.0)

The items marked **new** are in the repository but not in a release yet.

- **Formats.** Read and write: ZIP (store, deflate, zstd) and TAR (including `.tar.gz`, `.tar.zst`, `.tar.xz`,
  `.tar.lz4`). Read: 7z (LZMA2, BZip2 and PPMd verified on 7-Zip archives, other methods through the library), single
  `.gz`, `.bz2`, `.xz`, `.zst`, `.lz4` files. Creating **7z** works too (LZMA2 with a dictionary that follows the level, BCJ filters for executables, already-packed files stored as they are, files sorted by type; `--no-filters`, `--dict-mb`, `--solid-mb`). **New:** Packrat's own `.prat` (below). Read only: **RAR** (all versions up to 5.x, passwords, volumes open from any
  part; through the unrar library), **CAB** (MSZIP, LZX, Quantum; single cabinet), **ISO 9660** (Joliet and Rock
  Ridge), **LZH/LHA**, **AR/DEB**, **CPIO** (including `.cpio.gz` and the like) and **RPM**. `.jar`, `.apk`, `.docx`,
  `.epub`, `.cbz` and similar files are ZIP and open the same way.
- **The `.prat` format (new).** Packrat's own archive, for what ZIP, 7z and RAR cannot do together: files are cut into
  content-defined chunks and identical chunks are stored once (copies, backups and versions of one project shrink a
  lot, and a few bytes inserted in front of a file do not make the rest "new"); data is packed into zstd blocks that
  still open one file without decoding everything before it; every block carries a BLAKE3 hash. Optional **password
  encryption** (Argon2id, XChaCha20-Poly1305; names, sizes and the index are encrypted too) and optional
  **recovery data** (Reed-Solomon) that rebuilds damaged areas. `packrat-cli create out.prat dir --format prat
  [--level N] [--recovery PCT] [--ask-password]`. Layout and security notes: [docs/PRAT_FORMAT.md](docs/PRAT_FORMAT.md).
  **7-Zip opens `.prat`** (list, test, extract, password prompt) once the plugin `packrat7z.dll` is in its `Formats`
  folder: [docs/SEVENZIP_PLUGIN.md](docs/SEVENZIP_PLUGIN.md). WinRAR cannot load third-party formats; for it, a ZIP with
  recovery data is the way (below).
- **All cores.** ZIP entries and blocks of large files are compressed in parallel (deflate in independent blocks
  like pigz, zstd and lz4 in independent frames, 7z in parallel LZMA2 blocks, xz in its own blocks). Independent ZIP
  entries are extracted in parallel. The thread count is configurable (`--threads N`, Settings). Measured speed-ups:
  [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
- **Smart Extract.** One top-level folder goes straight into the chosen folder (no `Folder\Folder`); a single file
  lands next to the archive; several loose items go into a new folder named after the archive. `./` entries and
  folders that differ only by letter case are handled correctly.
- **Convenient extraction from Explorer.** “Extract here” opens a compact progress window, then opens the folder and closes by itself; if something goes wrong the window stays with a report. Settings and the “Extract to…” window can move the archive to the Recycle Bin after a complete clean extraction (off by default; skipped files or errors keep the archive).
- **Nothing is overwritten without your decision.** Before extracting, a plan shows which files already exist: "skip"
  (the default), "replace" or "keep both" (`name (2).txt`).
- **Names in old ZIP files.** When an archive has no UTF-8 flag and no Unicode Path field, Packrat detects the name
  encoding (CP866, Windows-1251, CP437, Shift-JIS, GBK, Big5, EUC-KR) statistically and shows which one it chose. The
  "Name encoding" button opens a window with a preview of how the names look in any encoding; the choice is applied
  immediately. On the command line: `--encoding cp866`.
- **Protection against hostile archives.** Entries with `..`, absolute paths, drive letters, UNC paths, reserved
  names (`CON`, `NUL`, `COM1`…), NTFS alternate streams (`name:stream`, `::$DATA`), trailing dots or spaces are
  blocked; symbolic links are never created and writing through an existing link or junction is refused. Before
  extracting, Packrat checks for signs of an **archive bomb** and warns with "Cancel" / "Continue at my own risk":
  an excessive expansion ratio (an entry ≥ 250× from 64 MB up, the whole archive ≥ 150× from 1 GB up), more than
  50 GB in total, over a million entries, not enough free space (with a 256 MB reserve), **overlapping ZIP entries**
  (shared stored data), archives nested deeper than three levels. When the unpacked size is not known in advance
  (a bare `.gz` and the like), the limits are enforced while unpacking. No entry can produce more bytes than its
  header declares.
- **Passwords.** ZIP: AES-256 (WinZip AE-2) read and write; the old ZipCrypto is read-only and comes with a warning
  about its weakness. 7z: AES-256, including encrypted file names (read and write). `.prat`: XChaCha20-Poly1305 with a
  key from Argon2id (new). The password is never stored,
  never logged and never on the command line (CLI: `--ask-password`, `--password-file` or `PACKRAT_PASSWORD`).
  Compatibility with 7-Zip 26.01 was tested in both directions.
- **Explorer.** A "Packrat" menu for archives (open, extract here, extract to folder, test) and for any file (add to `.zip`, `.7z`, `.tar.zst`, custom name). A multi-selection (files or archives) opens one window: files go into one archive, archives are extracted one after another with a single summary. “Send to” → “Packrat — to archive” does the same. On Windows 11 the menu is under “Show more options”; Settings has a switch for the classic menu (undone by unticking, Explorer must restart). Associations for `.zip`, `.7z`, `.tar` and others are switched on and rolled back in Settings; no administrator rights needed.
- **Verify and repair.** "Test integrity" (CRC and SHA-256), `packrat-cli test`. A damaged or truncated ZIP is read from its local headers (`extract --repair`); partly extracted files are kept. On "access denied" you can retry as administrator.
  **New:** `--recovery PCT` adds Reed-Solomon recovery data to `.prat` and to ordinary **ZIP** files (a ZIP with it is
  still a normal ZIP that 7-Zip, Explorer and others open); `packrat-cli repair archive` writes a repaired copy that is
  byte-for-byte what was written, never touching the damaged original, and needs no password for encrypted `.prat`
  ([docs/ZIP_RECOVERY.md](docs/ZIP_RECOVERY.md)).
- **Preview without extracting.** Select a file and its content appears on the right: images (PNG, JPEG, GIF, BMP,
  WebP) as a thumbnail with a full-size view, text and code with syntax highlighting, a hex view for the rest. For
  ZIP only the needed entry is read (a test counts the bytes read); for TAR and solid 7z the archive is read up to the
  file, marked "may be slow", with a limit on how much may be skipped. Preview sizes are capped (text 256 KB, images
  16 MB, hex 4 KB).
- **Window.** Content tree (name, size, compression, date, method), sorting, multi-selection, extraction by button
  or by dragging the selection into Explorer, dropping an archive or files onto the window. Russian and English UI.
- **Command line.** `packrat-cli list | extract | create | test | repair`, `--smart`, `--threads N`, `--encoding`,
  `--accept-risks`, passwords. Unknown options are refused (`--password abc` is not taken for a file name).
- **Auto-update.** Once a day one request to `api.github.com`; an "Update" button, SHA-256 check against
  `SHA256SUMS.txt`, file replacement and restart; `Packrat.exe --update` does the same without a window. It can be
  turned off in Settings.
- **Diagnostics, demo.** A log and crash reports in `%APPDATA%\Packrat\logs`; `Packrat.exe --demo` shows the
  program with made-up data.

![Image preview inside an archive](docs/screenshots/03-preview-image.png)

![Choosing the name encoding of an old ZIP](docs/screenshots/04-encoding.png)

![Archive bomb warning](docs/screenshots/05-bomb-warning.png)

## Install

Download `Packrat-Setup.exe` from [Releases](https://github.com/ahsoggg-creator/packrat/releases/latest) and run
it. No administrator rights are needed: the program is installed to `%LOCALAPPDATA%\Programs\Packrat`, a Start
menu shortcut is added, and an "Apps & features" entry lets you uninstall it.

There is also a portable version — just `Packrat.exe`; it can be installed later from Settings. `packrat-cli.exe`
is the console version.

### Code signing

The release executables are **not signed**: SmartScreen may show an "unknown publisher" warning ("More info" →
"Run anyway"). To check that a file is intact and matches what was published, compare it with `SHA256SUMS.txt` from
the same release. The repository has scripts for signing with a self-signed certificate (`scripts\make_cert.ps1`,
`scripts\trust_cert.ps1`, `scripts\release.ps1`); the private key stays with the author, and `*.pfx` files are
excluded from git.

## Diagnostics and privacy

Packrat sends nothing anywhere except the update check on GitHub (once a day, can be turned off in Settings).
There is no telemetry. Stored locally:

- `%APPDATA%\Packrat\logs\packrat.log` — program events (rotated at 512 KB). Passwords, names of files inside
  archives and their contents are not logged; the user's profile folder is replaced with `%USERPROFILE%`;
- `%APPDATA%\Packrat\logs\crashes\crash-<time>.txt` — a crash report: version, panic location, stack and the log tail.

Settings → Diagnostics opens this folder or copies the diagnostic text to the clipboard.

## Build

Requires Rust (stable, edition 2024) and MSVC.

```powershell
cargo build --release            # target\release\Packrat.exe and packrat-cli.exe
cargo test --workspace --release
powershell -ExecutionPolicy Bypass -File scripts\release.ps1   # checks, build, dist\ with checksums
powershell -ExecutionPolicy Bypass -File scripts\bench.ps1     # speed measurements
```

Layout:

- `crates/core` — formats, smart extraction, safety checks, encodings, passwords, preview, tests (no UI);
- `crates/app` — egui GUI, installer, auto-update, diagnostics, demo mode;
- `crates/cli` — `packrat-cli`;
- `crates/sevenzip-plugin` — `packrat7z.dll`, the 7-Zip plugin for `.prat` (`scripts\install_7zip_plugin.ps1` installs it);
- `scripts/` — release build, measurements, certificate; `docs/` — measurements, release notes, screenshots.

The same exe is an installer when it is named `Packrat-Setup.exe` (or started with `--install`) and an
uninstaller with `--uninstall`. To regenerate the screenshots (made-up data, nothing real is read or written):

```powershell
Packrat.exe --screenshots docs\screenshots
```

## Limitations

- RAR is read only (the unrar license does not allow creating it); a RAR inside another archive has to be extracted first. Multi-file CAB sets, ISO files over 4 GiB, UDF images and the legacy `.Z` and `.lzma` are not supported. ZIP methods deflate64, bzip2 and LZMA cannot be read.
- Encoding detection is statistical and was verified on generated names (Russian in CP866 and CP1251, Japanese,
  Chinese, Korean); on short or mixed names it can be wrong — then choose the encoding by hand. ZIP only: names in
  TAR and 7z are read as UTF-8.
- The bomb thresholds are heuristic: an honest archive with a huge ratio triggers a warning (which you can accept),
  while a bomb tuned to the thresholds passes without one — but no path can leave the destination folder and no entry
  can produce more bytes than declared.
- ZIP AES: AES-256 is verified (what 7-Zip and Packrat write); reading AES-128/192 is implemented but not tested.
  ZipCrypto passwords are taken as UTF-8; only ASCII was tested. TAR cannot be encrypted.
- zstd compression uses libzstd (levels 1–9 of the slider, up to zstd 19); decoding is pure Rust (`ruzstd`).
- The listing of `.tar.*` files is built with one pass over the whole archive; for big archives it is not instant.
  7z is created with LZMA2 only (plus BCJ and copy for parts of the data); on large source trees its size is a few percent above 7-Zip's at the same level. `.tar.lz4` files do not open in stock 7-Zip (it has no LZ4).
- Preview: images over 16 MB and files more than 256 MB into a streaming archive are not shown (extraction is
  suggested instead). Highlighting uses syntect's default language set.
- Dragging files from the window into Explorer: the data object is covered by a test, but the mouse gesture itself
  has not been verified automatically on a real system.
- The Explorer menu and associations were checked in an isolated registry hive, not in a live Explorer. A damaged ZIP without recovery data is read from its local headers; with Packrat's recovery data (ZIP and `.prat`) it is rebuilt exactly, up to the amount of recovery data. The GUI creates `.prat` and recovery data, but repair is a command-line action (`packrat-cli repair`).

- `.prat` is new: only Packrat and the 7-Zip plugin read it (the plugin is read-only and 64-bit, tested with 7-Zip 26.01),
  there are no multi-volume archives, blocks are zstd only, and the encryption has not been audited by anyone but
  its tests ([docs/PRAT_FORMAT.md](docs/PRAT_FORMAT.md) describes what it protects and what stays visible). A ZIP with
  recovery data was checked with 7-Zip, Python and .NET; WinRAR was not available for a test.

## License

At your option:

- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))
