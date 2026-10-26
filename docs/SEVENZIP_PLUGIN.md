# The 7-Zip plugin (`packrat7z.dll`)

7-Zip can load format handlers from the `Formats` folder next to its `7z.dll`. `packrat7z.dll` is such a handler for
`.prat` archives (see `PRAT_FORMAT.md`): with it, 7-Zip, 7-Zip File Manager and `7z.exe` list, test and extract
Packrat archives, including archives that carry recovery data. It only reads: creating and repairing `.prat` stays
in Packrat.

## Install

```
cargo build --release -p packrat-7zip-plugin            # target\release\packrat7z.dll
powershell -File scripts\install_7zip_plugin.ps1        # elevated: copies it into "7-Zip\Formats"
7z i                                                     # the format list must now contain "Packrat  prat"
```

`-Uninstall` removes it again. The DLL is 64-bit and needs the 64-bit 7-Zip. It was developed against 7-Zip 26.01.
Nothing else of 7-Zip is touched.

## What it does

7-Zip finds the handler by the extension `prat` and by the signature `PRAT\r\n\x1a\n` at offset 0. The plugin gives
7-Zip the path, size, directory flag, modification time, attributes and method of every entry, and answers
`Extract` by decoding the blocks an entry lives in (through the same code Packrat uses) and writing the bytes to the
output streams 7-Zip provides. Test mode decodes and verifies without writing. Damage in a block is reported to
7-Zip as a data error for the files that use that block only.

**Passwords.** An encrypted `.prat` opens in 7-Zip the way an encrypted 7z does: the plugin asks 7-Zip's open callback for
the password (`ICryptoGetTextPassword`), so 7-Zip shows its password box, or uses `-p` on the command line. A wrong
password gives "Cannot open encrypted archive. Wrong password?", cancelling the box aborts, and the file list shows
the files as encrypted with the method `PRAT+AEAD`.

Packrat's own safety checks (the archive-bomb heuristics, sanitised names) are part of Packrat's extraction, not of
this plugin: 7-Zip makes its own decisions about names and writing. What the plugin does guarantee is that a hostile
file cannot make it allocate more than one 256 MiB block at a time, and that nothing it is given can make it panic
across the boundary (panics are caught and returned as an error code).

## How it is built

The plugin implements the COM-style interfaces from 7-Zip's `CPP/7zip/Archive/IArchive.h` by hand (function-pointer
tables that start with `QueryInterface`, `AddRef`, `Release`): `IInArchive` for 7-Zip to call, and the `IInStream`,
`IArchiveExtractCallback` and `ISequentialOutStream` objects 7-Zip passes in, which the plugin calls. The exports are
`CreateObject`, `GetNumberOfFormats`, `GetHandlerProperty` and `GetHandlerProperty2`.

One thing worth knowing if you change it: while an extraction is running, 7-Zip's callback calls back into the same
archive object (`GetProperty` for the item's path), so no lock may be held across a call into 7-Zip. A version that
did hung `7z t` and `7z x` forever; `tests/protocol.rs` has a test for exactly that, with a watchdog.

## Tests

- `crates/sevenzip-plugin/tests/protocol.rs` drives the plugin with stand-ins for 7-Zip's objects: handler
  description, creating only the right class, listing, full and partial extraction, test mode, damage, things that are
  not archives, reference counting of the stream, `QueryInterface`. It needs no 7-Zip.
- The password tests use a stand-in for the open callback: the right password opens the archive (the callback is asked
  once and the interface is released), a wrong one, a cancelled box, no callback and a callback without the password
  interface all leave the archive closed with the proper code.
- By hand against a real 7-Zip (a copy of the installation with the DLL in `Formats`): `7z l`, `7z t` and `7z x` of an
  archive of 4044 files (783 folders) report "Everything is Ok", and every extracted file has the SHA-256 of its
  source, for an archive without and with recovery data; one file can be extracted by name; a damaged archive
  reports `Sub items Errors` and exit code 2; a file that merely has the extension reports "Cannot open the file as
  [Packrat] archive". An encrypted archive was checked the same way: `7z t` without a password asks for one, with a
  wrong `-p` says "Cannot open encrypted archive. Wrong password?", with the right one reports "Everything is Ok", and
  `7z x` gives files identical to the source; `7z l -slt` shows `Encrypted = +` and `Method = PRAT+AEAD` for the files.

## WinRAR

WinRAR has no way to load third-party formats, so it cannot open `.prat`. What it can open is a ZIP: see
`ZIP_RECOVERY.md` for a ZIP that carries Packrat recovery data and is still an ordinary ZIP.
