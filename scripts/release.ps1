# Builds the release artifacts into dist\:
#   Packrat-Setup.exe   the installer (the same executable; it installs itself when it is named *Setup*.exe)
#   Packrat.exe         the portable version (also what the updater downloads)
#   packrat-cli.exe     the command-line tool
#   packrat7z.dll       the 7-Zip plugin for .prat (scripts\install_7zip_plugin.ps1 puts it in 7-Zip\Formats)
#   packrat-sfx.exe     the stub of self-extracting archives (put next to packrat-cli.exe for `--sfx`)
#   SHA256SUMS.txt      checksums of the five files
#
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1                         # checks + build + dist\
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -Publish                # ... and `gh release create`
#   powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -Publish -NotesFile docs\RELEASE_NOTES.md
#
# If the self-signed certificate "CN=ahsoggg" exists in this user's store (scripts\make_cert.ps1), the executables are
# signed before the checksums are computed; otherwise they are released unsigned (and the notes say so).
param([switch]$Publish, [switch]$SkipChecks, [string]$NotesFile = "")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$tag = "v$version"
Write-Host "Packrat $tag"

if (-not $SkipChecks) {
    cargo fmt --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt --check failed" }
    cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "clippy failed" }
    cargo test --workspace --release
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$dist = Join-Path $root "dist"
if (Test-Path $dist) { Remove-Item -LiteralPath $dist -Recurse -Force }
New-Item -ItemType Directory $dist | Out-Null
Copy-Item target\release\Packrat.exe (Join-Path $dist "Packrat.exe")
Copy-Item target\release\packrat-cli.exe (Join-Path $dist "packrat-cli.exe")
Copy-Item target\release\packrat7z.dll (Join-Path $dist "packrat7z.dll")
Copy-Item target\release\packrat-sfx.exe (Join-Path $dist "packrat-sfx.exe")

$cert = $null
try { $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction Stop | Where-Object { $_.Subject -eq "CN=ahsoggg" } } catch { }
if ($cert) {
    & (Join-Path $PSScriptRoot "sign.ps1") (Join-Path $dist "Packrat.exe") (Join-Path $dist "packrat-cli.exe") (Join-Path $dist "packrat7z.dll") (Join-Path $dist "packrat-sfx.exe")
} else {
    Write-Warning "certificate CN=ahsoggg not found - releasing UNSIGNED (scripts\make_cert.ps1 creates it)"
}
Copy-Item (Join-Path $dist "Packrat.exe") (Join-Path $dist "Packrat-Setup.exe")

$lines = foreach ($f in "Packrat-Setup.exe", "Packrat.exe", "packrat-cli.exe", "packrat7z.dll", "packrat-sfx.exe") {
    $h = (Get-FileHash (Join-Path $dist $f) -Algorithm SHA256).Hash.ToLower()
    "$h  $f"
}
[IO.File]::WriteAllText((Join-Path $dist "SHA256SUMS.txt"), (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
Get-ChildItem $dist | Format-Table Name, Length
Get-Content (Join-Path $dist "SHA256SUMS.txt")

if ($Publish) {
    $assets = Get-ChildItem $dist | ForEach-Object { $_.FullName }
    if ($NotesFile -ne "") {
        gh release create $tag @assets --title "Packrat $version" --notes-file $NotesFile
    } else {
        gh release create $tag @assets --title "Packrat $version" --generate-notes
    }
    if ($LASTEXITCODE -ne 0) { throw "gh release failed" }
}
