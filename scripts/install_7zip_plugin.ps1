# Installs (or removes) the Packrat plugin for 7-Zip: packrat7z.dll goes into "7-Zip\Formats", after which 7-Zip,
# 7-Zip File Manager and `7z` list, test and extract .prat archives. Writing there needs an administrator.
#
#   powershell -File scripts\install_7zip_plugin.ps1                       # uses dist\packrat7z.dll or target\release\packrat7z.dll
#   powershell -File scripts\install_7zip_plugin.ps1 -DllPath C:\x\packrat7z.dll
#   powershell -File scripts\install_7zip_plugin.ps1 -SevenZipDir "D:\Tools\7-Zip"
#   powershell -File scripts\install_7zip_plugin.ps1 -Uninstall
#
# The plugin is 64-bit: it works with the 64-bit 7-Zip only.
param(
    [string]$DllPath = "",
    [string]$SevenZipDir = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if ($SevenZipDir -eq "") {
    foreach ($key in "HKLM:\SOFTWARE\7-Zip", "HKCU:\SOFTWARE\7-Zip") {
        $p = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).Path64
        if (-not $p) { $p = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).Path }
        if ($p -and (Test-Path -LiteralPath $p)) { $SevenZipDir = $p; break }
    }
}
if ($SevenZipDir -eq "" -or -not (Test-Path -LiteralPath (Join-Path $SevenZipDir "7z.dll"))) {
    throw "7-Zip was not found. Pass its folder with -SevenZipDir."
}
$formats = Join-Path $SevenZipDir "Formats"
$target = Join-Path $formats "packrat7z.dll"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this from an elevated PowerShell: $SevenZipDir is not writable for a normal user." }

if ($Uninstall) {
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force; Write-Host "removed $target" }
    else { Write-Host "nothing to remove: $target does not exist" }
    return
}

if ($DllPath -eq "") {
    foreach ($c in (Join-Path $root "dist\packrat7z.dll"), (Join-Path $root "target\release\packrat7z.dll")) {
        if (Test-Path -LiteralPath $c) { $DllPath = $c; break }
    }
}
if ($DllPath -eq "" -or -not (Test-Path -LiteralPath $DllPath)) {
    throw "packrat7z.dll was not found. Build it with `cargo build --release -p packrat-7zip-plugin` or pass -DllPath."
}
New-Item -ItemType Directory -Force $formats | Out-Null
Copy-Item -LiteralPath $DllPath -Destination $target -Force
Write-Host "installed $target"
Write-Host "check: & '$SevenZipDir\7z.exe' i   (the list of formats must contain 'Packrat  prat')"
