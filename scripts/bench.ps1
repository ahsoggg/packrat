# Measures compression and extraction speed with 1 thread and with all cores, and compares with 7-Zip when it is installed.
#
#   powershell -ExecutionPolicy Bypass -File scripts\bench.ps1                 # 800 MB data set, 3 runs
#   powershell -ExecutionPolicy Bypass -File scripts\bench.ps1 -SizeMb 300 -Runs 2
#   powershell -ExecutionPolicy Bypass -File scripts\bench.ps1 -Corpus "C:\Program Files\7-Zip" -Runs 1 -Extended
#
# -Corpus uses a real folder instead of the generated data set (the folder is only read, never changed).
# -Extended adds more levels (zstd 6/9, 7z 1/9) and the matching 7-Zip settings.
# Results go to the console and to docs\bench-results.json; docs\BENCHMARKS.md describes the method.
param(
    [int]$SizeMb = 800,
    [int]$Runs = 3,
    [string]$Work = (Join-Path $env:TEMP "packrat-bench"),
    [string]$Json = "",
    [string]$Corpus = "",
    [switch]$Extended
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if ($Json -eq "") { $Json = Join-Path $root "docs\bench-results.json" }

cargo build --release -p packrat-cli
if ($LASTEXITCODE -ne 0) { throw "build failed" }
$cli = Join-Path $root "target\release\packrat-cli.exe"
$seven = "C:\Program Files\7-Zip\7z.exe"
$haveSeven = Test-Path $seven

$data = Join-Path $Work "data"
$out = Join-Path $Work "out"
if (Test-Path $Work) { Remove-Item -LiteralPath $Work -Recurse -Force }
New-Item -ItemType Directory $Work, $out | Out-Null
if ($Corpus -ne "") {
    $data = (Resolve-Path -LiteralPath $Corpus).Path
} else {
    & $cli bench-gen $data --mb $SizeMb | Out-Null
}

$files = Get-ChildItem $data -Recurse -File
$srcCount = $files.Count
$srcBytes = ($files | Measure-Object Length -Sum).Sum
$cores = [Environment]::ProcessorCount

function Median([double[]]$v) { $s = $v | Sort-Object; $s[[int][math]::Floor(($s.Count - 1) / 2)] }

function TimeIt([scriptblock]$block) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $block | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "command failed ($LASTEXITCODE)" }
    $sw.Stop()
    $sw.Elapsed.TotalSeconds
}

function TreeStats($dir) {
    $f = Get-ChildItem $dir -Recurse -File
    "{0}/{1}" -f $f.Count, ($f | Measure-Object Length -Sum).Sum
}
$expected = "{0}/{1}" -f $srcCount, $srcBytes

# name, archive file, create block, extract block
$creates = @(
    @{ Name = "zip deflate, 1 thread";   File = "z1.zip";    Cmd = { & $cli create (Join-Path $out "z1.zip") $data --format zip --threads 1 } },
    @{ Name = "zip deflate, all cores";  File = "zn.zip";    Cmd = { & $cli create (Join-Path $out "zn.zip") $data --format zip --threads 0 } },
    @{ Name = "zip zstd, 1 thread";      File = "zs1.zip";   Cmd = { & $cli create (Join-Path $out "zs1.zip") $data --format zip-zstd --threads 1 } },
    @{ Name = "zip zstd, all cores";     File = "zsn.zip";   Cmd = { & $cli create (Join-Path $out "zsn.zip") $data --format zip-zstd --threads 0 } },
    @{ Name = "tar.zst, 1 thread";       File = "t1.tar.zst"; Cmd = { & $cli create (Join-Path $out "t1.tar.zst") $data --format tar.zst --threads 1 } },
    @{ Name = "tar.zst, all cores";      File = "tn.tar.zst"; Cmd = { & $cli create (Join-Path $out "tn.tar.zst") $data --format tar.zst --threads 0 } },
    @{ Name = "7z LZMA2, 1 thread";      File = "s1.7z";     Cmd = { & $cli create (Join-Path $out "s1.7z") $data --format 7z --threads 1 } },
    @{ Name = "7z LZMA2, all cores";     File = "sn.7z";     Cmd = { & $cli create (Join-Path $out "sn.7z") $data --format 7z --threads 0 } }
)
if ($Extended) {
    foreach ($l in 6, 9) {
        $creates += @{ Name = "zip zstd level $l, all cores"; File = "zsl$l.zip"; Cmd = [scriptblock]::Create("& '$cli' create '$out\zsl$l.zip' '$data' --format zip-zstd --level $l --threads 0") }
    }
    foreach ($l in 1, 9) {
        $creates += @{ Name = "7z LZMA2 level $l, all cores"; File = "sl$l.7z"; Cmd = [scriptblock]::Create("& '$cli' create '$out\sl$l.7z' '$data' --format 7z --level $l --threads 0") }
    }
    if ($haveSeven) {
        foreach ($l in 1, 9) {
            $creates += @{ Name = "7-Zip 7z mx$l, all cores"; File = "7s$l.7z"; Cmd = [scriptblock]::Create("& '$seven' a -t7z -mx=$l -mmt=on '$out\7s$l.7z' '$data'") }
        }
        $creates += @{ Name = "7-Zip 7z mx5, all cores"; File = "7s5.7z"; Cmd = { & $seven a -t7z -mx=5 -mmt=on (Join-Path $out "7s5.7z") $data } }
    }
}
if ($haveSeven) {
    $creates += @{ Name = "7-Zip zip deflate, 1 thread"; File = "7z1.zip"; Cmd = { & $seven a -tzip -mx=5 -mmt=1 (Join-Path $out "7z1.zip") $data } }
    $creates += @{ Name = "7-Zip zip deflate, all cores"; File = "7zn.zip"; Cmd = { & $seven a -tzip -mx=5 -mmt=on (Join-Path $out "7zn.zip") $data } }
}

$results = @()
$times = @{}
for ($run = 1; $run -le $Runs; $run++) {
    foreach ($c in $creates) {
        $path = Join-Path $out $c.File
        if (Test-Path $path) { Remove-Item $path -Force }
        $t = TimeIt $c.Cmd
        if (-not $times.ContainsKey($c.Name)) { $times[$c.Name] = @() }
        $times[$c.Name] += $t
        Write-Host ("run {0}: create {1,-32} {2,7:N2} s  {3,12:N0} bytes" -f $run, $c.Name, $t, (Get-Item $path).Length)
    }
}
foreach ($c in $creates) {
    $size = (Get-Item (Join-Path $out $c.File)).Length
    $results += [pscustomobject]@{ Operation = "create"; Name = $c.Name; Seconds = [math]::Round((Median $times[$c.Name]), 2); Runs = $Runs; ArchiveBytes = $size }
}

# extraction: archives made by Packrat, extracted by Packrat (1 thread / all cores) and by 7-Zip
$extracts = @(
    @{ Name = "extract zip deflate, 1 thread";  File = "zn.zip";     Dir = "x1"; Cmd = { param($d) & $cli extract (Join-Path $out "zn.zip") -o $d --threads 1 } },
    @{ Name = "extract zip deflate, all cores"; File = "zn.zip";     Dir = "xn"; Cmd = { param($d) & $cli extract (Join-Path $out "zn.zip") -o $d --threads 0 } },
    @{ Name = "extract zip zstd, 1 thread";     File = "zsn.zip";    Dir = "xs1"; Cmd = { param($d) & $cli extract (Join-Path $out "zsn.zip") -o $d --threads 1 } },
    @{ Name = "extract zip zstd, all cores";    File = "zsn.zip";    Dir = "xsn"; Cmd = { param($d) & $cli extract (Join-Path $out "zsn.zip") -o $d --threads 0 } },
    @{ Name = "extract tar.zst (sequential)";   File = "tn.tar.zst"; Dir = "xt"; Cmd = { param($d) & $cli extract (Join-Path $out "tn.tar.zst") -o $d } },
    @{ Name = "extract 7z";                     File = "sn.7z";      Dir = "xs"; Cmd = { param($d) & $cli extract (Join-Path $out "sn.7z") -o $d } }
)
if ($haveSeven) {
    $extracts += @{ Name = "7-Zip extract zip, all cores"; File = "zn.zip"; Dir = "x7"; Cmd = { param($d) & $seven x (Join-Path $out "zn.zip") "-o$d" -y -mmt=on } }
}
$xtimes = @{}
$verified = @{}
for ($run = 1; $run -le $Runs; $run++) {
    foreach ($e in $extracts) {
        $d = Join-Path $Work $e.Dir
        if (Test-Path $d) { Remove-Item $d -Recurse -Force }
        New-Item -ItemType Directory $d | Out-Null
        $t = TimeIt { & $e.Cmd $d }
        if (-not $xtimes.ContainsKey($e.Name)) { $xtimes[$e.Name] = @() }
        $xtimes[$e.Name] += $t
        $stats = TreeStats $d
        $verified[$e.Name] = ($stats -eq $expected)
        if (-not $verified[$e.Name]) { Write-Warning "$($e.Name): got $stats, expected $expected" }
        Write-Host ("run {0}: {1,-34} {2,7:N2} s  {3}" -f $run, $e.Name, $t, $(if ($verified[$e.Name]) { "files and bytes match" } else { "MISMATCH" }))
        Remove-Item $d -Recurse -Force
    }
}
foreach ($e in $extracts) {
    $results += [pscustomobject]@{ Operation = "extract"; Name = $e.Name; Seconds = [math]::Round((Median $xtimes[$e.Name]), 2); Runs = $Runs; ArchiveBytes = (Get-Item (Join-Path $out $e.File)).Length }
}

$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
$mem = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$os = (Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).Version
$av = try { (Get-MpComputerStatus).RealTimeProtectionEnabled } catch { "unknown" }
$disk = try { (Get-PhysicalDisk | Where-Object { $Work.StartsWith($_.DeviceId) } | Select-Object -First 1).MediaType } catch { "" }
$info = [pscustomobject]@{
    Date = (Get-Date -Format "yyyy-MM-dd"); Cpu = $cpu; LogicalCores = $cores; MemoryGB = $mem; Os = $os
    DefenderRealTime = $av; WorkFolder = $Work; DataFiles = $srcCount; DataBytes = $srcBytes; SevenZip = $haveSeven
    AllVerified = -not ($verified.Values -contains $false)
}
[pscustomobject]@{ Machine = $info; Results = $results } | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 $Json
$results | Format-Table Operation, Name, Seconds, ArchiveBytes -AutoSize
$info | Format-List
Remove-Item $Work -Recurse -Force
Write-Host "saved $Json"
