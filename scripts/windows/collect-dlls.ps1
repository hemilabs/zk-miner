# Copy the DLLs a set of Windows binaries need beside them, so they run on a machine with only
# the GPU driver installed: no CUDA, HIP SDK or oneAPI install, and no Visual C++ redistributable.
#
# Walks each binary's imports (normal and delay-loaded, from dumpbin) and, for each DLL:
#   - an API set (api-ms-*, ext-ms-*) or a driver's own DLL (-DriverDlls) is left alone;
#   - one found in -SearchDirs (in order: the toolkits' bin directories, the MSVC runtime's
#     redist directory) is copied to -Dest and walked in turn. A toolkit's copy wins over one
#     already in System32, so the shipped runtime is the one the build was made against;
#   - one only in System32 is an OS DLL and is left alone;
#   - anything else fails the run: the package would need something the user does not have.
# -Also names DLLs that are loaded at run time by name, so no import table shows them (SYCL's
# Unified Runtime adapters, say). They are copied and walked like the rest.
#
# -RedistList names a vendor's list of redistributable files (oneAPI's credist.txt): a DLL taken
# from the directory it covers (-RedistDir) must be on it, as `<installdir>/bin/<name>`.
#
# Prints each DLL with where it came from, which is the package's DLL resolution record.
#
# Usage:
#   collect-dlls.ps1 -Binaries a.exe,b.dll -SearchDirs dir1,dir2 -Dest out [-Also x.dll] [-DriverDlls y.dll]

param(
    [Parameter(Mandatory)][string[]]$Binaries,
    [Parameter(Mandatory)][string[]]$SearchDirs,
    [Parameter(Mandatory)][string]$Dest,
    [string[]]$Also = @(),
    # Provided by the GPU drivers: the NVIDIA driver API, the Level Zero loader the Intel driver
    # installs, and the OpenCL ICD loader.
    [string[]]$DriverDlls = @('nvcuda.dll', 'nvml.dll', 'ze_loader.dll', 'OpenCL.dll'),
    [string]$RedistList = '',
    [string]$RedistDir = ''
)
$ErrorActionPreference = 'Stop'

$dumpbin = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe' | Select-Object -First 1
if (-not $dumpbin) { throw 'dumpbin.exe not found (Visual Studio C++ tools)' }

$system32 = Join-Path $env:SystemRoot 'System32'
$driver = @{}
foreach ($d in $DriverDlls) { $driver[$d.ToLowerInvariant()] = $true }

function Get-Imports([string]$path) {
    $out = & $dumpbin /nologo /dependents $path
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed on $path" }
    $out | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[\w.+-]+\.dll$' }
}

$redist = @{}
if ($RedistList) {
    Get-Content $RedistList | ForEach-Object {
        if ($_ -match '^<installdir>/bin/([^/]+\.dll)\s*$') { $redist[$Matches[1].ToLowerInvariant()] = $true }
    }
    if ($redist.Count -eq 0) { throw "$RedistList lists no DLLs" }
}
$notRedist = @()
function Copy-Dll([string]$from, [string]$name) {
    $dir = (Split-Path $from -Parent).TrimEnd('\')
    if ($RedistList -and $dir -eq $RedistDir.TrimEnd('\') -and -not $redist[$name.ToLowerInvariant()]) {
        $script:notRedist += $name
    }
    Copy-Item -LiteralPath $from (Join-Path $Dest $name) -Force
    "{0,-40} {1}" -f $name, $from
}

function Find-Dll([string]$name) {
    foreach ($dir in $SearchDirs) {
        $candidate = Join-Path $dir $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

New-Item -ItemType Directory -Force $Dest | Out-Null
$seen = @{}
$queue = [System.Collections.Generic.Queue[string]]::new()
foreach ($b in $Binaries) {
    $full = (Resolve-Path -LiteralPath $b).Path
    $seen[(Split-Path $full -Leaf).ToLowerInvariant()] = $true
    $queue.Enqueue($full)
}
foreach ($name in $Also) {
    $from = Find-Dll $name
    if (-not $from) { throw "$name (-Also) is in none of the search directories" }
    $key = $name.ToLowerInvariant()
    if (-not $seen[$key]) {
        $seen[$key] = $true
        Copy-Dll $from $name
        $queue.Enqueue($from)
    }
}

$missing = @()
while ($queue.Count -gt 0) {
    $bin = $queue.Dequeue()
    foreach ($name in Get-Imports $bin) {
        $key = $name.ToLowerInvariant()
        if ($seen[$key]) { continue }
        $seen[$key] = $true
        if ($key -like 'api-ms-*' -or $key -like 'ext-ms-*') { continue }
        if ($driver[$key]) { "{0,-40} (driver)" -f $name; continue }
        $from = Find-Dll $name
        if ($from) {
            Copy-Dll $from $name
            $queue.Enqueue($from)
        } elseif (Test-Path -LiteralPath (Join-Path $system32 $name) -PathType Leaf) {
            # An OS DLL; not walked.
        } else {
            $missing += "$name (needed by $(Split-Path $bin -Leaf))"
        }
    }
}
if ($notRedist) { throw "not on $RedistList, so not redistributable: $($notRedist -join ', ')" }
if ($missing) { throw "not found in the search directories or System32: $($missing -join ', ')" }
