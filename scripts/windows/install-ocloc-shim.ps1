# Put scripts/windows/ocloc-shim in front of oneAPI's ocloc for the rest of a CI job: built, named
# ocloc.exe, first on PATH (GITHUB_PATH), with the real ocloc and the mode in its environment
# (GITHUB_ENV). See the shim's source for the modes. Run after install-toolkit.ps1 -Vendor intel,
# which puts the real ocloc on PATH.
#
# Usage: install-ocloc-shim.ps1 -Mode record|replay -Store <dir> [-Strict]

param(
    [Parameter(Mandatory)][ValidateSet('record', 'replay')][string]$Mode,
    [Parameter(Mandatory)][string]$Store,
    [switch]$Strict
)
$ErrorActionPreference = 'Stop'

$real = (Get-Command ocloc.exe -ErrorAction Stop).Source
$dir = Join-Path $env:RUNNER_TEMP 'ocloc-shim'
cargo build --release --manifest-path scripts\windows\ocloc-shim\Cargo.toml --target-dir "$dir\target"
if ($LASTEXITCODE -ne 0) { throw "building ocloc-shim failed" }
Copy-Item "$dir\target\release\ocloc-shim.exe" "$dir\ocloc.exe" -Force
New-Item -ItemType Directory -Force $Store | Out-Null

Add-Content $env:GITHUB_PATH $dir
Add-Content $env:GITHUB_ENV "ZKMINER_OCLOC_REAL=$real"
Add-Content $env:GITHUB_ENV "ZKMINER_OCLOC_MODE=$Mode"
Add-Content $env:GITHUB_ENV "ZKMINER_OCLOC_STORE=$Store"
if ($Strict) { Add-Content $env:GITHUB_ENV "ZKMINER_OCLOC_STRICT=1" }
"ocloc-shim ($Mode, store $Store) in front of $real"
if ($Mode -eq 'replay') {
    $n = @(Get-ChildItem $Store -Directory -ErrorAction SilentlyContinue).Count
    "$n device images to replay"
}
