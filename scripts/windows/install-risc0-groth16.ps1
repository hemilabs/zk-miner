# Install RISC Zero's `risc0-groth16` component on Windows, where rzup does not run.
#
# Every risc0 proof ends in a Groth16 wrap, which needs this component's files (~5.3 GB
# unpacked). On Linux, `rzup install risc0-groth16` provides them. This does what rzup does
# for that component: read its distribution manifest, download the archive the manifest names
# by SHA-256, check the hash, and unpack it where rzup would, which is where the prover looks:
#
#     $env:RISC0_HOME (default ~\.risc0) \extensions\v<version>-risc0-groth16
#
# Unlike rzup, this does not check the manifest's signature; the archive is checked against
# the hash the manifest (fetched over HTTPS) names.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\install-risc0-groth16.ps1

param([string]$Version = '0.1.0')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is far slower with it

$base = 'https://risc0-artifacts.s3.us-west-2.amazonaws.com/rzup/components/risc0-groth16'
$risc0Home = if ($env:RISC0_HOME) { $env:RISC0_HOME } else { Join-Path $env:USERPROFILE '.risc0' }
$dest = Join-Path $risc0Home "extensions\v$Version-risc0-groth16"
if (Test-Path $dest) {
    Write-Host "Already installed: $dest"
    exit 0
}

$manifest = Invoke-RestMethod "$base/distribution_manifest.json"
$release = $manifest.releases.$Version
if (-not $release) { throw "risc0-groth16 $Version is not in the distribution manifest" }
$sha256 = @($release.target_agnostic.artifact.sha256_blobs)
if ($sha256.Count -ne 1) { throw "expected one artifact for $Version, found $($sha256.Count)" }
$sha256 = $sha256[0]

$work = Join-Path ([IO.Path]::GetTempPath()) "risc0-groth16-$Version-$PID"
New-Item -ItemType Directory $work | Out-Null
try {
    $archive = Join-Path $work 'risc0-groth16.tar.xz'
    Write-Host "Downloading risc0-groth16 $Version (~2.3 GB)..."
    Invoke-WebRequest "$base/sha256/$sha256" -OutFile $archive
    $actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $sha256) { throw "SHA-256 mismatch: expected $sha256, got $actual" }

    # Unpacked beside the archive, then moved into place, so an interrupted run never
    # leaves a partial directory where the prover would take it for a complete one.
    $staging = Join-Path $work 'unpacked'
    New-Item -ItemType Directory $staging | Out-Null
    tar -xf $archive -C $staging
    if ($LASTEXITCODE -ne 0) { throw "tar failed with exit code $LASTEXITCODE" }
    New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
    Move-Item $staging $dest
    Write-Host "Installed: $dest"
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
