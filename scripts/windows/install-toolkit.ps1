# Install what a Windows CI job needs to build a zkminer worker or SP1 server, from the vendors'
# own downloads, each checked against the SHA-256 the workflow pins (build-windows.yml's env).
# Only GitHub-owned actions are allowed in this repo, so none of this comes from an action.
#
# -Vendor     nvidia | amd | intel | none
# -Components risc0 | sp1-worker | sp1-server
#
# Exports to later steps (GITHUB_ENV / GITHUB_PATH): the toolkit's variables, PROTOC, and
#   ZKMINER_RUNTIME_DIRS  where the runtime DLLs a build needs are found, for collect-dlls.ps1:
#                         the toolkit's bin directories, then the MSVC runtime's redist directory
#   ZKMINER_RUNTIME_ALSO  DLLs loaded by name at run time, which no import table lists
#   ZKMINER_LICENSES      the terms the shipped runtime DLLs are redistributed under
#   ZKMINER_REDIST_LIST   (Intel) the vendor's list of redistributable files, which every DLL
#   ZKMINER_REDIST_DIR    taken from its toolkit directory must be on (collect-dlls.ps1)

param(
    [Parameter(Mandatory)][ValidateSet('nvidia', 'amd', 'intel', 'none')][string]$Vendor,
    [Parameter(Mandatory)][ValidateSet('risc0', 'sp1-worker', 'sp1-server')][string]$Components
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is far slower with it

function Get-Verified([string]$Url, [string]$Sha256, [string]$Out) {
    Invoke-WebRequest $Url -OutFile $Out
    $actual = (Get-FileHash $Out -Algorithm SHA256).Hash
    if ($actual -ne $Sha256) { throw "$Url`: SHA-256 $actual, expected $Sha256" }
}
function Set-Env([string]$Name, [string]$Value) {
    Set-Item "env:$Name" $Value
    Add-Content $env:GITHUB_ENV "$Name=$Value"
}
function Add-Path([string]$Dir) {
    $env:PATH = "$Dir;$env:PATH"
    Add-Content $env:GITHUB_PATH $Dir
}

$tmp = $env:RUNNER_TEMP
$runtimeDirs = @()
$runtimeAlso = @()
$licenses = @()

# protoc: risc0-groth16's witness generator and the SP1 SDK compile protobufs.
Get-Verified "https://github.com/protocolbuffers/protobuf/releases/download/v$env:PROTOC_VERSION/protoc-$env:PROTOC_VERSION-win64.zip" `
    $env:PROTOC_SHA256 "$tmp\protoc.zip"
Expand-Archive "$tmp\protoc.zip" "$tmp\protoc"
Set-Env PROTOC "$tmp\protoc\bin\protoc.exe"

switch ($Vendor) {
    'nvidia' {
        # NVIDIA's network installer, limited to what the builds use; it downloads NVIDIA's signed
        # component packages itself.
        $version = $env:CUDA_VERSION
        $short = ($version -split '\.')[0..1] -join '.'
        Get-Verified "https://developer.download.nvidia.com/compute/cuda/$version/network_installers/cuda_${version}_windows_network.exe" `
            $env:CUDA_INSTALLER_SHA256 "$tmp\cuda_network.exe"
        $packages = 'nvcc', 'cudart', 'thrust', 'nvtx', 'cuobjdump', 'visual_studio_integration' |
            ForEach-Object { "${_}_$short" }
        $proc = Start-Process "$tmp\cuda_network.exe" -ArgumentList (@('-s') + $packages) -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw "CUDA installer exited with $($proc.ExitCode)" }
        $root = "$env:ProgramFiles\NVIDIA GPU Computing Toolkit\CUDA\v$short"
        if (-not (Test-Path "$root\bin\nvcc.exe")) { throw "nvcc not found under $root" }
        Set-Env CUDA_PATH $root
        # sppark resolves nvcc itself rather than through PATH.
        Set-Env NVCC "$root\bin\nvcc.exe"
        Set-Env CUDACXX "$root\bin\nvcc.exe"
        Add-Path "$root\bin"
        $runtimeDirs += "$root\bin"
        # The CUDA runtime is linked statically (Attachment A of the EULA lists it).
        $licenses += "$root\LICENSE"
    }
    'amd' {
        # The HIP SDK's packages (the compiler and runtime; hiprtc; the header-only hipCUB and
        # rocPRIM the SP1 server uses), unpacked from AMD's installer (a 7-Zip self-extractor) and
        # administratively from their MSIs: AMD's setup program itself targets Windows 10/11 and
        # would install a display driver, neither of which a build needs.
        Get-Verified $env:HIP_SDK_URL $env:HIP_SDK_SHA256 "$tmp\hip-sdk.exe"
        $msis = "$tmp\hip-msi"
        & "$env:ProgramFiles\7-Zip\7z.exe" e -y "-o$msis" "$tmp\hip-sdk.exe" `
            'Packages\Apps\ROCmSDKPackages\SDKCore\ROCm_SDK_Core.msi' `
            'Packages\Apps\ROCmSDKPackages\RTCRuntime\ROCm_RTC_RT.msi' `
            'Packages\Apps\ROCmSDKPackages\RTCDevelopment\ROCm_RTC_Dev.msi' `
            'Packages\Apps\ROCmSDKPackages\LibrariesDevelopment\ROCm_Libs_Dev.msi' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "7z exited with $LASTEXITCODE" }
        $unpacked = 'C:\hip-sdk'
        foreach ($msi in Get-ChildItem "$msis\*.msi") {
            $proc = Start-Process msiexec.exe -ArgumentList "/a `"$($msi.FullName)`" /qn TARGETDIR=`"$unpacked`"" -Wait -PassThru
            if ($proc.ExitCode -ne 0) { throw "msiexec /a $($msi.Name) exited with $($proc.ExitCode)" }
        }
        $root = "$unpacked\PFiles64\AMD\ROCm\$env:HIP_SDK_VERSION"
        if (-not (Test-Path "$root\bin\hipcc.exe")) { throw "hipcc not found under $root" }
        Set-Env HIP_PATH $root
        Set-Env ROCM_PATH $root
        Set-Env HIPCC "$root\bin\hipcc.exe"
        Add-Path "$root\bin"
        $runtimeDirs += "$root\bin"
    }
    'intel' {
        # The oneAPI toolkit's offline installer, silently, with only the DPC++/C++ compiler and
        # ocloc (ahead-of-time compilation for Intel GPUs), and tcm, whose hwloc the SYCL runtime's
        # memory manager (UMF) loads.
        Get-Verified $env:ONEAPI_URL $env:ONEAPI_SHA256 "$tmp\oneapi.exe"
        $proc = Start-Process "$tmp\oneapi.exe" -ArgumentList @(
            '-s', '-a', '--silent', '--eula', 'accept',
            '--components', 'intel.oneapi.win.cpp-dpcpp-common:intel.oneapi.win.ocloc:intel.oneapi.win.tcm',
            '-p=NEED_VS2017_INTEGRATION=0', '-p=NEED_VS2019_INTEGRATION=0', '-p=NEED_VS2022_INTEGRATION=0'
        ) -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw "oneAPI installer exited with $($proc.ExitCode)" }
        $root = "${env:ProgramFiles(x86)}\Intel\oneAPI"
        foreach ($dir in "$root\compiler\latest\bin", "$root\ocloc\latest\bin") {
            if (-not (Test-Path $dir)) { throw "$dir not found" }
            Add-Path $dir
        }
        if (-not (Test-Path "$root\compiler\latest\bin\icpx.exe")) { throw 'icpx not found' }
        Set-Env ONEAPI_ROOT $root
        $runtimeDirs += "$root\compiler\latest\bin", "$root\tcm\latest\bin"
        # Loaded by name, not imported: SYCL's Unified Runtime loader (through its proxy) and its
        # Level Zero adapters; the legacy adapter serves Arc A cards, V2 the rest (and SP1 on
        # every card).
        $runtimeAlso += 'ur_loader.dll', 'ur_adapter_level_zero.dll', 'ur_adapter_level_zero_v2.dll'
        $doc = "$root\compiler\latest\share\doc\compiler"
        $licenses += "$doc\credist.txt", "$doc\licensing\c\LICENSE.rtf", "$doc\licensing\c\third-party-programs.txt"
        # tcm's hwloc (BSD), under tcm's own license.
        $tcmDoc = "$root\tcm\latest\share\doc\tcm\licensing"
        $licenses += "$tcmDoc\license.txt", "$tcmDoc\third-party-programs.txt"
        Set-Env ZKMINER_REDIST_LIST "$doc\credist.txt"
        Set-Env ZKMINER_REDIST_DIR "$root\compiler\latest\bin"
    }
}

if ($Components -eq 'sp1-server') {
    # gnark's provers, through cgo, as on Linux (Dockerfile.build's GO_VERSION). cgo needs a
    # GCC-compatible compiler: llvm-mingw's, targeting the UCRT the MSVC build links. It is passed
    # to Go by full path and kept off PATH, so bindgen does not pick up its headers.
    Get-Verified 'https://go.dev/dl/go1.24.13.windows-amd64.zip' `
        '40B16BC8F00540A2CB02DFF4DE72B73E966FDD8D65F95E33D8E4080B48A2459A' "$tmp\go.zip"
    Expand-Archive "$tmp\go.zip" $tmp
    Add-Path "$tmp\go\bin"
    $mingw = 'llvm-mingw-20260908-ucrt-x86_64'
    Get-Verified "https://github.com/mstorsjo/llvm-mingw/releases/download/20260908/$mingw.zip" `
        '1BCF74D06B724AEECAA6412CA85F5B26FB1DA770E7CDCEFA9263C9C5C3AD34B6' "$tmp\mingw.zip"
    Expand-Archive "$tmp\mingw.zip" $tmp
    Set-Env SP1_GNARK_FFI_GO_ENVS "CC=$tmp\$mingw\bin\x86_64-w64-mingw32-clang.exe"
}

# The MSVC runtime, shipped beside the binaries (Microsoft's app-local deployment): a machine
# with only a GPU driver need not have the Visual C++ redistributable.
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath
$crt = Get-ChildItem "$vs\VC\Redist\MSVC\*\x64\Microsoft.VC14*.CRT" -Directory | Sort-Object FullName | Select-Object -Last 1
if (-not $crt) { throw 'MSVC runtime redist directory not found' }
$runtimeDirs += $crt.FullName

Set-Env ZKMINER_RUNTIME_DIRS ($runtimeDirs -join ';')
Set-Env ZKMINER_RUNTIME_ALSO ($runtimeAlso -join ';')
foreach ($l in $licenses) { if (-not (Test-Path $l)) { throw "$l not found" } }
Set-Env ZKMINER_LICENSES ($licenses -join ';')
