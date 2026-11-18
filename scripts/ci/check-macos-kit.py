#!/usr/bin/env python3
"""Checks the macOS beta kit tarball on any OS, without macOS tools (B9-CI).

    check-macos-kit.py [--version V] [--commit SHA] [--require-validated] <zkminer-<version>-macos-arm64.tar.gz>...

The release's assemble job runs on Linux, where otool, lipo and codesign do not exist, so this reads
the Mach-O load commands itself. It is the Mach-O counterpart of check-release-libs-inside.sh's ldd
check: every program of the kit must start on a stock Mac with nothing installed. (The macOS build
job runs the fuller check-macos-release.sh, with the Apple tools, before uploading the kit.)

For each tarball:
- one top directory, zkminer-<version>-macos-arm64/, named like the tarball; regular files and
  directories only (no links, no absolute or '..' paths); below 1 GiB (the 2.4 GB risc0-groth16
  component is never in the kit);
- the kit's SHA256SUMS lists every file but the SHA256SUMS files, and every SHA256SUMS holds;
- BUILDINFO: version equals the tarball's (and --version), commit equals --commit when given and
  commit_dirty=no; with --require-validated (the release), metal_compiler_validated=yes: the kernels
  were compiled by the validated Metal compiler (B9-M26), not by a runner's Xcode one;
- zkminer and provers/zkminer-prove-risc0-metal are Mach-O programs; every Mach-O CPU file in the
  kit is a thin arm64 image (not universal, not x86_64), links only /usr/lib/ and /System/Library/
  libraries (no @rpath, @loader_path or @executable_path, nothing from Homebrew), has
  LC_BUILD_VERSION platform macOS with minos = BUILDINFO binaries_minos, and has a code signature
  (LC_CODE_SIGNATURE: arm64 macOS kills an unsigned program);
- Metal GPU binary archives (metal-aot/*.binarchive, Mach-O files for the GPU's CPU type) are
  counted, and the kit's README.md must say what the kit has (BETA-FIX): a kit without archives
  carries the sentence NO_ARCHIVES_TEXT (every Mac then compiles its pipelines at first start), a
  kit with archives must not; the README's "About <x> GB for the kit" must be within a factor of
  two of the unpacked kit.
Exit 0 when every check passes; each failure is printed as a FAIL line.
"""
import hashlib
import io
import re
import struct
import sys
import tarfile

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGICS = (0xCAFEBABE, 0xCAFEBABF)
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE, MH_DYLIB, MH_BUNDLE = 2, 6, 8
LC_REQ_DYLD = 0x80000000
DYLIB_CMDS = {0xC: 'LC_LOAD_DYLIB', 0x18 | LC_REQ_DYLD: 'LC_LOAD_WEAK_DYLIB',
              0x1F | LC_REQ_DYLD: 'LC_REEXPORT_DYLIB', 0x20: 'LC_LAZY_LOAD_DYLIB',
              0x23 | LC_REQ_DYLD: 'LC_LOAD_UPWARD_DYLIB'}
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x1D
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1
SYSTEM_PREFIXES = ('/usr/lib/', '/System/Library/')
MAX_KIT = 1 << 30
PROGRAMS = ('zkminer', 'provers/zkminer-prove-risc0-metal')
# The kit README's statement that the kit has no offline Metal archives (packaging/macos/README.md).
NO_ARCHIVES_TEXT = 'This kit has no offline GPU pipeline archives'
KIT_SIZE_RE = re.compile(r'About ([0-9]+(?:\.[0-9]+)?) GB for the kit')

fails = []


def fail(msg):
    fails.append(msg)
    print('FAIL ' + msg)


def version_str(v):
    major, minor, patch = v >> 16, (v >> 8) & 0xFF, v & 0xFF
    return f'{major}.{minor}' + (f'.{patch}' if patch else '')


def macho(name, data):
    """Returns None for a non-Mach-O file, else a dict describing it."""
    if len(data) < 32:
        return None
    (be_magic,) = struct.unpack_from('>I', data, 0)
    if be_magic in FAT_MAGICS:
        (n,) = struct.unpack_from('>I', data, 4)
        if n > 16:  # a Java class file shares 0xCAFEBABE; a real fat header has a few slices
            return None
        cpus = [struct.unpack_from('>i', data, 8 + 20 * i)[0] & 0xFFFFFFFF for i in range(n)]
        return {'fat': True, 'cpus': cpus}
    (magic,) = struct.unpack_from('<I', data, 0)
    if magic != MH_MAGIC_64:
        if magic in (0xFEEDFACE,) or be_magic in (MH_MAGIC_64, 0xFEEDFACE):
            return {'fat': False, 'bad': 'a 32-bit or big-endian Mach-O image'}
        return None
    cputype, _sub, filetype, ncmds, sizeofcmds, _flags, _res = struct.unpack_from('<iiIIIII', data, 4)
    info = {'fat': False, 'cpu': cputype & 0xFFFFFFFF, 'filetype': filetype, 'dylibs': [],
            'rpaths': [], 'build': None, 'signed': False}
    if info['cpu'] != CPU_TYPE_ARM64:
        return info
    off = 32
    end = 32 + sizeofcmds
    if end > len(data):
        info['bad'] = 'load commands run past the end of the file'
        return info
    for _ in range(ncmds):
        if off + 8 > end:
            info['bad'] = 'truncated load commands'
            return info
        cmd, size = struct.unpack_from('<II', data, off)
        if size < 8 or off + size > end:
            info['bad'] = f'load command {cmd:#x} of size {size} is malformed'
            return info
        if cmd in DYLIB_CMDS or cmd == LC_RPATH:
            (str_off,) = struct.unpack_from('<I', data, off + 8)
            raw = data[off + str_off:off + size]
            path = raw.split(b'\0', 1)[0].decode('utf-8', 'replace')
            (info['rpaths'] if cmd == LC_RPATH else info['dylibs']).append((DYLIB_CMDS.get(cmd, 'LC_RPATH'), path))
        elif cmd == LC_BUILD_VERSION:
            platform, minos, sdk = struct.unpack_from('<III', data, off + 8)
            info['build'] = (platform, version_str(minos), version_str(sdk))
        elif cmd == LC_CODE_SIGNATURE:
            info['signed'] = True
        off += size
    return info


def check_tarball(path, want_version, want_commit, require_validated=False):
    m = re.search(r'(?:^|/)(zkminer-([0-9][0-9A-Za-z.+-]*)-macos-arm64)\.tar\.gz$', path)
    if not m:
        fail(f'{path}: not a zkminer-<version>-macos-arm64.tar.gz')
        return
    top, version = m.group(1), m.group(2)
    with open(path, 'rb') as f:
        blob = f.read()
    if len(blob) > MAX_KIT:
        fail(f'{path}: {len(blob)} bytes, over 1 GiB (the risc0-groth16 component must not be in the kit)')
    files = {}
    modes = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as tar:
        for ti in tar:
            name = ti.name[2:] if ti.name.startswith('./') else ti.name
            if name.startswith('/') or '..' in name.split('/'):
                fail(f'{path}: unsafe path {ti.name!r}')
                continue
            if name.rstrip('/') != top and not name.startswith(top + '/'):
                fail(f'{path}: {ti.name!r} is outside {top}/')
                continue
            if ti.isdir():
                continue
            if not ti.isfile():
                fail(f'{path}: {ti.name!r} is not a regular file or directory')
                continue
            rel = name[len(top) + 1:]
            files[rel] = tar.extractfile(ti).read()
            modes[rel] = ti.mode
    if want_version is not None and version != want_version:
        fail(f'{path}: version {version} in the name, want {want_version}')
    # SHA256SUMS: the kit's lists every file but the SHA256SUMS files (as assemble-macos.sh writes
    # it); each SHA256SUMS (also metal-aot/SHA256SUMS) holds for the files it lists, in its directory.
    if 'SHA256SUMS' not in files:
        fail(f'{path}: no SHA256SUMS')
    listed_top = set()
    for sums_rel in sorted(r for r in files if r.rsplit('/', 1)[-1] == 'SHA256SUMS'):
        base = sums_rel[:-len('SHA256SUMS')]
        for line in files[sums_rel].decode('utf-8', 'replace').splitlines():
            mm = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
            if not mm:
                fail(f'{path}: {sums_rel} line {line!r}')
                continue
            digest, rel = mm.groups()
            rel = base + rel
            if sums_rel == 'SHA256SUMS':
                listed_top.add(rel)
            if rel not in files:
                fail(f'{path}: {sums_rel} lists {rel}, which the kit does not have')
            elif hashlib.sha256(files[rel]).hexdigest() != digest:
                fail(f'{path}: {rel} does not match {sums_rel}')
    unlisted = sorted(r for r in files if r.rsplit('/', 1)[-1] != 'SHA256SUMS' and r not in listed_top)
    if unlisted:
        fail(f'{path}: not in SHA256SUMS: {unlisted}')
    # BUILDINFO
    bi = {}
    if 'BUILDINFO' not in files:
        fail(f'{path}: no BUILDINFO')
    else:
        for line in files['BUILDINFO'].decode('utf-8', 'replace').splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                bi[k] = v
        if bi.get('version') != version:
            fail(f'{path}: BUILDINFO version={bi.get("version")}, the tarball says {version}')
        if want_commit is not None:
            if bi.get('commit') != want_commit:
                fail(f'{path}: BUILDINFO commit={bi.get("commit")}, want {want_commit}')
            if bi.get('commit_dirty') != 'no':
                fail(f'{path}: BUILDINFO commit_dirty={bi.get("commit_dirty")}')
        if require_validated and bi.get('metal_compiler_validated') != 'yes':
            fail(f'{path}: BUILDINFO metal_compiler_validated={bi.get("metal_compiler_validated")} '
                 f'(metal_compiler={bi.get("metal_compiler")}): a release needs the validated Metal compiler')
    want_minos = bi.get('binaries_minos')
    if not want_minos:
        fail(f'{path}: BUILDINFO has no binaries_minos')
    # Mach-O files
    programs = 0
    archives = 0
    for rel in sorted(files):
        info = macho(rel, files[rel])
        if info is None:
            if rel in PROGRAMS:
                fail(f'{path}: {rel} is not a Mach-O file')
            continue
        where = f'{path}: {rel}'
        if info['fat']:
            cpus = ', '.join(f'{c:#x}' for c in info['cpus'])
            fail(f'{where}: a universal (fat) file with CPU types {cpus}; want a thin arm64 image')
            continue
        if 'bad' in info and info.get('cpu') in (None, CPU_TYPE_ARM64):
            fail(f'{where}: {info["bad"]}')
            continue
        if info['cpu'] != CPU_TYPE_ARM64:
            if rel.startswith('metal-aot/') and rel.endswith('.binarchive') and info['cpu'] != CPU_TYPE_X86_64:
                archives += 1  # a Metal GPU binary archive: GPU code, not a program
                continue
            fail(f'{where}: CPU type {info["cpu"]:#x}, want arm64 ({CPU_TYPE_ARM64:#x})')
            continue
        if info['filetype'] not in (MH_EXECUTE, MH_DYLIB, MH_BUNDLE):
            fail(f'{where}: Mach-O file type {info["filetype"]}, want a program or library')
            continue
        if rel in PROGRAMS and info['filetype'] != MH_EXECUTE:
            fail(f'{where}: not an executable (file type {info["filetype"]})')
        if info['filetype'] == MH_EXECUTE:
            programs += 1
            if not modes[rel] & 0o111:
                fail(f'{where}: not executable (mode {modes[rel]:o})')
        bad = [p for _, p in info['dylibs'] if not p.startswith(SYSTEM_PREFIXES)]
        if bad:
            fail(f'{where}: links libraries a stock Mac does not have: {bad}')
        if not info['dylibs']:
            fail(f'{where}: links no library at all (not a dynamically linked macOS program?)')
        if info['build'] is None:
            fail(f'{where}: no LC_BUILD_VERSION')
        else:
            platform, minos, sdk = info['build']
            if platform != PLATFORM_MACOS:
                fail(f'{where}: LC_BUILD_VERSION platform {platform}, want macOS ({PLATFORM_MACOS})')
            if want_minos and minos != want_minos:
                fail(f'{where}: minos {minos}, BUILDINFO binaries_minos={want_minos}')
        if not info['signed']:
            fail(f'{where}: no code signature (LC_CODE_SIGNATURE)')
        libs = len(info['dylibs'])
        b = info['build']
        print(f'  {rel}: arm64, minos {b[1] if b else "?"} (sdk {b[2] if b else "?"}), {libs} system libraries, signed={info["signed"]}')
    for p in PROGRAMS:
        if p not in files:
            fail(f'{path}: no {p}')
    check_readme(path, files, archives)
    print(f'{path}: version {version}, {len(files)} files, {programs} programs, {archives} GPU binary archives')


def check_readme(path, files, archives):
    """The kit README must describe this kit: whether it has offline archives, and its size."""
    if 'README.md' not in files:
        fail(f'{path}: no README.md')
        return
    text = ' '.join(files['README.md'].decode('utf-8', 'replace').split())
    says_none = NO_ARCHIVES_TEXT in text
    if archives == 0 and not says_none:
        fail(f'{path}: README.md does not say "{NO_ARCHIVES_TEXT}", but the kit has no metal-aot/*.binarchive '
             f'(its first start compiles the GPU pipelines on every Mac)')
    if archives > 0 and says_none:
        fail(f'{path}: README.md says "{NO_ARCHIVES_TEXT}", but the kit has {archives} GPU binary archives')
    m = KIT_SIZE_RE.search(text)
    unpacked = sum(len(d) for d in files.values())
    if not m:
        fail(f'{path}: README.md does not give the kit size ("About <x> GB for the kit")')
    elif not 0.5 <= float(m.group(1)) * 1e9 / unpacked <= 2.0:
        fail(f'{path}: README.md says "About {m.group(1)} GB for the kit", the kit unpacks to {unpacked / 1e9:.2f} GB')


def main(argv):
    want_version = want_commit = None
    require_validated = False
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('--version', '--commit') and i + 1 < len(argv):
            if a == '--version':
                want_version = argv[i + 1]
            else:
                want_commit = argv[i + 1]
            i += 2
            continue
        if a == '--require-validated':
            require_validated = True
            i += 1
            continue
        if a in ('-h', '--help'):
            print(__doc__)
            return 0
        args.append(a)
        i += 1
    if not args:
        print('usage: check-macos-kit.py [--version V] [--commit SHA] [--require-validated] <kit tarball>...', file=sys.stderr)
        return 2
    for p in args:
        check_tarball(p, want_version, want_commit, require_validated)
    if fails:
        print(f'{len(fails)} check(s) failed')
        return 1
    print('ok: every macOS program links only system libraries, is arm64, signed, with the kit\'s minimum macOS')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
