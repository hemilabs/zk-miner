//! No network filesystem within reach of a process that runs untrusted code.
//!
//! Landlock decides what a process may open, read, write or execute below a path, but not the path
//! walk that leads there: `stat`, `access`, `readlink`, `getxattr`, `statfs`, `chdir` and the lookup
//! of an `open` that Landlock then refuses all go through every directory on the way, on whatever
//! filesystem holds it. On a network filesystem (NFS, SMB, Ceph, 9p, ...) each of those lookups is a
//! request to its server, carrying the name the process chose and answering whether it exists; on
//! a FUSE filesystem it is a request to a user-space daemon (sshfs, rclone, gvfs, ...) that may go
//! anywhere; on an automount point it mounts whatever the lookup names (`/net/<host>`). A process
//! confined to no network could still query those servers by name. So before such a process runs
//! anything untrusted, [`check_local_filesystems`] refuses if any filesystem it can reach is not
//! local:
//!
//! - **every mount this process can reach by path**, from `/proc/self/mountinfo` (not only those
//!   under the paths it is granted, since a lookup needs no grant). A mount hidden under another
//!   (mounted over it, or over one of its parent directories) cannot be reached by any path and is
//!   left out; an automount point never is (its mount expires and it is reachable again). The
//!   filesystem type must be one known to be local ([`LOCAL_TYPES`]: disk, memory and kernel
//!   filesystems); anything else is refused, unknown types included. Two exceptions, both because
//!   the kernel itself keeps the process out: a FUSE mount without `allow_other` that belongs to
//!   another user (the kernel refuses this user's lookups before the daemon sees them), and a
//!   *direct* automount point (one fixed mount, such as systemd's for `binfmt_misc` or the EFI
//!   system partition) whose target is a local filesystem; an idle one is triggered once to see
//!   what it mounts. An indirect automount map (a lookup names what it mounts) is refused.
//! - **every path the process is granted**: `statfs` must report a local filesystem
//!   ([`LOCAL_MAGICS`]);
//! - **its working directory and every regular file, directory or link it holds open**: on a
//!   mount of the table that is local, or (an fd of the kernel's own, such as a memfd) on a local
//!   filesystem by `fstatfs`. These are read without asking a network filesystem's server
//!   (`AT_STATX_DONT_SYNC`).
//!
//! What it cannot see: a mount added after the check (the process is confined for the rest of its
//! life, so an operator who mounts a network filesystem while workers run exposes it to them until
//! they are restarted), and filesystems whose own storage is remote (an overlay or `ecryptfs` with a
//! layer on a network filesystem not in the table, a block device backed by iSCSI, NBD, RBD or a
//! file on NFS): those are judged by their own type.

use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::SandboxError;

/// Filesystem types that are local: disk filesystems, memory filesystems and the kernel's own.
/// A lookup on them reaches no other host and no user-space daemon. Overlay and `ecryptfs` stack
/// on other directories, whose own mounts are judged where they are in the table.
pub const LOCAL_TYPES: &[&str] = &[
    // On a disk.
    "ext2",
    "ext3",
    "ext4",
    "xfs",
    "btrfs",
    "f2fs",
    "zfs",
    "bcachefs",
    "jfs",
    "reiserfs",
    "nilfs2",
    "hfs",
    "hfsplus",
    "minix",
    "ufs",
    "udf",
    "iso9660",
    "vfat",
    "msdos",
    "exfat",
    "ntfs3",
    "ntfs",
    "squashfs",
    "erofs",
    "cramfs",
    "romfs",
    "zonefs",
    // Stacked on local directories.
    "overlay",
    "ecryptfs",
    // In memory.
    "tmpfs",
    "ramfs",
    "rootfs",
    "devtmpfs",
    "hugetlbfs",
    "mqueue",
    "devpts",
    // The kernel's.
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "securityfs",
    "debugfs",
    "tracefs",
    "bpf",
    "configfs",
    "pstore",
    "efivarfs",
    "binfmt_misc",
    "fusectl",
    "nsfs",
    "rpc_pipefs",
    "nfsd",
    "selinuxfs",
    "smackfs",
];

/// `statfs` magic numbers of the [`LOCAL_TYPES`] (`<linux/magic.h>`), and of the kernel's internal
/// filesystems an open fd can be on (memfds, pidfds, namespaces, sockets, pipes, anonymous inodes,
/// DMA buffers).
pub const LOCAL_MAGICS: &[(u64, &str)] = &[
    (0xef53, "ext2/3/4"),
    (0x5846_5342, "xfs"),
    (0x9123_683e, "btrfs"),
    (0xf2f5_2010, "f2fs"),
    (0x2fc1_2fc1, "zfs"),
    (0xca45_1a4e, "bcachefs"),
    (0x3153_464a, "jfs"),
    (0x5265_4973, "reiserfs"),
    (0x3434, "nilfs2"),
    (0x4244, "hfs"),
    (0x482b, "hfsplus"),
    (0x137f, "minix"),
    (0x138f, "minix"),
    (0x2468, "minix2"),
    (0x2478, "minix2"),
    (0x4d5a, "minix3"),
    (0x0001_1954, "ufs"),
    (0x1501_3346, "udf"),
    (0x9660, "iso9660"),
    (0x4d44, "vfat/msdos"),
    (0x2011_bab0, "exfat"),
    (0x7366_746e, "ntfs3"),
    (0x5346_544e, "ntfs"),
    (0x7371_7368, "squashfs"),
    (0xe0f5_e1e2, "erofs"),
    (0x28cd_3d45, "cramfs"),
    (0x7275, "romfs"),
    (0x5a4f_4653, "zonefs"),
    (0x794c_7630, "overlay"),
    (0xf15f, "ecryptfs"),
    (0x0102_1994, "tmpfs/devtmpfs"),
    (0x8584_58f6, "ramfs"),
    (0x9584_58f6, "hugetlbfs"),
    (0x1980_0202, "mqueue"),
    (0x1cd1, "devpts"),
    (0x9fa0, "proc"),
    (0x6265_6572, "sysfs"),
    (0x0027_e0eb, "cgroup"),
    (0x6367_7270, "cgroup2"),
    (0x7363_6673, "securityfs"),
    (0x6462_6720, "debugfs"),
    (0x7472_6163, "tracefs"),
    (0xcafe_4a11, "bpf"),
    (0x6265_6570, "configfs"),
    (0x6165_676c, "pstore"),
    (0xde5e_81e4, "efivarfs"),
    (0x4249_4e4d, "binfmt_misc"),
    (0x6573_5543, "fusectl"),
    (0x6e73_6673, "nsfs"),
    (0x6759_6969, "rpc_pipefs"),
    (0x6e66_7364, "nfsd"),
    (0xf97c_ff8c, "selinuxfs"),
    (0x4341_5d53, "smackfs"),
    // The kernel's internal ones.
    (0x5049_4446, "pidfs"),
    (0x534f_434b, "sockfs"),
    (0x5049_5045, "pipefs"),
    (0x0904_1934, "anon_inodefs"),
    (0x444d_4142, "dma-buf"),
    (0x5345_434d, "secretmem"),
    (0xa10a_10a1, "aio"),
    (0x6264_6576, "bdev"),
];

/// Names for magic numbers that are not local, for messages.
const OTHER_MAGICS: &[(u64, &str)] = &[
    (0x6969, "nfs"),
    (0x517b, "smbfs"),
    (0xff53_4d42, "cifs"),
    (0xfe53_4d42, "smb2"),
    (0x6573_5546, "fuse"),
    (0x0187, "autofs"),
    (0x00c3_6400, "ceph"),
    (0x0102_1997, "9p"),
    (0x5346_414f, "afs"),
    (0x7375_7245, "coda"),
    (0x7461_636f, "ocfs2"),
    (0x0116_1970, "gfs2"),
    (0x0bd0_0bd0, "lustre"),
    (0x564c, "ncpfs"),
    (0x786f_4256, "vboxsf"),
    (0x2003_0528, "orangefs"),
];

/// What a filesystem type is, for the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Local,
    Fuse,
    Automount,
    Other,
}

fn kind_of(fstype: &str) -> Kind {
    if LOCAL_TYPES.contains(&fstype) {
        Kind::Local
    } else if fstype == "fuse" || fstype == "fuseblk" || fstype.starts_with("fuse.") {
        Kind::Fuse
    } else if fstype == "autofs" {
        Kind::Automount
    } else {
        Kind::Other
    }
}

/// Why a filesystem of `fstype` is refused.
fn why_not_local(fstype: &str) -> &'static str {
    const NETWORK: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "ceph",
        "glusterfs",
        "9p",
        "afs",
        "kafs",
        "lustre",
        "ncpfs",
        "coda",
        "orangefs",
        "pvfs2",
        "beegfs",
        "gpfs",
        "virtiofs",
        "vboxsf",
        "davfs",
    ];
    match kind_of(fstype) {
        Kind::Local => "local",
        Kind::Fuse => "a FUSE filesystem, served by a user-space daemon",
        Kind::Automount => "an automount point",
        Kind::Other if NETWORK.contains(&fstype) => "a network filesystem",
        Kind::Other if fstype == "ocfs2" || fstype == "gfs2" => "a cluster filesystem",
        Kind::Other => "a filesystem type not known to be local",
    }
}

/// One line of `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: u32,
    pub parent: u32,
    /// The mount point as `mountinfo` writes it (octal escapes kept), relative to this process's
    /// root.
    point: String,
    /// `fuse.sshfs` for a FUSE filesystem with a subtype.
    pub fstype: String,
    pub source: String,
    super_options: String,
}

impl Mount {
    /// The mount point.
    pub fn mount_point(&self) -> PathBuf {
        PathBuf::from(OsString::from_vec(unescape(&self.point)))
    }

    fn has_super_option(&self, name: &str) -> bool {
        self.super_options.split(',').any(|o| o == name)
    }

    fn super_option(&self, name: &str) -> Option<&str> {
        self.super_options
            .split(',')
            .find_map(|o| o.strip_prefix(name)?.strip_prefix('='))
    }

    fn describe(&self) -> String {
        format!(
            "{} ({} from {})",
            self.mount_point().display(),
            self.fstype,
            String::from_utf8_lossy(&unescape(&self.source))
        )
    }
}

/// `mountinfo`'s octal escapes (`\040` for a space, ...) undone.
fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64
                + (b[i + 2] - b'0') as u32 * 8
                + (b[i + 3] - b'0') as u32;
            if let Ok(byte) = u8::try_from(v) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The lines of a `mountinfo` file.
pub fn parse_mountinfo(text: &str) -> Result<Vec<Mount>, String> {
    let mut mounts = Vec::new();
    for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
        let bad = || format!("mountinfo line {}: {line:?}", n + 1);
        let fields: Vec<&str> = line.split(' ').collect();
        let sep = fields
            .iter()
            .skip(6)
            .position(|f| *f == "-")
            .map(|p| p + 6)
            .ok_or_else(bad)?;
        if fields.len() < sep + 4 {
            return Err(bad());
        }
        mounts.push(Mount {
            id: fields[0].parse().map_err(|_| bad())?,
            parent: fields[1].parse().map_err(|_| bad())?,
            point: fields[4].to_string(),
            fstype: fields[sep + 1].to_string(),
            source: fields[sep + 2].to_string(),
            super_options: fields[sep + 3].to_string(),
        });
    }
    Ok(mounts)
}

/// The prefixes of `point`, one per component: `/a`, `/a/b`, ...
fn prefixes(point: &str) -> Vec<String> {
    let comps: Vec<&str> = point.split('/').filter(|c| !c.is_empty()).collect();
    (1..=comps.len())
        .map(|i| format!("/{}", comps[..i].join("/")))
        .collect()
}

/// Where a path walk to `point` from the mount `root` ends: the mount it is in, and the mounts it
/// entered at the last component (a stack of mounts on one mount point, bottom first). `None` where
/// two mounts share a parent and a mount point (the walk cannot be told from the table).
/// `follow_root_stack`: whether mounts stacked on the root are entered (a process whose root was
/// mounted over keeps the one it had; both are tried).
fn walk(
    mounts: &[Mount],
    root: usize,
    point: &str,
    follow_root_stack: bool,
) -> Option<(usize, Vec<usize>)> {
    let mut cur = root;
    let mut stack = Vec::new();
    let mut steps: Vec<String> = Vec::new();
    if follow_root_stack {
        steps.push("/".to_string());
    }
    steps.extend(prefixes(point));
    for prefix in &steps {
        stack.clear();
        for _ in 0..=mounts.len() {
            let parent = mounts[cur].id;
            let mut on = mounts
                .iter()
                .enumerate()
                .filter(|(i, m)| *i != cur && m.parent == parent && m.point == *prefix);
            match (on.next(), on.next()) {
                (None, _) => break,
                (Some((i, _)), None) => {
                    cur = i;
                    stack.push(i);
                }
                (Some(_), Some(_)) => return None,
            }
        }
    }
    Some((cur, stack))
}

/// Which mounts a path walk can reach, from the mount `root_id` (this process's root): a mount is
/// reachable if a walk to its mount point ends in it, or (an automount point, which its own mount
/// covers only until that expires) passes through it there. Where the table cannot tell, it is
/// reachable.
fn reachable(mounts: &[Mount], root_id: u32) -> Vec<bool> {
    let Some(root) = mounts.iter().position(|m| m.id == root_id) else {
        return vec![true; mounts.len()];
    };
    mounts
        .iter()
        .enumerate()
        .map(|(i, m)| {
            i == root
                || [false, true]
                    .iter()
                    .any(|&follow| match walk(mounts, root, &m.point, follow) {
                        None => true,
                        Some((end, stack)) => {
                            end == i
                                || (kind_of(&m.fstype) == Kind::Automount && stack.contains(&i))
                        }
                    })
        })
        .collect()
}

/// The reachable mounts of `mounts` that are not local, each with why (see the module docs), for a
/// process whose root is the mount `root_id` and whose effective uid is `euid`.
pub(crate) fn judge(mounts: &[Mount], root_id: u32, euid: u32) -> Vec<String> {
    let reach = reachable(mounts, root_id);
    let mut problems = Vec::new();
    for (m, _) in mounts.iter().zip(&reach).filter(|(_, r)| **r) {
        match kind_of(&m.fstype) {
            Kind::Local => {}
            Kind::Fuse
                if euid != 0
                    && !m.has_super_option("allow_other")
                    && m.super_option("user_id")
                        .and_then(|u| u.parse::<u32>().ok())
                        .is_some_and(|owner| owner != euid) =>
            {
                // The kernel refuses this user's lookups before its daemon sees them.
            }
            Kind::Automount => {
                let target = mounts
                    .iter()
                    .find(|t| t.parent == m.id && t.point == m.point && t.id != m.id);
                match (m.has_super_option("direct"), target) {
                    (true, Some(t)) if kind_of(&t.fstype) == Kind::Local => {}
                    (true, Some(t)) => problems.push(format!(
                        "{}: an automount point that mounts {} ({})",
                        m.describe(),
                        t.fstype,
                        why_not_local(&t.fstype)
                    )),
                    (true, None) => problems.push(format!(
                        "{}: an automount point whose target could not be seen (triggering it \
                         mounted nothing)",
                        m.describe()
                    )),
                    (false, _) => problems.push(format!(
                        "{}: an automount map that mounts whatever a lookup names",
                        m.describe()
                    )),
                }
            }
            Kind::Fuse | Kind::Other => {
                problems.push(format!("{}: {}", m.describe(), why_not_local(&m.fstype)))
            }
        }
    }
    problems
}

fn cpath(p: &Path) -> Result<CString, SandboxError> {
    CString::new(p.as_os_str().as_bytes()).map_err(|e| SandboxError::InvalidArgument(e.to_string()))
}

/// `statx` of `path` relative to `dirfd` (`AT_EMPTY_PATH` with `""`), from the attributes the
/// kernel has, without asking a network filesystem's server and without triggering an automount:
/// the file type and the id of the mount it is on.
fn statx_mount(
    dirfd: libc::c_int,
    path: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<(u32, u64)> {
    // SAFETY: a zeroed statx buffer the kernel fills; a NUL-terminated path.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::statx(
            dirfd,
            path.as_ptr(),
            flags | libc::AT_STATX_DONT_SYNC | libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_TYPE | libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if stx.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(std::io::Error::other("statx gave no mount id"));
    }
    Ok((u32::from(stx.stx_mode) & libc::S_IFMT, stx.stx_mnt_id))
}

/// The `statfs` magic of a path, or of an fd.
fn magic(path: Option<&std::ffi::CStr>, fd: libc::c_int) -> std::io::Result<u64> {
    // SAFETY: a zeroed statfs buffer the kernel fills; a NUL-terminated path or an open fd.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        match path {
            Some(p) => libc::statfs(p.as_ptr(), &mut st),
            None => libc::fstatfs(fd, &mut st),
        }
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.f_type as u64)
}

fn magic_name(m: u64) -> String {
    LOCAL_MAGICS
        .iter()
        .chain(OTHER_MAGICS)
        .find(|(v, _)| *v == m)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("filesystem magic {m:#x}"))
}

fn local_magic(m: u64) -> bool {
    LOCAL_MAGICS.iter().any(|(v, _)| *v == m)
}

/// Every mount of this process's table, and the id of its root mount.
fn mount_table() -> Result<(Vec<Mount>, u32), SandboxError> {
    let text = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mounts = parse_mountinfo(&text).map_err(SandboxError::InvalidArgument)?;
    let (_, root) = statx_mount(libc::AT_FDCWD, c"/", 0)?;
    let root = u32::try_from(root)
        .map_err(|_| SandboxError::InvalidArgument(format!("root mount id {root}")))?;
    if !mounts.iter().any(|m| m.id == root) {
        return Err(SandboxError::InvalidArgument(format!(
            "this process's root (mount {root}) is not in its mount table"
        )));
    }
    Ok((mounts, root))
}

/// Triggers every reachable *direct* automount point that has nothing mounted on it, so that what
/// it mounts can be judged; whether any was.
fn trigger_idle_direct_automounts(mounts: &[Mount], root: u32) -> bool {
    let reach = reachable(mounts, root);
    let mut any = false;
    for (m, _) in mounts.iter().zip(&reach).filter(|(_, r)| **r) {
        let idle = kind_of(&m.fstype) == Kind::Automount
            && m.has_super_option("direct")
            && !mounts
                .iter()
                .any(|t| t.parent == m.id && t.point == m.point && t.id != m.id);
        if idle {
            if let Ok(p) = cpath(&m.mount_point()) {
                // statfs follows the automount; its answer does not matter.
                let _ = magic(Some(&p), -1);
                any = true;
            }
        }
    }
    any
}

/// What [`check_local_filesystems`] looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFsReport {
    /// Mounts this process can reach by path.
    pub reachable_mounts: usize,
    /// Granted paths `statfs` judged.
    pub paths: usize,
    /// Open files, directories and links judged (and the working directory).
    pub open_files: usize,
}

/// Fails if this process can reach a filesystem that is not local (see the module docs), naming
/// each one and its type. `granted`: the paths it is (or will be) granted; missing ones are skipped,
/// as Landlock skips them.
pub fn check_local_filesystems(granted: &[PathBuf]) -> Result<LocalFsReport, SandboxError> {
    let (mut mounts, mut root) = mount_table()?;
    if trigger_idle_direct_automounts(&mounts, root) {
        (mounts, root) = mount_table()?;
    }
    // SAFETY: geteuid has no arguments.
    let euid = unsafe { libc::geteuid() };
    let mut problems = judge(&mounts, root, euid);

    let mut paths = 0;
    for p in granted {
        let c = cpath(p)?;
        match magic(Some(c.as_c_str()), -1) {
            Ok(m) if local_magic(m) => paths += 1,
            Ok(m) => problems.push(format!("{} is on {}", p.display(), magic_name(m))),
            // Missing: nothing can be reached through it.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => problems.push(format!("{}: statfs failed ({e})", p.display())),
        }
    }

    // The working directory, and every file, directory or link held open.
    let mut held: Vec<(String, libc::c_int, CString, libc::c_int)> = vec![(
        "the working directory".into(),
        libc::AT_FDCWD,
        c".".to_owned(),
        0,
    )];
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let Some(fd) = entry?
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<libc::c_int>().ok())
        else {
            continue;
        };
        held.push((format!("fd {fd}"), fd, c"".to_owned(), libc::AT_EMPTY_PATH));
    }
    let mut open_files = 0;
    for (what, fd, path, flags) in held {
        let (kind, mnt) = match statx_mount(fd, &path, flags) {
            Ok(v) => v,
            // An fd closed meanwhile (the directory listing's own).
            Err(e) if e.raw_os_error() == Some(libc::EBADF) => continue,
            Err(e) => {
                problems.push(format!("{what}: statx failed ({e})"));
                continue;
            }
        };
        if !matches!(kind, libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK) {
            continue;
        }
        open_files += 1;
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map(|t| t.display().to_string())
            .unwrap_or_default();
        match mounts.iter().find(|m| u64::from(m.id) == mnt) {
            Some(m) if kind_of(&m.fstype) == Kind::Local => {}
            Some(m) => problems.push(format!(
                "{what} {target} is on {}: {}",
                m.describe(),
                why_not_local(&m.fstype)
            )),
            // A mount of the kernel's own (a memfd's, a pidfd's), or of another namespace.
            None => match if fd == libc::AT_FDCWD {
                magic(Some(c"."), -1)
            } else {
                magic(None, fd)
            } {
                Ok(m) if local_magic(m) => {}
                Ok(m) => problems.push(format!("{what} {target} is on {}", magic_name(m))),
                Err(e) => problems.push(format!("{what} {target}: fstatfs failed ({e})")),
            },
        }
    }

    if problems.is_empty() {
        Ok(LocalFsReport {
            reachable_mounts: reachable(&mounts, root).iter().filter(|r| **r).count(),
            paths,
            open_files,
        })
    } else {
        Err(SandboxError::NotLocal(problems.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This host's table when the check was written (Ubuntu 26.04, a VM): systemd's binfmt_misc
    /// automount triggered, snaps, Docker's overlay and network namespaces.
    pub(crate) const HOST: &str = "\
25 1 252:0 / / rw,relatime shared:1 - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
26 25 0:6 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=32834652k,nr_inodes=8208663,mode=755,inode64
27 26 0:25 / /dev/pts rw,nosuid,noexec,relatime shared:3 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 25 0:26 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=6574812k,mode=755,inode64
29 25 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
30 25 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
31 26 0:28 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw,inode64
32 29 0:7 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:7 - securityfs securityfs rw
33 29 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:8 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
34 29 0:31 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:9 - pstore none rw
35 29 0:32 / /sys/firmware/efi/efivars rw,nosuid,nodev,noexec,relatime shared:10 - efivarfs efivarfs rw
36 29 0:33 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:11 - bpf bpf rw,mode=700
37 30 0:34 / /proc/sys/fs/binfmt_misc rw,relatime shared:13 - autofs systemd-1 rw,fd=36,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=4917
38 26 0:20 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:14 - mqueue mqueue rw
39 26 0:35 / /dev/hugepages rw,nosuid,nodev,relatime shared:15 - hugetlbfs hugetlbfs rw,pagesize=2M
40 29 0:8 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:16 - debugfs debugfs rw
41 29 0:13 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:17 - tracefs tracefs rw
42 29 0:36 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:18 - fusectl fusectl rw
43 29 0:21 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:19 - configfs configfs rw
44 25 0:37 / /tmp rw,nosuid,nodev shared:20 - tmpfs tmpfs rw,nr_inodes=1048576,inode64
45 25 7:0 / /snap/core24/1643 ro,nodev,relatime shared:21 - squashfs /dev/loop0 ro,errors=continue,threads=single
46 25 8:2 / /boot rw,relatime shared:22 - ext4 /dev/sda2 rw
47 46 8:1 / /boot/efi rw,relatime shared:23 - vfat /dev/sda1 rw,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro
48 37 0:38 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime shared:24 - binfmt_misc binfmt_misc rw
49 28 0:39 / /run/user/1000 rw,nosuid,nodev,relatime shared:25 - tmpfs tmpfs rw,size=6574808k,nr_inodes=1643702,mode=700,uid=1000,gid=1000,inode64
50 28 0:4 net:[4026532401] /run/docker/netns/5315c78841c2 rw shared:26 - nsfs nsfs rw
51 25 0:40 / /var/lib/docker/rootfs/overlayfs/d7e1f228 rw,relatime shared:27 - overlay overlay rw,lowerdir=/var/lib/docker/a:/var/lib/docker/b,upperdir=/var/lib/docker/c,workdir=/var/lib/docker/d
";

    fn judged(extra: &str) -> Vec<String> {
        let mounts = parse_mountinfo(&format!("{HOST}{extra}")).unwrap();
        judge(&mounts, 25, 1000)
    }

    #[test]
    fn a_local_host_passes() {
        assert_eq!(judged(""), Vec::<String>::new());
        let mounts = parse_mountinfo(HOST).unwrap();
        assert_eq!(mounts.len(), 27);
        let snap = mounts.iter().find(|m| m.id == 45).unwrap();
        assert_eq!(
            (snap.mount_point(), snap.fstype.as_str()),
            (PathBuf::from("/snap/core24/1643"), "squashfs")
        );
        assert!(reachable(&mounts, 25).iter().all(|r| *r));
    }

    #[test]
    fn a_network_filesystem_anywhere_is_refused_by_path_and_type() {
        for (line, point, fstype) in [
            (
                "60 25 0:50 / /mnt/share rw - nfs4 fileserver.corp:/export rw,vers=4.2,addr=10.0.0.5",
                "/mnt/share",
                "nfs4",
            ),
            ("60 25 0:50 / /opt/models rw - nfs 10.0.0.5:/models rw,addr=10.0.0.5", "/opt/models", "nfs"),
            ("60 25 0:50 / /home rw - cifs //nas/home rw,addr=192.168.1.2", "/home", "cifs"),
            ("60 25 0:50 / /home rw - smb3 //nas/home rw", "/home", "smb3"),
            ("60 25 0:50 / /data rw - ceph 10.0.0.1:6789:/ rw", "/data", "ceph"),
            ("60 25 0:50 / /data rw - glusterfs gl:/vol rw", "/data", "glusterfs"),
            ("60 25 0:50 / /mnt/c rw - 9p drvfs rw,aname=drvfs", "/mnt/c", "9p"),
            ("60 25 0:50 / /afs rw - afs AFS rw", "/afs", "afs"),
            ("60 25 0:50 / /lustre rw - lustre 10.0.0.1@tcp:/fs rw", "/lustre", "lustre"),
            ("60 25 0:50 / /shared rw - virtiofs tag rw", "/shared", "virtiofs"),
            ("60 25 0:50 / /cluster rw - ocfs2 /dev/sdb rw", "/cluster", "ocfs2"),
            ("60 25 0:50 / /cluster rw - gfs2 /dev/sdb rw", "/cluster", "gfs2"),
            ("60 25 0:50 / /odd rw - somethingnew src rw", "/odd", "somethingnew"),
            // Below a granted path, and deep below one.
            ("60 30 0:50 / /proc/fs/remote rw - nfs 10.0.0.5:/x rw", "/proc/fs/remote", "nfs"),
            ("60 49 0:50 / /run/user/1000/net rw - nfs 10.0.0.5:/x rw", "/run/user/1000/net", "nfs"),
        ] {
            let problems = judged(&format!("{line}\n"));
            assert_eq!(problems.len(), 1, "{line}: {problems:?}");
            assert!(problems[0].starts_with(&format!("{point} ({fstype} from ")), "{problems:?}");
        }
    }

    #[test]
    fn fuse_is_refused_unless_the_kernel_keeps_this_user_out() {
        let gvfs = "60 49 0:51 / /run/user/1000/gvfs rw,nosuid,nodev,relatime shared:30 - \
                    fuse.gvfsd-fuse gvfsd-fuse rw,user_id=1000,group_id=1000\n";
        let p = judged(gvfs);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(
            p[0].contains("fuse.gvfsd-fuse") && p[0].contains("FUSE"),
            "{p:?}"
        );
        for line in [
            "60 25 0:51 / /mnt/remote rw - fuse.sshfs me@host:/ rw,user_id=1000,group_id=1000",
            "60 25 0:51 / /mnt/remote rw - fuse.rclone remote: rw,user_id=1000,group_id=1000",
            "60 25 0:51 / /mnt/win rw - fuseblk /dev/sdb1 rw,user_id=0,group_id=0,allow_other",
            // Another user's, but open to every user.
            "60 25 0:51 / /mnt/x rw - fuse.sshfs h:/ rw,user_id=1001,group_id=1001,allow_other",
            "60 25 0:51 / /mnt/x rw - fuse src rw",
        ] {
            assert_eq!(judged(&format!("{line}\n")).len(), 1, "{line}");
        }
        // Another user's, without allow_other: the kernel refuses this user's lookups.
        assert!(judged(
            "60 25 0:51 / /home/other/remote rw - fuse.sshfs h:/ rw,user_id=1001,group_id=1001\n"
        )
        .is_empty());
        // ...unless this process is root.
        let mounts = parse_mountinfo(&format!(
            "{HOST}60 25 0:51 / /home/other/remote rw - fuse.sshfs h:/ rw,user_id=1001,group_id=1001\n"
        ))
        .unwrap();
        assert_eq!(judge(&mounts, 25, 0).len(), 1);
    }

    #[test]
    fn automount_points_are_judged_by_what_they_mount() {
        // The host's binfmt_misc automount, triggered: fine (HOST). Not triggered: refused until it
        // is (the check triggers a direct one before judging).
        let idle = HOST.replace(
            "48 37 0:38 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime shared:24 - binfmt_misc binfmt_misc rw\n",
            "",
        );
        let p = judge(&parse_mountinfo(&idle).unwrap(), 25, 1000);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("could not be seen"), "{p:?}");
        // A direct automount of the EFI partition, mounted: fine.
        assert!(judged(
            "60 46 0:52 / /boot/efi2 rw - autofs systemd-1 rw,fd=50,pgrp=1,timeout=120,minproto=5,maxproto=5,direct\n\
             61 60 8:1 / /boot/efi2 rw - vfat /dev/sda1 rw\n"
        )
        .is_empty());
        // A direct automount of an NFS share: refused, twice over.
        let p = judged(
            "60 25 0:52 / /srv/data rw - autofs systemd-1 rw,fd=50,pgrp=1,timeout=0,minproto=5,maxproto=5,direct\n\
             61 60 0:53 / /srv/data rw - nfs4 nas:/data rw\n",
        );
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p.iter().any(|l| l.contains("mounts nfs4")), "{p:?}");
        // An indirect map (/net with the hosts map): refused, mounted entries or not.
        let p = judged(
            "60 25 0:52 / /net rw - autofs -hosts rw,fd=7,pgrp=900,timeout=300,minproto=5,maxproto=5,indirect\n",
        );
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("whatever a lookup names"), "{p:?}");
        // An automount point mounted over and then covered by its own mount stays reachable.
        let mounts = parse_mountinfo(&format!(
            "{HOST}60 25 0:52 / /srv/data rw - autofs systemd-1 rw,direct\n61 60 0:53 / /srv/data rw - ext4 /dev/sdc rw\n"
        ))
        .unwrap();
        let reach = reachable(&mounts, 25);
        assert!(reach[mounts.len() - 2] && reach[mounts.len() - 1]);
    }

    #[test]
    fn a_hidden_mount_is_left_out_and_nothing_else() {
        // An NFS share mounted over by a tmpfs at the same point (systemd's InaccessiblePaths=):
        // no path reaches it.
        assert!(judged(
            "60 25 0:50 / /mnt/share rw - nfs nas:/x rw\n61 60 0:54 / /mnt/share rw - tmpfs tmpfs rw\n"
        )
        .is_empty());
        // ...or below a directory mounted over later (TemporaryFileSystem=/mnt).
        assert!(judged(
            "60 25 0:50 / /mnt/share rw - nfs nas:/x rw\n61 25 0:54 / /mnt rw - tmpfs tmpfs rw\n"
        )
        .is_empty());
        // But a share mounted below that tmpfs (its child) is reachable.
        assert_eq!(
            judged("61 25 0:54 / /mnt rw - tmpfs tmpfs rw\n60 61 0:50 / /mnt/share rw - nfs nas:/x rw\n")
                .len(),
            1
        );
        // A mount over a sibling path hides nothing.
        assert_eq!(
            judged("60 25 0:50 / /mnt/share rw - nfs nas:/x rw\n61 25 0:54 / /mnt/sha rw - tmpfs tmpfs rw\n")
                .len(),
            1
        );
        // Two mounts on one point of one parent: the table cannot tell, so both count.
        assert_eq!(
            judged(
                "60 25 0:50 / /mnt/a rw - nfs nas:/x rw\n61 25 0:54 / /mnt/a rw - tmpfs tmpfs rw\n"
            )
            .len(),
            1
        );
        // A mount stacked on the root itself: whether this process sees it depends on when its root
        // was set, so it counts.
        assert_eq!(judged("60 25 0:50 / / rw - nfs nas:/root rw\n").len(), 1);
        // A share on the original root, which a later mount on the root covers, counts too: this
        // process may still have the original root.
        assert_eq!(
            judged("60 25 0:54 / / rw - ext4 /dev/sdz rw\n61 25 0:50 / /mnt/share rw - nfs nas:/x rw\n")
                .len(),
            1
        );
        // An unknown root: everything counts.
        let mounts = parse_mountinfo(
            "1 0 0:1 / / rw - ext4 /dev/sda rw\n2 1 0:2 / /x rw - tmpfs t rw\n3 2 0:3 / /x rw - nfs n:/ rw\n",
        )
        .unwrap();
        assert!(reachable(&mounts, 99).iter().all(|r| *r));
        assert!(!reachable(&mounts, 1)[1], "covered by the share");
    }

    #[test]
    fn escapes_and_odd_lines() {
        let mounts = parse_mountinfo(
            "60 25 0:50 / /mnt/my\\040share rw shared:1 master:2 - nfs nas:/a\\040b rw,addr=10.0.0.5\n",
        )
        .unwrap();
        assert_eq!(mounts[0].mount_point(), PathBuf::from("/mnt/my share"));
        assert_eq!(mounts[0].fstype, "nfs");
        assert_eq!(unescape("a\\134b\\011c\\012"), b"a\\b\tc\n");
        assert_eq!(unescape("\\999\\04"), b"\\999\\04");
        assert!(parse_mountinfo("60 25 0:50 / /x rw nfs a b\n").is_err());
        assert!(parse_mountinfo("x 25 0:50 / /x rw - nfs a b\n").is_err());
        assert!(parse_mountinfo("60 25 0:50 / /x rw -\n").is_err());
        // Mount options that are a lone dash are not mistaken for the separator.
        assert!(parse_mountinfo("60 25 0:50 / /x - - nfs a b\n").is_ok());
    }

    #[test]
    fn local_types_have_local_magics() {
        for t in [
            "ext4", "xfs", "btrfs", "tmpfs", "proc", "sysfs", "overlay", "squashfs",
        ] {
            assert_eq!(kind_of(t), Kind::Local);
        }
        for (m, _) in OTHER_MAGICS {
            assert!(!local_magic(*m), "{m:#x}");
        }
        assert_eq!(magic_name(0x6969), "nfs");
        assert_eq!(magic_name(0x1234_5678), "filesystem magic 0x12345678");
    }

    #[test]
    fn this_host_is_local() {
        // The test's own process: its table, its paths, its fds.
        let r = check_local_filesystems(&[PathBuf::from("/usr"), PathBuf::from("/proc")]);
        assert!(r.is_ok(), "{r:?}");
        let r = r.unwrap();
        assert!(
            r.reachable_mounts > 3 && r.paths == 2 && r.open_files >= 1,
            "{r:?}"
        );
    }
}
