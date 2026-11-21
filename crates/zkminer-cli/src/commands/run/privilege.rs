//! A miner run as root (review r4 LD2).
//!
//! Its workers drop every capability first thing (`zkminer_witness_sandbox::drop_all_capabilities`),
//! and their seccomp filters refuse the host-control syscalls, so a guest that escaped its executor
//! in one gets neither the kernel nor the clock. They still run as uid 0, though, and Landlock's
//! grants do not look at the uid: what a worker may read (`/etc` among the system paths, its own
//! directory) includes files only root may read, such as `/etc/shadow`, SSH host keys and a
//! service's `EnvironmentFile`. So the miner is not refused as root (the dashboard's GPU tuning
//! needs root), but a bare-metal run as root is a `PAGE:`, and `zkminer doctor` warns of it.
//!
//! A container's root is another matter: its `/etc` holds nothing of the host's, and Docker's
//! default capability set and seccomp profile already refuse what root would add. It is a warning
//! there, with what narrows it further.

/// Where a miner runs, as far as its uid goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRun {
    /// An unprivileged uid: nothing to say.
    NotRoot,
    /// uid 0 in a container (Docker, Podman, systemd-nspawn, ...).
    Container,
    /// uid 0 on the host itself.
    BareHost,
}

/// What `euid` and `in_container` make of a run.
pub(crate) fn root_run(euid: u32, in_container: bool) -> RootRun {
    match (euid, in_container) {
        (0, true) => RootRun::Container,
        (0, false) => RootRun::BareHost,
        _ => RootRun::NotRoot,
    }
}

/// [`root_run`] for this process: its effective uid, and whether it runs in a container (Docker's
/// `/.dockerenv`, Podman's `/run/.containerenv`, or the `container` variable systemd-nspawn, LXC
/// and Podman set).
#[cfg(target_os = "linux")]
pub(crate) fn root_run_here() -> RootRun {
    // SAFETY: geteuid cannot fail.
    let euid = unsafe { libc::geteuid() };
    let in_container = std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || std::env::var_os("container").is_some_and(|v| !v.is_empty());
    root_run(euid, in_container)
}

/// The start-up line for `run`, if any: a `PAGE:` on a bare host, a warning in a container.
pub(crate) fn startup_line(run: RootRun) -> Option<String> {
    match run {
        RootRun::NotRoot => None,
        RootRun::BareHost => Some(
            "PAGE: RUNNING-AS-ROOT the miner runs as root on this host. Its workers drop every \
             capability before their first guest, but they still run as uid 0, which owns root's \
             files: a guest that escaped its executor could read the ones a worker may (/etc among \
             them: /etc/shadow, SSH host keys, a service's environment file). Run the miner as an \
             unprivileged user in the render and video groups (contrib/zkminer.service shows how); \
             only the dashboard's GPU tuning needs root"
                .to_string(),
        ),
        RootRun::Container => Some(
            "the miner runs as root in a container. Its workers drop every capability before their \
             first guest; to narrow it further, run the container with --user <uid that owns the \
             volume>, or at least with --cap-drop=ALL --security-opt no-new-privileges"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_uid_0_counts_and_a_container_is_told_apart() {
        assert_eq!(root_run(0, false), RootRun::BareHost);
        assert_eq!(root_run(0, true), RootRun::Container);
        for euid in [1, 999, 1000, 65534, u32::MAX] {
            for in_container in [false, true] {
                assert_eq!(root_run(euid, in_container), RootRun::NotRoot, "{euid}");
            }
        }
    }

    #[test]
    fn a_bare_host_root_run_pages_and_a_container_warns() {
        assert_eq!(startup_line(RootRun::NotRoot), None);
        let bare = startup_line(RootRun::BareHost).unwrap();
        assert!(bare.starts_with("PAGE: RUNNING-AS-ROOT "), "{bare}");
        let container = startup_line(RootRun::Container).unwrap();
        assert!(!container.contains("PAGE:"), "{container}");
        assert!(container.contains("--user"), "{container}");
        // No runs of spaces from a line break inside the literal.
        for line in [bare, container] {
            assert!(!line.contains("  "), "{line}");
        }
    }
}
