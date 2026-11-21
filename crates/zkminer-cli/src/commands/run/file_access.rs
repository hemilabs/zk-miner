//! Linux: who can read the key's files, and who can replace what the miner runs (review r6 LS1,
//! LS3).
//!
//! - **The key's files.** With `key_source = "env"` the key usually comes from a systemd unit's
//!   `EnvironmentFile` (`contrib/zkminer.service`: [`UNIT_ENV_FILE`]). systemd reads it as root
//!   before it starts the miner, so it should be root's and private to root. One written with an
//!   editor or `tee` under the usual umask is 0644, readable by every local user. With `key_source =
//!   "file"`, the key file should be private to this user (or to root). Group or other bits, or
//!   another owner, are a `PAGE: KEY-FILE-READABLE` at start-up and a doctor failure. A guest that
//!   escaped its executor cannot read the miner's files in `/etc`, whatever their mode
//!   (`zkminer_witness_sandbox::confine::ETC_DENIED`).
//! - **Who can replace the miner.** The Linux counterpart of the Windows check
//!   (`windows_account::writers_of`) covers the miner's program, its configuration, its workers
//!   (those configured and those in the directories searched for them), `~/.sp1/bin`, and the
//!   unit's `ExecStart` and environment files. Each of these, and every directory above it, must
//!   be owned by root or this user and writable by no one else; a sticky directory above them is
//!   fine. Whoever else can write one can run code as the miner's account, key included.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zkminer_config::config::WalletConfig;
use zkminer_config::ZkMinerConfig;

/// The environment file `contrib/zkminer.service` names.
pub(crate) const UNIT_ENV_FILE: &str = "/etc/zkminer/env";

/// The systemd unit the miner is documented to run as (`contrib/zkminer.service`).
pub(crate) const SERVICE: &str = "zkminer.service";

/// Why the file of mode `mode` owned by `uid`, which holds a secret, is not private to one of
/// `owners`: its group or other users may read or change it, or it belongs to someone else. `None`
/// if it is private.
pub(crate) fn secret_exposure(mode: u32, uid: u32, owners: &[u32]) -> Option<String> {
    let mut why = Vec::new();
    if mode & 0o077 != 0 {
        let read = mode & 0o044 != 0;
        let write = mode & 0o022 != 0;
        why.push(format!(
            "mode {:04o}: {} its group or other users",
            mode & 0o7777,
            match (read, write) {
                (true, true) => "readable and writable by",
                (true, false) => "readable by",
                (false, true) => "writable by",
                (false, false) => "open to",
            }
        ));
    }
    if !owners.contains(&uid) {
        why.push(format!("owned by uid {uid}"));
    }
    (!why.is_empty()).then(|| why.join(", "))
}

/// The files on the `EnvironmentFiles=` lines of `systemctl show` output: one line per file,
/// `EnvironmentFiles=<path> (ignore_errors=<yes|no>)`.
pub(crate) fn environment_files(props: &str) -> Vec<PathBuf> {
    props
        .lines()
        .filter_map(|l| l.strip_prefix("EnvironmentFiles="))
        .map(|v| {
            let v = v.trim_end();
            v.rsplit_once(" (ignore_errors=").map_or(v, |(p, _)| p)
        })
        .filter(|p| p.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

/// The program on the `ExecStart=` line of `systemctl show` output:
/// `ExecStart={ path=<program> ; argv[]=… }`.
pub(crate) fn exec_start_program(props: &str) -> Option<PathBuf> {
    let value = props.lines().find_map(|l| l.strip_prefix("ExecStart="))?;
    let rest = value.split_once("path=")?.1;
    let program = rest.split(" ;").next()?.trim();
    program.starts_with('/').then(|| PathBuf::from(program))
}

/// The value of `key` in `systemctl show` output.
fn property<'a>(props: &'a str, key: &str) -> Option<&'a str> {
    props
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(str::trim)
}

/// `systemctl [--user] show` of `unit`'s `props` (comma-separated), if it ran and the unit is
/// loaded.
fn unit_properties(unit: &str, user: bool, props: &str) -> Option<String> {
    let mut cmd = std::process::Command::new("systemctl");
    if user {
        cmd.arg("--user");
    }
    cmd.args(["show", &format!("--property=LoadState,{props}"), "--", unit])
        .stdin(std::process::Stdio::null());
    let (outcome, out) = zkminer_prover_protocol::proc::output_with_timeout_capturing_stdout(
        &mut cmd,
        Duration::from_secs(5),
        64 * 1024,
    );
    let ran = matches!(
        outcome,
        zkminer_prover_protocol::proc::Outcome::Ran { success: true, .. }
    );
    (ran && property(&out, "LoadState") == Some("loaded")).then_some(out)
}

/// The installed [`SERVICE`]'s `EnvironmentFiles` and `ExecStart`, if it is loaded (for `zkminer
/// doctor`, which runs from a shell, not in the unit).
pub(crate) fn installed_service() -> Option<String> {
    unit_properties(SERVICE, false, "EnvironmentFiles,ExecStart")
}

/// The systemd unit this process runs in, and whether a user manager runs it: under systemd only
/// (`INVOCATION_ID`, which systemd sets for a unit's processes).
fn own_unit() -> Option<(String, bool)> {
    std::env::var_os("INVOCATION_ID")?;
    match zkminer_witness_sandbox::own_systemd_unit()? {
        zkminer_witness_sandbox::SystemdUnit::System(u) => Some((u, false)),
        zkminer_witness_sandbox::SystemdUnit::User(u) => Some((u, true)),
        _ => None,
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() }
}

/// A file that holds the key, or may, and is not private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExposedKeyFile {
    pub path: PathBuf,
    /// [`secret_exposure`]'s reason.
    pub why: String,
    /// The commands that make it private.
    pub fix: String,
}

/// The key's files that are not private ([`secret_exposure`]), each followed through links as
/// systemd and the miner read it:
/// - `env` key: [`UNIT_ENV_FILE`] and `env_files` (a unit's environment files, `user_unit` if a
///   user manager reads them). They must be root's, or this user's for a user unit.
/// - `file` key: the key file, which must be this user's or root's (a systemd credential).
///
/// A file that is missing, or that this user cannot stat (a directory above it is private), is
/// not reported.
pub(crate) fn exposed_key_files(
    wallet: &WalletConfig,
    env_files: &[PathBuf],
    user_unit: bool,
) -> Vec<ExposedKeyFile> {
    let own = euid();
    let mut checked: Vec<(PathBuf, Vec<u32>)> = Vec::new();
    match wallet.key_source.as_str() {
        "env" => {
            checked.push((PathBuf::from(UNIT_ENV_FILE), vec![0]));
            let owners = if user_unit { vec![0, own] } else { vec![0] };
            checked.extend(env_files.iter().map(|p| (p.clone(), owners.clone())));
        }
        "file" => {
            if let Some(p) = wallet.key_file_path.as_deref() {
                checked.push((PathBuf::from(p), vec![own, 0]));
            }
        }
        _ => {}
    }
    let mut seen = std::collections::BTreeSet::new();
    checked
        .into_iter()
        .filter(|(p, _)| seen.insert(p.clone()))
        .filter_map(|(path, owners)| {
            let meta = std::fs::metadata(&path).ok()?;
            let why = secret_exposure(meta.mode(), meta.uid(), &owners)?;
            let p = path.display();
            let fix = if owners == [0] {
                format!("sudo chown root:root {p} && sudo chmod 600 {p}")
            } else {
                format!("chmod 600 {p}, as the user the miner runs as")
            };
            Some(ExposedKeyFile { path, why, fix })
        })
        .collect()
}

/// The start-up pages of [`exposed_key_files`], with the environment files of the unit this
/// process runs in. Not a refusal: the key is loaded already, and refusing would only leave held
/// locks undriven.
pub(crate) fn key_file_pages(wallet: &WalletConfig) -> Vec<String> {
    let (env_files, user_unit) = match own_unit() {
        Some((unit, user)) if wallet.key_source == "env" => (
            unit_properties(&unit, user, "EnvironmentFiles")
                .map(|p| environment_files(&p))
                .unwrap_or_default(),
            user,
        ),
        _ => (Vec::new(), false),
    };
    exposed_key_files(wallet, &env_files, user_unit)
        .into_iter()
        .map(|e| {
            format!(
                "PAGE: KEY-FILE-READABLE {} ({}) may hold the signing key: other users of this \
                 host could read or change it. Run `{}`, and if others could read it, consider \
                 the key exposed",
                e.path.display(),
                e.why,
                e.fix
            )
        })
        .collect()
}

/// `zkminer doctor`: [`exposed_key_files`] with the installed [`SERVICE`]'s environment files
/// (`service`: [`installed_service`]'s output), each as a failure's text.
pub(crate) fn key_file_findings(wallet: &WalletConfig, service: Option<&str>) -> Vec<String> {
    let env_files = service.map(environment_files).unwrap_or_default();
    exposed_key_files(wallet, &env_files, false)
        .into_iter()
        .map(|e| {
            format!(
                "{} ({}) may hold the key, and other users of this host could read or change it \
                 (`zkminer run` pages KEY-FILE-READABLE): `{}`",
                e.path.display(),
                e.why,
                e.fix
            )
        })
        .collect()
}

/// Why another user could replace the file or directory of mode `mode` owned by `uid`, if one
/// could: it belongs to someone other than root and `own`, or its group or others may write it. A
/// symbolic link's own mode means nothing. A sticky directory (`/tmp`) lets no one replace what is
/// not theirs in it, so it is fine above what is checked, but not as a directory searched for
/// workers (`searched`), where anyone could add one.
pub(crate) fn replace_risk(
    mode: u32,
    uid: u32,
    own: u32,
    dir: bool,
    symlink: bool,
    searched: bool,
) -> Option<String> {
    if uid != 0 && uid != own {
        return Some(format!("is owned by uid {uid}"));
    }
    if symlink || mode & 0o022 == 0 {
        return None;
    }
    if dir && mode & 0o1000 != 0 && !searched {
        return None;
    }
    Some(format!(
        "is writable by {} (mode {:04o})",
        if mode & 0o002 != 0 {
            "every user"
        } else {
            "its group"
        },
        mode & 0o7777
    ))
}

/// What [`replace_problems`] checks: this program, the configuration file `config_file`, the
/// worker binaries configured and those in the directories searched for them, `~/.sp1/bin` and
/// what is in it, and the installed unit's program and environment files (`service`:
/// [`installed_service`]'s output). Each is given with whether workers are searched for in it.
pub(crate) fn replace_targets(
    config: &ZkMinerConfig,
    config_file: &Path,
    service: Option<&str>,
) -> Vec<(PathBuf, bool)> {
    let mut targets: Vec<(PathBuf, bool)> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        targets.push((exe, false));
    }
    targets.push((config_file.to_path_buf(), false));
    targets.extend(
        config
            .prover
            .worker_binaries
            .values()
            .map(|p| (PathBuf::from(p), false)),
    );
    let searched = zkminer_prover::discovery::worker_search_dirs(
        &config
            .prover
            .worker_search_paths
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
    );
    for dir in &searched {
        if let Ok(entries) = std::fs::read_dir(dir) {
            targets.extend(
                entries
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with("zkminer-prove"))
                    })
                    .map(|e| (e.path(), false)),
            );
        }
        targets.push((dir.clone(), true));
    }
    if let Some(home) = dirs::home_dir() {
        let sp1_bin = home.join(".sp1").join("bin");
        if let Ok(entries) = std::fs::read_dir(&sp1_bin) {
            targets.extend(entries.flatten().map(|e| (e.path(), false)));
        }
        targets.push((sp1_bin, true));
    }
    if let Some(service) = service {
        targets.extend(exec_start_program(service).map(|p| (p, false)));
        targets.extend(environment_files(service).into_iter().map(|p| (p, false)));
    }
    targets
}

/// For each of `targets` (path, searched for workers) and every directory above it, both as named
/// and with links resolved, that another user could replace ([`replace_risk`]): the path and why.
/// What is missing is skipped (said elsewhere).
pub(crate) fn replace_problems(targets: &[(PathBuf, bool)]) -> Vec<(PathBuf, String)> {
    let own = euid();
    // Each path once, searched if it is searched for any target.
    let mut paths: BTreeMap<PathBuf, bool> = BTreeMap::new();
    for (target, searched) in targets {
        let resolved = std::fs::canonicalize(target).ok();
        for start in std::iter::once(target).chain(resolved.as_ref()) {
            if !start.is_absolute() {
                continue;
            }
            for (depth, p) in start.ancestors().enumerate() {
                let entry = paths.entry(p.to_path_buf()).or_insert(false);
                // The target itself (and what it resolves to), not the directories above it.
                *entry |= depth == 0 && *searched;
            }
        }
    }
    paths
        .into_iter()
        .filter_map(|(path, searched)| {
            let meta = std::fs::symlink_metadata(&path).ok()?;
            let why = replace_risk(
                meta.mode(),
                meta.uid(),
                own,
                meta.is_dir(),
                meta.file_type().is_symlink(),
                searched,
            )?;
            Some((path, why))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Review r6 LS1: 0600 and 0400 are private; any group or other bit, or a foreign owner, is
    /// not.
    #[test]
    fn a_secret_file_is_private_to_its_owner_only() {
        for mode in [0o100600, 0o100400, 0o600, 0o400, 0o700] {
            assert_eq!(secret_exposure(mode, 0, &[0]), None, "{mode:o}");
        }
        let world = secret_exposure(0o100644, 0, &[0]).unwrap();
        assert!(
            world.contains("0644") && world.contains("readable by"),
            "{world}"
        );
        let group = secret_exposure(0o640, 0, &[0]).unwrap();
        assert!(group.contains("readable by"), "{group}");
        let writable = secret_exposure(0o620, 0, &[0]).unwrap();
        assert!(writable.contains("writable by"), "{writable}");
        assert!(secret_exposure(0o601, 0, &[0]).is_some());
        // The miner's own user, for a key file; another user, never.
        assert_eq!(secret_exposure(0o600, 1000, &[1000, 0]), None);
        let foreign = secret_exposure(0o600, 1001, &[1000, 0]).unwrap();
        assert!(foreign.contains("uid 1001"), "{foreign}");
        // An environment file of the system unit is root's.
        assert!(secret_exposure(0o600, 1000, &[0]).is_some());
    }

    /// The shipped unit's environment file is the one checked, and the unit says how to create it
    /// private (review r6 LS1).
    #[test]
    fn the_shipped_unit_creates_its_environment_file_private() {
        let unit = include_str!("../../../../../contrib/zkminer.service");
        assert!(unit
            .lines()
            .any(|l| l.trim() == format!("EnvironmentFile=-{UNIT_ENV_FILE}")));
        assert!(
            unit.contains(&format!(
                "sudo install -m 600 -o root -g root /dev/null {UNIT_ENV_FILE}"
            )),
            "the unit's create command"
        );
        assert!(unit.contains(&format!("/run/credentials/{SERVICE}/")));
    }

    #[test]
    fn the_units_environment_files_and_program_are_read_from_systemctl() {
        let props = "LoadState=loaded\n\
                     EnvironmentFiles=/etc/zkminer/env (ignore_errors=yes)\n\
                     EnvironmentFiles=/etc/default/zk miner (ignore_errors=no)\n\
                     ExecStart={ path=/usr/local/bin/zkminer ; argv[]=/usr/local/bin/zkminer run \
                     --headless ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; \
                     code=(null) ; status=0/0 }\n";
        assert_eq!(
            environment_files(props),
            [
                PathBuf::from("/etc/zkminer/env"),
                PathBuf::from("/etc/default/zk miner")
            ]
        );
        assert_eq!(
            exec_start_program(props),
            Some(PathBuf::from("/usr/local/bin/zkminer"))
        );
        assert!(environment_files("LoadState=loaded\nEnvironmentFiles=\n").is_empty());
        assert_eq!(exec_start_program("ExecStart=\n"), None);
    }

    /// The key file's mode, read from disk: the warning `load_from_file` gives becomes a page.
    #[test]
    fn a_key_file_others_can_read_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        std::fs::write(&key, b"not a key").unwrap();
        let wallet = WalletConfig {
            key_source: "file".into(),
            key_file_path: Some(key.to_string_lossy().into_owned()),
            ..WalletConfig::default()
        };
        for (mode, exposed) in [(0o600, false), (0o400, false), (0o644, true), (0o660, true)] {
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
            let found = exposed_key_files(&wallet, &[], false);
            assert_eq!(found.len(), usize::from(exposed), "{mode:o}: {found:?}");
            if exposed {
                assert!(found[0].fix.contains("chmod 600"), "{:?}", found[0]);
            }
        }
        // An `env` key ignores the key file but checks the unit's environment files, as root's.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let env = WalletConfig {
            key_source: "env".into(),
            ..wallet.clone()
        };
        let found = exposed_key_files(&env, std::slice::from_ref(&key), false);
        assert!(found.iter().any(|e| e.path == key), "{found:?}");
        assert!(found
            .iter()
            .filter(|e| e.path == key)
            .all(|e| e.fix.starts_with("sudo chown root:root")));
        let pages = key_file_pages(&wallet);
        assert!(pages
            .iter()
            .all(|p| p.starts_with("PAGE: KEY-FILE-READABLE ") && !p.contains("  ")));
    }

    /// Review r6 LS3: only root or this user may own what the miner runs, and no one else may write
    /// it; a sticky directory is fine above it, not as a searched directory.
    #[test]
    fn who_can_replace_the_miner() {
        let own = 1000;
        assert_eq!(replace_risk(0o100755, 0, own, false, false, false), None);
        assert_eq!(replace_risk(0o40755, own, own, true, false, true), None);
        assert!(replace_risk(0o100755, 1001, own, false, false, false)
            .unwrap()
            .contains("uid 1001"));
        assert!(replace_risk(0o100775, own, own, false, false, false)
            .unwrap()
            .contains("its group"));
        assert!(replace_risk(0o40777, 0, own, true, false, false)
            .unwrap()
            .contains("every user"));
        // /tmp: fine above, not as a directory searched for workers.
        assert_eq!(replace_risk(0o41777, 0, own, true, false, false), None);
        assert!(replace_risk(0o41777, 0, own, true, false, true).is_some());
        // A link's own mode means nothing; its owner does.
        assert_eq!(replace_risk(0o120777, 0, own, false, true, false), None);
        assert!(replace_risk(0o120777, 1001, own, false, true, false).is_some());
    }

    #[test]
    fn a_group_writable_workers_directory_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let provers = dir.path().join("provers");
        std::fs::create_dir(&provers).unwrap();
        let worker = provers.join("zkminer-prove-risc0-cuda");
        std::fs::write(&worker, b"").unwrap();
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&provers, std::fs::Permissions::from_mode(0o755)).unwrap();
        let targets = [(worker.clone(), false), (provers.clone(), true)];
        let flagged = |found: &[(PathBuf, String)], p: &Path| found.iter().any(|(q, _)| q == p);
        let found = replace_problems(&targets);
        assert!(
            !flagged(&found, &provers) && !flagged(&found, &worker),
            "{found:?}"
        );
        std::fs::set_permissions(&provers, std::fs::Permissions::from_mode(0o775)).unwrap();
        let found = replace_problems(&targets);
        assert!(flagged(&found, &provers), "{found:?}");
        std::fs::set_permissions(&provers, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}
