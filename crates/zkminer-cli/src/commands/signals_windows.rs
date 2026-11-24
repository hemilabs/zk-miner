//! The shutdown ladder's signals on Windows: the console's control events in place of SIGINT and
//! SIGTERM (see the unix task in `run.rs`, which this mirrors).
//!
//! - Ctrl+C / Ctrl+Break: a person at the console, who can escalate. 1st DRAIN (stop claiming,
//!   let in-flight proofs finish), 2nd ABANDON (release what can be released), 3rd force exit. In
//!   the dashboard, Ctrl+C is a key (raw mode) that asks how to stop, like `q`; Ctrl+Break is still
//!   a signal, and starts DRAIN. During a keep-locks stop, stage 2 keeps the locks.
//! - Closing the console window, or Windows shutting down: nobody is there to press anything, and
//!   Windows ends the process seconds later (tokio's handler holds it until then), enough for one
//!   release at most. A keep-locks stop: the locks stay for the next start (as when a close killed
//!   the miner outright), except one too close to its deadline to wait for it.
//!
//! Logoff is NOT handled: Windows sends it to every console process when ANY user logs off,
//! including a miner running as a service, which must not stop because an administrator signed out.
//! (Windows also stops delivering close/shutdown events to a process that has loaded user32, which
//! a GPU runtime may do; then those end the process as before.)
//!
//! Without this, Windows had a single `ctrl_c()` in headless mode and nothing at all after the TUI
//! quit: a second Ctrl+C could not abandon the drain (although the drain said to press it), and
//! closing the window stranded every held lock until the next start.

use std::sync::atomic::Ordering;
use zkminer_tui::state::SharedState;

/// Which console event arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    /// Ctrl+C or Ctrl+Break.
    Interrupt,
    /// The window closing, or a system shutdown.
    Close,
}

/// The ladder stage after `event`, given the stage `n` already reached; `None` leaves it unchanged.
fn next_stage(n: u8, event: Event) -> Option<u8> {
    match event {
        Event::Interrupt => Some(n.saturating_add(1)),
        // A close never force-exits: Windows ends the process itself, and the seconds it leaves are
        // for the releases already under way.
        Event::Close if n >= 2 => None,
        Event::Close => Some(n + 1),
    }
}

/// Await an optional listener; a missing one never fires.
macro_rules! recv_opt {
    ($l:expr) => {
        async {
            match $l.as_mut() {
                Some(l) => {
                    l.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
    };
}

/// Install the console handlers now and drive the shutdown ladder on `sig_tx`.
pub(crate) fn spawn(sig_tx: tokio::sync::watch::Sender<u8>, state: SharedState) {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};
    // Registered here, synchronously, so an event that arrives before the task first polls is
    // still seen (a listener created after the event never observes it).
    let (mut c, mut brk, mut close, mut shutdown) = (
        ctrl_c().ok(),
        ctrl_break().ok(),
        ctrl_close().ok(),
        ctrl_shutdown().ok(),
    );
    if c.is_none() || brk.is_none() || close.is_none() || shutdown.is_none() {
        tracing::error!(
            "could not install every console control handler (Ctrl+C {}, Ctrl+Break {}, close {}, \
             shutdown {}); the missing ones end the process without releasing held jobs",
            c.is_some(),
            brk.is_some(),
            close.is_some(),
            shutdown.is_some()
        );
    }
    // The task holds `sig_tx` for the life of the process: dropping it would read as "shut down now".
    tokio::spawn(async move {
        let mut n = 0u8;
        loop {
            let event = tokio::select! {
                _ = recv_opt!(c) => Event::Interrupt,
                _ = recv_opt!(brk) => Event::Interrupt,
                _ = recv_opt!(close) => Event::Close,
                _ = recv_opt!(shutdown) => Event::Close,
            };
            // From the stage the ladder is at, however it got there (the dashboard's quit prompt
            // and `zkminer stop` advance it too) — but a stage-2 ABANDON another reached is not
            // this task's to escalate past: the first interrupt to see it does not force an exit.
            if event == Event::Interrupt && *sig_tx.borrow() >= 2 && n < 2 {
                n = 2;
                super::run::shutdown_say(&state, super::run::ALREADY_RELEASING_MSG).await;
                continue;
            }
            n = n.max(*sig_tx.borrow());
            let supervised = event == Event::Close;
            // Closing the window, or Windows shutting down (an update's reboot, a service stop):
            // Windows ends the process within seconds, enough for one release at most, so
            // abandoning would pay penalties for little. Keep the locks instead, as a keep-locks
            // stop (which still releases a lock too close to its deadline to wait for the next
            // start): the next start finishes them, as it did when the window close killed the
            // miner outright. Once a stop is under way, a close changes nothing but the wait.
            if supervised && *sig_tx.borrow() < 2 && !super::run::keep_in_progress() {
                super::run::SUPERVISED_STOP.store(true, Ordering::SeqCst);
                {
                    let mut st = state.write().await;
                    st.shutdown_requested = true;
                    st.paused = true;
                }
                super::run::shutdown_say(
                    &state,
                    "\nWINDOW CLOSING / SHUTDOWN — keeping the locks for the next start (Windows \
                     ends the process within seconds). Start the miner again soon.",
                )
                .await;
                let _ = super::run::apply_stop_request(
                    zkminer_tui::state::StopMode::KeepLocks,
                    &sig_tx,
                    &state,
                )
                .await;
                n = n.max(1);
                continue;
            }
            let Some(stage) = next_stage(n, event) else {
                // A close past ABANDON changes nothing but the release wait, now Windows' seconds.
                if supervised {
                    super::run::SUPERVISED_STOP.store(true, Ordering::SeqCst);
                }
                continue;
            };
            if supervised {
                super::run::SUPERVISED_STOP.store(true, Ordering::SeqCst);
            }
            // Break the TUI out of its event loop so `run()` reaches the ladder.
            {
                let mut st = state.write().await;
                st.shutdown_requested = true;
                st.paused = true;
            }
            match stage {
                1 | 2 if supervised => {
                    let closing = "\nWINDOW CLOSING / SHUTDOWN — releasing held jobs now (Windows \
                                   ends the process within seconds; no proof could finish).";
                    match stage {
                        2 if super::run::keep_in_progress() => {
                            super::run::shutdown_say(&state, super::run::KEEP_SIGNAL_MSG).await
                        }
                        2 => match super::run::begin_abandon() {
                            Ok(()) => super::run::shutdown_say(&state, closing).await,
                            Err(why) => super::run::shutdown_say(&state, why).await,
                        },
                        _ if super::run::keep_in_progress() => {
                            super::run::shutdown_say(&state, super::run::KEEP_SIGNAL_MSG).await
                        }
                        _ => super::run::shutdown_say(&state, closing).await,
                    }
                }
                1 => {
                    // On the dashboard Ctrl+C is a key, which does not escalate; Ctrl+Break does.
                    let again = if super::run::tui_up() {
                        "Press Ctrl+Break again (or [a] on the dashboard)"
                    } else {
                        "Press Ctrl+C again (or run `zkminer stop --abandon`)"
                    };
                    super::run::shutdown_say(
                        &state,
                        format!(
                            "\nDRAINING — finishing in-flight proofs, no new claims. {again} to \
                             ABANDON (release jobs), a third time to force-exit."
                        ),
                    )
                    .await
                }
                2 if super::run::keep_in_progress() => {
                    super::run::shutdown_say(&state, super::run::KEEP_SIGNAL_MSG).await
                }
                2 => match super::run::begin_abandon() {
                    Ok(()) => {
                        super::run::shutdown_say(
                            &state,
                            "\nABANDONING — releasing jobs, nearest deadline first...",
                        )
                        .await
                    }
                    Err(why) => super::run::shutdown_say(&state, why).await,
                },
                _ => super::run::force_exit(),
            }
            n = stage;
            super::run::raise_stage(&sig_tx, n);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{next_stage, Event};
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    extern "system" {
        fn GenerateConsoleCtrlEvent(event: u32, process_group: u32) -> i32;
        fn GetConsoleWindow() -> *mut std::ffi::c_void;
    }
    const CTRL_BREAK_EVENT: u32 = 1;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CHILD: &str = "ZKMINER_TEST_SIGNAL_LADDER_CHILD";

    /// The stage arithmetic, both modes: the same values the unix task sends.
    #[test]
    fn stages_match_the_unix_ladder() {
        use Event::*;
        // Headless: drain, abandon, force.
        assert_eq!(next_stage(0, Interrupt), Some(1));
        assert_eq!(next_stage(1, Interrupt), Some(2));
        assert_eq!(next_stage(2, Interrupt), Some(3));
        // Headless close: a supervised drain (stage 1, like SIGTERM), then never past 2.
        assert_eq!(next_stage(0, Close), Some(1));
        assert_eq!(next_stage(1, Close), Some(2));
        assert_eq!(next_stage(2, Close), None, "a close never force-exits");
        // A stop begun elsewhere (the dashboard's quit prompt, `zkminer stop`) set stage 1: the
        // caller passes that in, and the next Ctrl+C abandons.
        assert_eq!(next_stage(1, Interrupt), Some(2));
    }

    /// The child half of `ctrl_break_walks_the_ladder`: install the handlers and print each stage.
    #[tokio::test]
    #[ignore = "run by ctrl_break_walks_the_ladder in its own process group"]
    async fn ladder_child() {
        if std::env::var(CHILD).is_err() {
            return;
        }
        let (tx, mut rx) = tokio::sync::watch::channel(0u8);
        super::spawn(tx, zkminer_tui::state::new_shared_state());
        println!("ready");
        loop {
            rx.changed().await.unwrap();
            println!("stage {}", *rx.borrow());
        }
    }

    /// Kills the child if the test fails part-way.
    struct KillOnDrop(Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Real console events: Ctrl+Break (what one console process can send another's group; Ctrl+C
    /// is handled the same way) drains, then abandons, then force-exits with 130.
    #[test]
    fn ctrl_break_walks_the_ladder() {
        use std::os::windows::process::CommandExt;
        // SAFETY: plain kernel32 call.
        if unsafe { GetConsoleWindow() }.is_null() {
            eprintln!("no console attached: console control events cannot be sent; skipped");
            return;
        }
        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "commands::signals_windows::tests::ladder_child",
                ])
                .args(["--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .creation_flags(CREATE_NEW_PROCESS_GROUP)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let out = child.0.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let wait_for = |want: &str| loop {
            let line = rx
                .recv_timeout(Duration::from_secs(30))
                .unwrap_or_else(|e| panic!("no {want:?} from the child: {e}"));
            if line.contains(want) {
                return;
            }
        };
        let pid = child.0.id();
        // SAFETY: plain kernel32 call; the group is the child's own (its pid).
        let send = || assert!(unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) } != 0);
        wait_for("ready");
        send();
        wait_for("stage 1");
        send();
        wait_for("stage 2");
        send();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(s) = child.0.try_wait().unwrap() {
                break s;
            }
            assert!(std::time::Instant::now() < deadline, "no force exit");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(status.code(), Some(130), "the third Ctrl+Break force-exits");
    }
}
