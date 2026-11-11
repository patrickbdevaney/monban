//! sd-notify integration (READY / RELOADING / MAINPID / STOPPING / STATUS). A no-op when not under systemd
//! (`NOTIFY_SOCKET` unset): every call returns `Ok(())` without touching the network or the environment.

use sd_notify::NotifyState;

/// Notifier bound to the environment at construction.
#[derive(Debug, Clone, Copy)]
pub struct Notifier {
    enabled: bool,
}

impl Notifier {
    /// Enabled iff `NOTIFY_SOCKET` is set.
    pub fn from_env() -> Self {
        Self { enabled: std::env::var_os("NOTIFY_SOCKET").is_some() }
    }
    /// A notifier that never sends anything.
    pub fn disabled() -> Self {
        Self { enabled: false }
    }
    /// Whether messages are sent.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    fn send(&self, st: &[NotifyState<'_>]) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        sd_notify::notify(st)
    }
    /// READY=1.
    pub fn ready(&self) -> std::io::Result<()> {
        self.send(&[NotifyState::Ready])
    }
    /// RELOADING=1 + MONOTONIC_USEC (required by systemd ≥ 253 Type=notify-reload).
    pub fn reloading(&self) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let now = NotifyState::monotonic_usec_now()?;
        self.send(&[NotifyState::Reloading, now])
    }
    /// MAINPID=<pid> then READY=1: the upgraded child is now the service's main process.
    pub fn main_pid(&self, pid: u32) -> std::io::Result<()> {
        self.send(&[NotifyState::MainPid(pid), NotifyState::Ready])
    }
    /// STOPPING=1.
    pub fn stopping(&self) -> std::io::Result<()> {
        self.send(&[NotifyState::Stopping])
    }
    /// STATUS=<s>.
    pub fn status(&self, s: &str) -> std::io::Result<()> {
        self.send(&[NotifyState::Status(s)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    #[test]
    fn disabled_is_noop() {
        let n = Notifier::disabled();
        assert!(!n.enabled());
        assert!(n.ready().is_ok() && n.reloading().is_ok() && n.main_pid(1).is_ok() && n.stopping().is_ok());
    }

    /// Child half of `sends_under_notify_socket`: runs only when re-executed with the env set.
    #[test]
    fn notify_child_helper() {
        if std::env::var_os("AEGIS_NOTIFY_TEST_CHILD").is_none() {
            return;
        }
        let n = Notifier::from_env();
        assert!(n.enabled());
        assert!(n.reloading().is_ok());
        assert!(n.main_pid(4242).is_ok());
    }

    /// Spawns this test binary with NOTIFY_SOCKET pointing at a datagram socket and checks the wire messages.
    #[test]
    fn sends_under_notify_socket() {
        let dir = std::env::temp_dir().join(format!("monban-notify-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir(&dir).is_err() {
            return;
        }
        let sock = dir.join("n.sock");
        let Ok(rx) = UnixDatagram::bind(&sock) else { return };
        let _ = rx.set_read_timeout(Some(Duration::from_secs(20)));
        let Ok(exe) = std::env::current_exe() else { return };
        let st = std::process::Command::new(exe)
            .args(["--exact", "notify::tests::notify_child_helper", "--test-threads=1"])
            .env("AEGIS_NOTIFY_TEST_CHILD", "1")
            .env("NOTIFY_SOCKET", &sock)
            .stdout(std::process::Stdio::null())
            .status();
        assert!(st.map(|s| s.success()).unwrap_or(false));
        let mut buf = [0u8; 512];
        let mut msgs = Vec::new();
        for _ in 0..2 {
            let n = rx.recv(&mut buf).unwrap_or(0);
            msgs.push(String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).to_string());
        }
        let _ = std::fs::remove_dir_all(&dir);
        let m0 = msgs.first().cloned().unwrap_or_default();
        assert!(m0.contains("RELOADING=1\n") && m0.contains("MONOTONIC_USEC="), "{m0:?}");
        assert_eq!(msgs.get(1).map(String::as_str), Some("MAINPID=4242\nREADY=1\n"));
    }
}
