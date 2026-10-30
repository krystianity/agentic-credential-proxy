//! The local control channel the menu bar app talks to: pause, resume, and a
//! few per-target counters.
//!
//! A Unix socket rather than a route, on purpose. Anything served on the bind
//! address is reachable by the agent, and the agent must not be able to unpause
//! the proxy it is being paused from. The socket is not on any network, only
//! answers processes running as the same user, and speaks three words.

use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::proxy::AppState;

#[derive(Default)]
struct Counts {
    allowed: u64,
    denied: u64,
    last_unix: Option<u64>,
}

pub struct Control {
    paused: AtomicBool,
    started: Instant,
    /// Unix time of the last forwarded request, or of startup or the last
    /// resume if later -- what the menu bar's idle auto-pause measures from.
    /// Denied requests do not count, or an agent hammering a blocked path
    /// would keep the proxy awake.
    last_active: AtomicU64,
    /// Keyed by the configured targets only, fixed at startup, so a caller
    /// spraying made-up provider names cannot grow it.
    counts: Mutex<BTreeMap<String, Counts>>,
}

impl Control {
    pub fn new<'a>(targets: impl IntoIterator<Item = &'a str>) -> Self {
        Control {
            paused: AtomicBool::new(false),
            started: Instant::now(),
            last_active: AtomicU64::new(now_unix()),
            counts: Mutex::new(
                targets
                    .into_iter()
                    .map(|t| (t.to_string(), Counts::default()))
                    .collect(),
            ),
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Counts one audited request against its target. Anything not configured
    /// is ignored rather than added.
    pub fn record(&self, target: &str, decision: &str) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let Some(c) = counts.get_mut(target) else {
            return;
        };
        if decision == "allow" {
            c.allowed += 1;
            self.last_active.store(now_unix(), Ordering::SeqCst);
        } else {
            c.denied += 1;
        }
        c.last_unix = Some(now_unix());
    }

    pub(crate) fn set_paused(&self, paused: bool) {
        if self.paused.swap(paused, Ordering::SeqCst) != paused {
            if !paused {
                // Otherwise resuming after a quiet night would be idle-paused
                // again on the menu bar's next look.
                self.last_active.store(now_unix(), Ordering::SeqCst);
            }
            let decision = if paused { "paused" } else { "resumed" };
            tracing::warn!(target: "audit", decision, "forwarding {decision} from the control socket");
        }
    }

    fn status(&self, bind: &str) -> serde_json::Value {
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let targets: Vec<_> = counts
            .iter()
            .map(|(name, c)| {
                serde_json::json!({
                    "name": name,
                    "allowed": c.allowed,
                    "denied": c.denied,
                    "last_unix": c.last_unix,
                })
            })
            .collect();
        serde_json::json!({
            "paused": self.is_paused(),
            "bind": bind,
            "uptime_s": self.started.elapsed().as_secs(),
            "idle_s": now_unix().saturating_sub(self.last_active.load(Ordering::SeqCst)),
            "targets": targets,
        })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One per instance, named by port, in a fixed directory the menu bar app
/// scans, so it finds every running instance without a copy of any config.
pub fn socket_path(port: u16) -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| {
        PathBuf::from(h)
            .join(".config")
            .join("agentic-credential-proxy")
            .join(format!("control-{port}.sock"))
    })
}

/// Best effort: the proxy works without its menu bar, so a socket that cannot
/// be bound is a warning, not a reason to refuse to serve.
pub fn spawn(state: Arc<AppState>) {
    let Some(path) = socket_path(state.config.bind.port()) else {
        tracing::warn!("HOME is unset; no control socket, so no menu bar");
        return;
    };
    let listener = match bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = format!("{e:#}"), "no control socket, so no menu bar");
            return;
        }
    };
    tracing::info!(path = %path.display(), "control socket");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let bind = state.config.bind.to_string();
                        // A client that connects and says nothing does not get
                        // to hold a task and a descriptor open forever.
                        let _ = tokio::time::timeout(
                            Duration::from_secs(2),
                            handle(&state.control, &bind, stream),
                        )
                        .await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "control socket accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });
}

fn bind(path: &Path) -> Result<UnixListener> {
    let dir = path.parent().context("socket path has no parent")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;

    // A socket left behind by a previous run is ours to replace; one another
    // instance is still answering on is not. Anything else at that path is
    // not a socket at all, and is left alone.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("another instance is already answering on {}", path.display());
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale {}", path.display()))?
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(_) => {}
    }

    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(listener)
}

/// One line in, one JSON line out, then close.
async fn handle(control: &Control, bind: &str, mut stream: UnixStream) -> std::io::Result<()> {
    // Same user only. The socket is 0600 inside a 0700 directory as well, but
    // the kernel's word on who is connecting does not depend on getting
    // permissions right.
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Ok(());
    }

    let (read, mut write) = stream.split();
    let mut line = String::new();
    BufReader::new(read.take(64)).read_line(&mut line).await?;

    let reply = match line.trim() {
        "status" => control.status(bind),
        "pause" => {
            control.set_paused(true);
            control.status(bind)
        }
        "resume" => {
            control.set_paused(false);
            control.status(bind)
        }
        _ => serde_json::json!({ "error": "expected status, pause or resume" }),
    };

    write.write_all(format!("{reply}\n").as_bytes()).await?;
    write.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_targets_are_not_counted_or_added() {
        let control = Control::new(["pixellab", "files"]);
        control.record("pixellab", "allow");
        control.record("pixellab", "deny-path");
        control.record("made-up", "allow");

        let status = control.status("127.0.0.1:1");
        let targets = status["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 2);
        let pixellab = targets.iter().find(|t| t["name"] == "pixellab").unwrap();
        assert_eq!(pixellab["allowed"], 1);
        assert_eq!(pixellab["denied"], 1);
    }

    #[test]
    fn only_forwarding_or_a_resume_resets_the_idle_clock() {
        let control = Control::new(["pixellab"]);
        let idle = |c: &Control| c.status("127.0.0.1:1")["idle_s"].as_u64().unwrap();
        let six_hours_ago = now_unix() - 6 * 3600;

        control.last_active.store(six_hours_ago, Ordering::SeqCst);
        control.record("pixellab", "deny-path");
        control.record("pixellab", "deny-paused");
        assert!(idle(&control) >= 6 * 3600, "a refused request is not activity");

        control.record("pixellab", "allow");
        assert!(idle(&control) < 60);

        control.last_active.store(six_hours_ago, Ordering::SeqCst);
        control.set_paused(true);
        assert!(idle(&control) >= 6 * 3600, "pausing does not reset it");
        control.set_paused(false);
        assert!(idle(&control) < 60);
    }

    async fn ask(control: &Control, command: &str) -> serde_json::Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(format!("{command}\n").as_bytes()).await.unwrap();
        handle(control, "127.0.0.1:1", server).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    #[tokio::test]
    async fn the_socket_pauses_resumes_and_ignores_anything_else() {
        let control = Control::new(["pixellab"]);
        assert_eq!(ask(&control, "status").await["paused"], false);
        assert_eq!(ask(&control, "pause").await["paused"], true);
        assert!(control.is_paused());
        assert!(ask(&control, "resume please").await["error"].is_string());
        assert!(control.is_paused(), "an unknown command changes nothing");
        assert_eq!(ask(&control, "resume").await["paused"], false);
        assert!(!control.is_paused());
    }

    #[tokio::test]
    async fn the_socket_is_private_and_only_replaces_a_stale_socket() {
        let dir = std::env::temp_dir().join(format!("acp-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("control.sock");

        drop(bind(&path).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        // Still answered on, so it belongs to a live instance and is refused.
        let live = bind(&path).unwrap();
        assert!(bind(&path).is_err());
        drop(live);

        // Left behind by the run above, so it is replaced rather than refused.
        drop(bind(&path).unwrap());

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
