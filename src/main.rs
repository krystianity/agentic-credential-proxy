mod config;
mod control;
mod files;
mod keychain;
mod proxy;
mod secret;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::proxy::AppState;

/// Every config this binary may run with, baked in at build time; see build.rs.
const EMBEDDED_CONFIGS: &[&str] = include!(concat!(env!("OUT_DIR"), "/configs.rs"));

#[derive(Parser)]
#[command(name = "agentic-credential-proxy", version, about)]
struct Args {
    /// Path to the TOML config. Defaults to
    /// ~/.config/agentic-credential-proxy/config.toml, then ./config.toml.
    /// Its contents must match a config embedded at build time.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Validate the config and the keychain items, then exit without binding.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Fixed rather than read from RUST_LOG, so whoever launches the binary
    // cannot turn on dependency trace logging in the process holding the keys.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("agentic_credential_proxy=info,audit=info"))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let config_path = resolve_config_path(args.config)?;
    tracing::info!(path = %config_path.display(), "using config");
    let config = Config::load(&config_path, EMBEDDED_CONFIGS)?;
    let bind = config.bind;
    for p in config.providers.values() {
        tracing::info!(provider = %p.name, upstream = %p.base_url, "provider");
    }

    tracing::info!(
        providers = config.providers.len(),
        keychain_service = %config.keychain_service,
        "loading credentials"
    );

    // Reads every keychain item up front, so an ACL prompt or a missing item is
    // a startup failure in the launching terminal rather than a 503 an hour later.
    let state = AppState::new(config).await?;

    if args.check {
        println!("config and keychain items OK; would bind {bind}");
        return Ok(());
    }

    let app = proxy::router(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "listening");

    spawn_reload_task(Arc::clone(&state));
    control::spawn(Arc::clone(&state));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("shut down");
    Ok(())
}

/// An explicit --config wins. Otherwise prefer the one in the user profile and
/// fall back to the working directory, so running from a checkout still works.
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    let profile = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|base| base.join("agentic-credential-proxy").join("config.toml"));

    if let Some(path) = &profile {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    let cwd = PathBuf::from("config.toml");
    if cwd.exists() {
        return Ok(cwd);
    }

    match profile {
        Some(p) => bail!("no config found at {} or ./config.toml", p.display()),
        None => bail!("no config found at ./config.toml and HOME is unset"),
    }
}

/// SIGHUP re-reads the keychain, so rotating an API key takes effect without a
/// restart. Config changes still need one -- the bind address is fixed at listen.
fn spawn_reload_task(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGHUP handler; reload disabled");
                return;
            }
        };
        while hup.recv().await.is_some() {
            match state.load_credentials().await {
                Ok(()) => tracing::info!("reloaded credentials from the keychain"),
                // The previous set stays live; a failed reload must not take the
                // proxy down mid-flight.
                Err(e) => tracing::error!(error = format!("{e:#}"), "credential reload failed"),
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
