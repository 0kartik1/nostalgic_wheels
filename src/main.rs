//! netwatch — a DNS-level network monitor for a Raspberry Pi on a home LAN.
//!
//! See README.md for why this is built around a DNS forwarder rather than a
//! packet sniffer: a Pi plugged into a switch port cannot see other devices'
//! traffic, but it can serve their DNS.

mod api;
mod blocklist;
mod config;
mod db;
mod devices;
mod dns;
mod monitor;
mod netinfo;
mod oui;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "netwatch",
    version,
    about = "DNS-level network monitor and ad blocker with a web dashboard"
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "/etc/netwatch/config.toml")]
    config: PathBuf,

    /// Override the DNS listen address.
    #[arg(long)]
    dns_listen: Option<SocketAddr>,

    /// Override the dashboard listen address.
    #[arg(long)]
    web_listen: Option<SocketAddr>,

    /// Override the database path.
    #[arg(long)]
    database: Option<PathBuf>,

    /// Do not download blocklists on startup (use whatever is cached).
    #[arg(long)]
    no_fetch: bool,

    /// Print the effective configuration as TOML and exit.
    #[arg(long)]
    print_config: bool,

    /// Validate the config file and exit: 0 if netwatch would start with it,
    /// 1 with the reason if not. Run this before restarting the service.
    #[arg(long)]
    check_config: bool,
}

/// Apply the command-line overrides on top of a loaded config.
///
/// Shared by the real startup path and `--check-config`, so the check
/// validates exactly what a start would use rather than the file alone.
fn apply_overrides(cfg: &mut config::Config, cli: &Cli) {
    if let Some(a) = cli.dns_listen {
        cfg.dns.listen = a;
    }
    if let Some(a) = cli.web_listen {
        cfg.web.listen = a;
    }
    if let Some(p) = &cli.database {
        cfg.storage.database = p.clone();
    }
}

/// Report whether netwatch would start with this config, in a form a shell
/// script can gate on.
///
/// This exists because a bad config is the one failure that takes DNS down for
/// the entire network: the process exits, systemd restarts it into the same
/// broken file, and every device sits without name resolution. `systemctl
/// restart` offers no chance to notice beforehand, so this does.
fn check_config(cli: &Cli, loaded: Result<config::Config>) -> Result<()> {
    let path = cli.config.display();

    // load_or_default() quietly falls back to built-in defaults for a missing
    // file. That is right for starting up, but for a check it would report OK
    // on a mistyped path, which is precisely the mistake worth catching.
    if !cli.config.exists() {
        println!("config not found: {path} (netwatch would start on built-in defaults)");
        return Ok(());
    }

    let result = loaded.and_then(|mut cfg| {
        apply_overrides(&mut cfg, cli);
        cfg.validate()?;
        Ok(())
    });

    match result {
        Ok(()) => {
            println!("config OK: {path}");
            Ok(())
        }
        Err(e) => {
            eprintln!("config INVALID: {path}\n\n{e:#}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netwatch=info,warn".into()),
        )
        .init();

    // reqwest is built with rustls-no-provider so the ring backend can be
    // selected here; aws-lc-rs would drag cmake into the ARM cross-compile.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls crypto provider already installed");
    }

    let cli = Cli::parse();

    // Taken before `?` unwraps it: --check-config has to report a parse failure
    // as its own readable verdict, not as a propagated error trace.
    let loaded = config::Config::load_or_default(Some(&cli.config));
    if cli.check_config {
        return check_config(&cli, loaded);
    }

    let mut cfg = loaded?;
    apply_overrides(&mut cfg, &cli);

    if cli.print_config {
        println!("{}", toml::to_string_pretty(&cfg)?);
        return Ok(());
    }

    let cfg = Arc::new(cfg);
    std::fs::create_dir_all(&cfg.blocking.state_dir)
        .with_context(|| format!("creating state dir {}", cfg.blocking.state_dir.display()))?;

    // ---- storage -----------------------------------------------------------
    let write_conn = db::open(&cfg.storage.database)?;
    let read_conn = db::open(&cfg.storage.database)?;
    let writer = db::spawn_writer(
        write_conn,
        Duration::from_millis(cfg.storage.flush_interval_ms),
        cfg.storage.retention_days,
    );
    let read_handle = Arc::new(Mutex::new(read_conn));
    tracing::info!("database at {}", cfg.storage.database.display());

    // ---- blocklists --------------------------------------------------------
    let list_health = blocklist::new_health(&cfg);
    let refresh_lock = blocklist::new_refresh_lock();
    if cfg.blocking.enabled && !cli.no_fetch {
        // Only download if we have nothing cached; otherwise start fast and let
        // the refresh task update in the background.
        let have_cache = cfg
            .blocking
            .sources
            .iter()
            .all(|u| cfg.cached_list_path(u).exists());
        if !have_cache {
            tracing::info!("downloading blocklists (first run)");
            let outcome = blocklist::refresh_sources(&cfg, &list_health).await;
            if outcome.total_failure() {
                tracing::error!(
                    "all {} blocklist sources failed; starting without filtering. \
                     Check connectivity and POST /api/reload to retry.",
                    outcome.attempted
                );
            }
        }
    }
    let blocklist = Arc::new(RwLock::new(blocklist::build(&cfg)));

    // ---- device identification --------------------------------------------
    let mut oui_db = oui::OuiDb::new();
    if let Some(path) = &cfg.discovery.oui_file {
        match oui_db.load_ieee_csv(path) {
            Ok(n) => tracing::info!("loaded {n} OUI entries from {}", path.display()),
            Err(e) => tracing::warn!("could not read {}: {e}", path.display()),
        }
    }
    tracing::info!("{} MAC vendor prefixes available", oui_db.len());
    let device_store = devices::DeviceStore::new(oui_db, writer.clone());

    // Figure out where we are on the network.
    let route = netinfo::default_route();
    let subnet = match &cfg.discovery.subnet {
        Some(s) => Some(netinfo::Subnet::parse_cidr(s)?),
        None => route.as_ref().and_then(|r| netinfo::lan_subnet(&r.iface)),
    };
    match (&route, &subnet) {
        (Some(r), Some(s)) => tracing::info!("LAN {s} via {} (gateway {})", r.iface, r.gateway),
        (Some(r), None) => tracing::warn!(
            "found gateway {} on {} but no LAN subnet; set discovery.subnet to enable sweeping",
            r.gateway,
            r.iface
        ),
        _ => tracing::warn!("no default route found; device discovery will be limited"),
    }

    // ---- resolver ----------------------------------------------------------
    let resolver = Arc::new(dns::Resolver::new(
        &cfg,
        subnet,
        Arc::clone(&blocklist),
        writer.clone(),
        device_store.clone(),
    ));

    // Serving the whole internet is a choice, not a default; say so if made.
    if resolver.is_open_to_world() {
        tracing::warn!(
            "dns.allow_from permits ANY source address. If port 53 is reachable from \
             the internet this is an open resolver and will be abused for DNS \
             amplification attacks. Restrict it to \"private\" unless you are certain."
        );
    } else {
        tracing::info!("answering DNS for {:?}", cfg.dns.allow_from);
    }

    // ---- background workers ------------------------------------------------
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // The IPv4 listener plus, if configured, an independent IPv6 one. They are
    // separate sockets rather than one dual-stack socket; see `dns::new_socket`.
    let dns_listeners: Vec<SocketAddr> = std::iter::once(cfg.dns.listen)
        .chain(cfg.dns.listen_v6)
        .collect();

    for listen in dns_listeners.iter().copied() {
        let r = Arc::clone(&resolver);
        tasks.push(tokio::spawn(async move {
            if let Err(e) = dns::serve_udp(r, listen).await {
                // DNS is the entire point of this program. `serve_udp` already
                // retries a transient bind conflict for a while on its own; if
                // it still gives up, limping along with the dashboard and
                // discovery workers alive but no DNS being served would look
                // "healthy" to systemd forever while doing nothing useful. Exit
                // instead, so the unit's `Restart=on-failure` actually engages.
                tracing::error!("DNS/UDP server failed, exiting so systemd restarts us: {e:#}");
                std::process::exit(1);
            }
        }));
    }

    for listen in dns_listeners.iter().copied() {
        if !cfg.dns.enable_tcp {
            break;
        }
        let r = Arc::clone(&resolver);
        tasks.push(tokio::spawn(async move {
            if let Err(e) = dns::serve_tcp(r, listen).await {
                tracing::error!("DNS/TCP server failed, exiting so systemd restarts us: {e:#}");
                std::process::exit(1);
            }
        }));
    }

    tasks.push(tokio::spawn(dns::cache_sweeper(Arc::clone(&resolver))));

    if cfg.discovery.arp {
        let store = device_store.clone();
        let interval = Duration::from_secs(cfg.discovery.arp_interval_secs.max(5));
        let iface = route.as_ref().map(|r| r.iface.clone());
        tasks.push(tokio::spawn(devices::arp_poller(
            store, interval, subnet, iface,
        )));
    }

    let discovery_status: devices::SharedDiscoveryStatus = Default::default();

    if cfg.discovery.mdns {
        let store = device_store.clone();
        let st = Arc::clone(&discovery_status);
        tasks.push(tokio::spawn(async move {
            if let Ok(mut s) = st.write() {
                s.mdns = devices::ListenerState::Active;
            }
            // Not fatal: Avahi may already own port 5353.
            if let Err(e) = devices::mdns_listener(store).await {
                tracing::warn!("mDNS discovery unavailable: {e:#}");
                if let Ok(mut s) = st.write() {
                    s.mdns = devices::ListenerState::Unavailable {
                        reason: format!("{e:#}"),
                    };
                }
            }
        }));
    }

    if cfg.discovery.dhcp {
        tracing::warn!(
            "discovery.dhcp is enabled. netwatch only listens, but a UDP/67 socket \
             shares a reuseport group with any DHCP server running as the same user, \
             which would divert leases. Leave it off unless nothing else on this host \
             serves DHCP."
        );
        let store = device_store.clone();
        let st = Arc::clone(&discovery_status);
        tasks.push(tokio::spawn(async move {
            if let Ok(mut s) = st.write() {
                s.dhcp = devices::ListenerState::Active;
            }
            if let Err(e) = devices::dhcp_listener(store).await {
                tracing::warn!("DHCP discovery unavailable: {e:#}");
                if let Ok(mut s) = st.write() {
                    s.dhcp = devices::ListenerState::Unavailable {
                        reason: format!("{e:#}"),
                    };
                }
            }
        }));
    }

    if cfg.discovery.sweep
        && let Some(s) = subnet
    {
        let interval = Duration::from_secs(cfg.discovery.sweep_interval_secs.max(30));
        tasks.push(tokio::spawn(devices::subnet_sweeper(s, interval)));
    }

    if cfg.discovery.reverse_dns {
        let store = device_store.clone();
        let upstream = cfg.dns.upstreams[0];
        let gw = route.as_ref().map(|r| r.gateway);
        tasks.push(tokio::spawn(devices::reverse_dns_worker(
            store, upstream, gw,
        )));
    }

    tasks.push(tokio::spawn(monitor::throughput_sampler(
        writer.clone(),
        Duration::from_secs(10),
    )));
    tasks.push(tokio::spawn(monitor::latency_sampler(
        writer.clone(),
        cfg.dns.upstreams[0],
        Duration::from_secs(60),
    )));

    // Periodic blocklist refresh.
    if cfg.blocking.enabled && cfg.blocking.refresh_hours > 0 {
        let cfg2 = Arc::clone(&cfg);
        let bl = Arc::clone(&blocklist);
        let r = Arc::clone(&resolver);
        let health2 = Arc::clone(&list_health);
        let lock2 = Arc::clone(&refresh_lock);
        let period = Duration::from_secs(cfg.blocking.refresh_hours * 3600);
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // the first tick fires immediately; skip it
            loop {
                tick.tick().await;

                // Skip this cycle if a manual reload holds the lock; it is
                // doing the same work right now.
                let Ok(_guard) = lock2.try_lock() else {
                    tracing::debug!("scheduled refresh skipped, a manual one is running");
                    continue;
                };

                let outcome = blocklist::refresh_sources(&cfg2, &health2).await;
                if outcome.total_failure() {
                    tracing::error!(
                        "scheduled refresh: all {} sources failed, keeping cached lists",
                        outcome.attempted
                    );
                    continue;
                }

                // Parsing ~100k domains must not block the executor that is
                // also serving DNS.
                let cfg3 = Arc::clone(&cfg2);
                match tokio::task::spawn_blocking(move || blocklist::build(&cfg3)).await {
                    Ok(fresh) => {
                        if let Ok(mut guard) = bl.write() {
                            *guard = fresh;
                        }
                        r.flush_cache();
                    }
                    Err(e) => tracing::error!("rebuilding blocklist: {e}"),
                }
            }
        }));
    }

    // ---- dashboard ---------------------------------------------------------
    let state = api::AppState {
        db: read_handle,
        cfg: Arc::clone(&cfg),
        blocklist: Arc::clone(&blocklist),
        resolver: Arc::clone(&resolver),
        started: std::time::Instant::now(),
        write_drops: writer.drop_counts(),
        discovery: Arc::clone(&discovery_status),
        list_health: Arc::clone(&list_health),
        refresh_lock: Arc::clone(&refresh_lock),
    };
    {
        let listen = cfg.web.listen;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = api::serve(state, listen).await {
                tracing::error!("dashboard stopped: {e:#}");
            }
        }));
    }

    tracing::info!("netwatch {} ready", env!("CARGO_PKG_VERSION"));

    shutdown_signal().await;
    tracing::info!("shutting down");
    for t in tasks {
        t.abort();
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::warn!("cannot listen for SIGTERM: {e}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
