//! Configuration loading. Everything has a default so netwatch runs with no
//! config file at all; a TOML file only needs the keys you want to change.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub dns: DnsConfig,
    pub web: WebConfig,
    pub storage: StorageConfig,
    pub discovery: DiscoveryConfig,
    pub blocking: BlockingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Address to serve DNS on. 0.0.0.0:53 so LAN clients can reach it.
    pub listen: SocketAddr,
    /// Also answer DNS over TCP (required for large responses).
    pub enable_tcp: bool,
    /// Which clients may query us. Keywords `loopback`, `private`, `any`, or
    /// CIDRs like "192.168.1.0/24". Defaults to loopback + private ranges:
    /// answering the whole internet would make this an open resolver, which is
    /// what DNS amplification attacks are built out of.
    pub allow_from: Vec<String>,
    /// Upstream resolvers, tried in order on failure.
    pub upstreams: Vec<SocketAddr>,
    /// How long to wait for an upstream before trying the next one.
    pub upstream_timeout_ms: u64,
    /// Largest UDP answer we will ask an upstream for, in bytes. Caps how much
    /// we must buffer per in-flight query regardless of what a client claims
    /// it can receive. Anything bigger arrives over TCP instead.
    pub upstream_udp_payload: u16,
    /// Most DNS requests handled at once. Past this, new UDP packets are
    /// dropped rather than queued: a client that gets no answer retries, but
    /// a queue that grows without limit takes the whole Pi down.
    pub max_udp_in_flight: usize,
    /// Most simultaneous DNS-over-TCP connections. Excess is closed at accept.
    pub max_tcp_connections: usize,
    /// Ceiling on one request end to end, across every upstream attempt.
    pub request_timeout_ms: u64,
    /// Cache answers locally. Big latency win on a home network.
    pub cache: bool,
    /// Maximum cache entries before the oldest-expiring are dropped.
    pub cache_max_entries: usize,
    /// Clamp cached TTLs into this range (seconds).
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    /// Dashboard address. Loopback by default: the dashboard can add block
    /// rules and flush the cache, so it is not something to expose to a whole
    /// LAN without a deliberate decision.
    pub listen: SocketAddr,
    /// Shared secret required by the state-changing endpoints as
    /// `Authorization: Bearer <token>`.
    ///
    /// Required whenever `listen` is not loopback — an off-host dashboard with
    /// no authentication lets anyone who can reach the port rewrite the
    /// network's DNS policy. Read-only endpoints stay open so the dashboard
    /// still renders without it.
    pub admin_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub database: PathBuf,
    /// Drop query log rows older than this. Keeps the SD card happy.
    pub retention_days: u32,
    /// Batch writes for this long before committing (reduces flash wear).
    pub flush_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    /// Poll the kernel ARP/neighbour table for IP <-> MAC pairs.
    pub arp: bool,
    pub arp_interval_secs: u64,
    /// Listen for mDNS (Bonjour) announcements to learn device names.
    pub mdns: bool,
    /// Listen for DHCP requests to learn hostnames + MACs. Needs port 67.
    ///
    /// Off by default. Binding UDP/67 with SO_REUSEPORT is only reliably
    /// passive when nothing else on this host serves DHCP: sockets in a
    /// reuseport group share incoming datagrams rather than each getting a
    /// copy. A dedicated service user makes an accidental group unlikely
    /// (the kernel only groups sockets owned by the same UID, so a
    /// differently-owned DHCP server makes our bind fail cleanly instead),
    /// but "unlikely" is not a good enough guarantee to put household DHCP
    /// at risk by default.
    pub dhcp: bool,
    /// Nudge every address in the local subnet so the kernel ARPs for it.
    /// This is what makes idle devices show up at all.
    pub sweep: bool,
    pub sweep_interval_secs: u64,
    /// Ask upstream for PTR records of clients we have no name for.
    pub reverse_dns: bool,
    /// Override the detected LAN CIDR, e.g. "192.168.1.0/24".
    pub subnet: Option<String>,
    /// Optional IEEE OUI database (CSV) to supplement the built-in vendors.
    /// Get it from https://standards-oui.ieee.org/oui/oui.csv
    pub oui_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlockingConfig {
    pub enabled: bool,
    /// How to answer a blocked name: "zero_ip" (0.0.0.0 / ::) or "nxdomain".
    pub mode: String,
    /// Remote hosts/domain lists to download.
    pub sources: Vec<String>,
    /// Local list files (hosts format or one domain per line).
    pub files: Vec<PathBuf>,
    /// Re-download `sources` this often.
    pub refresh_hours: u64,
    /// Where downloaded lists and the manual allow/deny lists live.
    pub state_dir: PathBuf,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:53".parse().unwrap(),
            enable_tcp: true,
            allow_from: vec!["loopback".to_string(), "private".to_string()],
            upstreams: vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()],
            upstream_timeout_ms: 2500,
            // The DNS Flag Day 2020 recommendation: large enough for almost
            // every real answer, small enough to avoid IP fragmentation on a
            // 1500-byte-MTU home link.
            upstream_udp_payload: 1232,
            // Sized for a household on a 4 GB Pi: comfortably above real peak
            // demand, low enough that a misbehaving device cannot exhaust
            // memory. Each in-flight query holds roughly a socket plus its
            // buffers.
            max_udp_in_flight: 128,
            max_tcp_connections: 64,
            // Must exceed upstream_timeout_ms * number of upstreams so a
            // normal failover is not cut short.
            request_timeout_ms: 10_000,
            cache: true,
            cache_max_entries: 20_000,
            cache_min_ttl: 30,
            cache_max_ttl: 86_400,
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().unwrap(),
            admin_token: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::from("/var/lib/netwatch/netwatch.db"),
            retention_days: 14,
            flush_interval_ms: 750,
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            arp: true,
            arp_interval_secs: 15,
            mdns: true,
            dhcp: false,
            sweep: true,
            sweep_interval_secs: 120,
            reverse_dns: true,
            subnet: None,
            oui_file: None,
        }
    }
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "zero_ip".to_string(),
            sources: vec![
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
            ],
            files: Vec::new(),
            refresh_hours: 24,
            state_dir: PathBuf::from("/var/lib/netwatch"),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => Self::load(p),
            Some(p) => {
                tracing::warn!("config {} not found, using defaults", p.display());
                Ok(Self::default())
            }
            None => Ok(Self::default()),
        }
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.dns.upstreams.is_empty(),
            "dns.upstreams must not be empty"
        );
        // Fail at startup on a malformed ACL rather than silently falling back
        // to a stance the operator did not choose.
        crate::dns::acl::Acl::parse(&self.dns.allow_from)?;
        anyhow::ensure!(
            self.dns.max_udp_in_flight > 0 && self.dns.max_tcp_connections > 0,
            "dns.max_udp_in_flight and dns.max_tcp_connections must be greater than zero"
        );
        // Refuse to start in the one configuration that would silently expose
        // rule-changing endpoints to the network.
        if !self.web.listen.ip().is_loopback() {
            let token_ok = self
                .web
                .admin_token
                .as_deref()
                .is_some_and(|t| t.trim().len() >= 16);
            anyhow::ensure!(
                token_ok,
                "web.listen is {} (not loopback), so web.admin_token must be set to at \
                 least 16 characters. The dashboard can add block rules and flush the \
                 DNS cache, so it must not be reachable off-host unauthenticated. \
                 Generate one with: openssl rand -hex 32",
                self.web.listen
            );
        }
        anyhow::ensure!(
            matches!(self.blocking.mode.as_str(), "zero_ip" | "nxdomain"),
            "blocking.mode must be \"zero_ip\" or \"nxdomain\", got {:?}",
            self.blocking.mode
        );
        Ok(())
    }

    /// Path of the user-managed deny list (domains added from the dashboard).
    pub fn manual_deny_path(&self) -> PathBuf {
        self.blocking.state_dir.join("deny.list")
    }

    /// Path of the user-managed allow list, which overrides all block lists.
    pub fn manual_allow_path(&self) -> PathBuf {
        self.blocking.state_dir.join("allow.list")
    }

    /// Where a downloaded blocklist is cached on disk.
    pub fn cached_list_path(&self, url: &str) -> PathBuf {
        // Stable, filesystem-safe name derived from the URL.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for b in url.as_bytes() {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        self.blocking
            .state_dir
            .join(format!("lists/{hash:016x}.list"))
    }
}

#[cfg(test)]
mod web_auth_tests {
    use super::*;

    fn cfg(listen: &str, token: Option<&str>) -> Config {
        let mut c = Config::default();
        c.web.listen = listen.parse().unwrap();
        c.web.admin_token = token.map(|t| t.to_string());
        c
    }

    #[test]
    fn the_default_dashboard_is_loopback_only() {
        let c = Config::default();
        assert!(
            c.web.listen.ip().is_loopback(),
            "a dashboard that can rewrite DNS policy must not default to the LAN"
        );
        assert!(c.validate().is_ok(), "and needs no token to work locally");
    }

    #[test]
    fn exposing_the_dashboard_without_a_token_is_refused_at_startup() {
        let err = cfg("0.0.0.0:8080", None).validate().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("admin_token"),
            "must name the missing setting: {msg}"
        );
        assert!(msg.contains("openssl rand"), "and say how to fix it: {msg}");

        // A token too short to be worth anything is not a token.
        assert!(cfg("0.0.0.0:8080", Some("hunter2")).validate().is_err());
        assert!(cfg("192.168.1.5:8080", Some("   ")).validate().is_err());
    }

    #[test]
    fn exposing_the_dashboard_with_a_real_token_is_allowed() {
        let c = cfg("0.0.0.0:8080", Some("0123456789abcdef0123456789abcdef"));
        assert!(c.validate().is_ok());
    }

    #[test]
    fn a_token_on_loopback_is_honoured_rather_than_ignored() {
        // Setting one locally is a deliberate choice; it must still apply.
        let c = cfg("127.0.0.1:8080", Some("0123456789abcdef0123456789abcdef"));
        assert!(c.validate().is_ok());
        assert!(c.web.admin_token.is_some());
    }
}
