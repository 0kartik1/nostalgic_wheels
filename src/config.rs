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
    pub listen: SocketAddr,
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
            listen: "0.0.0.0:8080".parse().unwrap(),
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
            dhcp: true,
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
