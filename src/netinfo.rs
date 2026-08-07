//! Reading network state out of `/proc` and `/sys`.
//!
//! Everything here is parsed from kernel-exported text files rather than via
//! libc/netlink bindings, which keeps the dependency tree small and the
//! cross-compile to ARM trivial.

use anyhow::{Context, Result};
use serde::Serialize;
use std::net::Ipv4Addr;

/// The default route: which interface leaves the house, and via which gateway.
#[derive(Debug, Clone, Serialize)]
pub struct DefaultRoute {
    pub iface: String,
    pub gateway: Ipv4Addr,
}

/// An on-link IPv4 network reachable directly (no gateway) on an interface.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Subnet {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Subnet {
    pub fn netmask(&self) -> u32 {
        if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        }
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        (u32::from(addr) & self.netmask()) == (u32::from(self.network) & self.netmask())
    }

    /// Every usable host address, excluding the network and broadcast address.
    /// Returns nothing for prefixes wider than /16 — sweeping those is not a
    /// sensible thing to do to a network.
    pub fn hosts(&self) -> Vec<Ipv4Addr> {
        if self.prefix_len < 16 || self.prefix_len > 30 {
            return Vec::new();
        }
        let base = u32::from(self.network) & self.netmask();
        let count = 1u32 << (32 - self.prefix_len);
        (1..count.saturating_sub(1))
            .map(|i| Ipv4Addr::from(base + i))
            .collect()
    }

    pub fn parse_cidr(s: &str) -> Result<Self> {
        let (addr, len) = s
            .split_once('/')
            .with_context(|| format!("{s:?} is not CIDR notation, expected e.g. 192.168.1.0/24"))?;
        let network: Ipv4Addr = addr
            .trim()
            .parse()
            .with_context(|| format!("bad address {addr:?}"))?;
        let prefix_len: u8 = len
            .trim()
            .parse()
            .with_context(|| format!("bad prefix {len:?}"))?;
        anyhow::ensure!(prefix_len <= 32, "prefix /{prefix_len} out of range");
        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// Parse `/proc/net/route`, whose addresses are little-endian hex.
fn read_routes() -> Result<String> {
    std::fs::read_to_string("/proc/net/route").context("reading /proc/net/route")
}

fn hex_le_to_ipv4(s: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(s, 16).ok()?;
    // The kernel prints these in host byte order, which is little-endian on
    // every platform a Pi runs, so the octets come out reversed.
    Some(Ipv4Addr::from(raw.swap_bytes()))
}

pub fn default_route() -> Option<DefaultRoute> {
    let text = read_routes().ok()?;
    parse_default_route(&text)
}

fn parse_default_route(text: &str) -> Option<DefaultRoute> {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        // Destination 00000000 with a non-zero gateway is the default route.
        if f[1] != "00000000" {
            continue;
        }
        let Some(gw) = hex_le_to_ipv4(f[2]) else {
            continue;
        };
        if !gw.is_unspecified() {
            return Some(DefaultRoute {
                iface: f[0].to_string(),
                gateway: gw,
            });
        }
    }
    None
}

/// The directly-attached network on `iface` — i.e. the LAN the Pi shares with
/// every other device. This is what we sweep and match clients against.
pub fn lan_subnet(iface: &str) -> Option<Subnet> {
    let text = read_routes().ok()?;
    parse_lan_subnet(&text, iface)
}

fn parse_lan_subnet(text: &str, iface: &str) -> Option<Subnet> {
    let mut best: Option<Subnet> = None;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || f[0] != iface {
            continue;
        }
        // On-link route: no gateway, non-default destination.
        if f[2] != "00000000" || f[1] == "00000000" {
            continue;
        }
        let Some(network) = hex_le_to_ipv4(f[1]) else {
            continue;
        };
        let Some(mask) = hex_le_to_ipv4(f[7]) else {
            continue;
        };
        let prefix_len = u32::from(mask).count_ones() as u8;
        // Skip link-local (169.254/16) and multicast leftovers.
        if network.is_link_local() || network.is_multicast() {
            continue;
        }
        // Prefer the most specific real LAN route.
        if best.is_none_or(|b| prefix_len > b.prefix_len) {
            best = Some(Subnet {
                network,
                prefix_len,
            });
        }
    }
    best
}

/// One row from `/proc/net/arp`: the kernel's IP-to-MAC neighbour table.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub iface: String,
}

pub fn arp_table() -> Result<Vec<ArpEntry>> {
    let text = std::fs::read_to_string("/proc/net/arp").context("reading /proc/net/arp")?;
    Ok(parse_arp_table(&text))
}

fn parse_arp_table(text: &str) -> Vec<ArpEntry> {
    let mut out = Vec::new();
    // IP address  HW type  Flags  HW address  Mask  Device
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let Ok(ip) = f[0].parse::<Ipv4Addr>() else {
            continue;
        };
        // Flags 0x0 means the entry is incomplete — the MAC is meaningless.
        if f[2] == "0x0" {
            continue;
        }
        let Some(mac) = crate::oui::normalize(f[3]) else {
            continue;
        };
        out.push(ArpEntry {
            ip,
            mac,
            iface: f[5].to_string(),
        });
    }
    out
}

/// Cumulative byte/packet counters per interface from `/proc/net/dev`.
#[derive(Debug, Clone)]
pub struct IfaceCounters {
    pub iface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

pub fn iface_counters() -> Result<Vec<IfaceCounters>> {
    let text = std::fs::read_to_string("/proc/net/dev").context("reading /proc/net/dev")?;
    Ok(parse_iface_counters(&text))
}

fn parse_iface_counters(text: &str) -> Vec<IfaceCounters> {
    let mut out = Vec::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let iface = name.trim().to_string();
        if iface == "lo" {
            continue;
        }
        let v: Vec<u64> = rest
            .split_whitespace()
            .map(|s| s.parse::<u64>().unwrap_or(0))
            .collect();
        // rx: bytes packets errs drop fifo frame compressed multicast
        // tx: bytes packets errs drop fifo colls carrier compressed
        if v.len() < 16 {
            continue;
        }
        out.push(IfaceCounters {
            iface,
            rx_bytes: v[0],
            rx_packets: v[1],
            rx_errors: v[2],
            rx_dropped: v[3],
            tx_bytes: v[8],
            tx_packets: v[9],
            tx_errors: v[10],
            tx_dropped: v[11],
        });
    }
    out
}

/// Pi health: the things you actually want to know about a box in a cupboard.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemInfo {
    pub uptime_secs: u64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub cpu_temp_c: Option<f64>,
    /// Set when the Pi's firmware reports undervoltage or thermal throttling.
    pub throttled: Option<String>,
}

pub fn system_info() -> SystemInfo {
    let mut info = SystemInfo::default();

    if let Ok(s) = std::fs::read_to_string("/proc/uptime")
        && let Some(first) = s.split_whitespace().next()
    {
        info.uptime_secs = first.parse::<f64>().unwrap_or(0.0) as u64;
    }

    if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
        let f: Vec<&str> = s.split_whitespace().collect();
        if f.len() >= 3 {
            info.load1 = f[0].parse().unwrap_or(0.0);
            info.load5 = f[1].parse().unwrap_or(0.0);
            info.load15 = f[2].parse().unwrap_or(0.0);
        }
    }

    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        for line in s.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let kb = v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            match k {
                "MemTotal" => info.mem_total_kb = kb,
                "MemAvailable" => info.mem_available_kb = kb,
                _ => {}
            }
        }
    }

    // thermal_zone0 is the SoC sensor on every Pi model.
    if let Ok(s) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        && let Ok(milli) = s.trim().parse::<f64>()
    {
        info.cpu_temp_c = Some(milli / 1000.0);
    }

    info
}

/// Measure round-trip time to a host by timing a TCP handshake.
///
/// ICMP would need a raw socket (and thus extra privileges beyond what we
/// already hold for port 53), so this times a connect instead. A refused
/// connection is just as good a timing signal as an accepted one — both prove
/// the packet made it there and back.
pub async fn tcp_probe_ms(target: std::net::SocketAddr, timeout_ms: u64) -> Option<f64> {
    let started = std::time::Instant::now();
    let fut = tokio::net::TcpStream::connect(target);
    match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
        // Reachable: handshake completed.
        Ok(Ok(_stream)) => Some(started.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some(started.elapsed().as_secs_f64() * 1000.0)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE_SAMPLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t202\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t202\t00FFFFFF\t0\t0\t0
wlan0\t0000FEA9\t00000000\t0001\t0\t0\t303\t0000FFFF\t0\t0\t0
";

    #[test]
    fn parses_default_gateway() {
        let r = parse_default_route(ROUTE_SAMPLE).expect("default route");
        assert_eq!(r.iface, "eth0");
        assert_eq!(r.gateway, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn parses_lan_subnet_and_skips_link_local() {
        let s = parse_lan_subnet(ROUTE_SAMPLE, "eth0").expect("lan subnet");
        assert_eq!(s.network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(s.prefix_len, 24);
        // wlan0's only route is 169.254/16, which must be ignored.
        assert!(parse_lan_subnet(ROUTE_SAMPLE, "wlan0").is_none());
    }

    #[test]
    fn subnet_contains_and_enumerates() {
        let s = Subnet::parse_cidr("192.168.1.0/24").unwrap();
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 57)));
        assert!(!s.contains(Ipv4Addr::new(192, 168, 2, 57)));
        let hosts = s.hosts();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn refuses_to_enumerate_huge_subnets() {
        assert!(Subnet::parse_cidr("10.0.0.0/8").unwrap().hosts().is_empty());
    }

    #[test]
    fn parses_arp_table_skipping_incomplete() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         b8:27:eb:aa:bb:cc     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.42     0x1         0x2         5c:cf:7f:11:22:33     *        eth0
";
        let entries = parse_arp_table(sample);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].mac, "b8:27:eb:aa:bb:cc");
        assert_eq!(entries[1].ip, Ipv4Addr::new(192, 168, 1, 42));
    }

    #[test]
    fn parses_iface_counters() {
        let sample = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth0: 5000      50    1    2    0     0          0         3     6000      60    4    5    0     0       0          0
";
        let c = parse_iface_counters(sample);
        assert_eq!(c.len(), 1, "loopback should be skipped");
        assert_eq!(c[0].iface, "eth0");
        assert_eq!(c[0].rx_bytes, 5000);
        assert_eq!(c[0].tx_bytes, 6000);
        assert_eq!(c[0].rx_errors, 1);
        assert_eq!(c[0].tx_dropped, 5);
    }
}
