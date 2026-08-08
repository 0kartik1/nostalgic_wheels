//! Working out *which device* a request came from.
//!
//! A DNS query only carries an IP. Turning that into "the kitchen iPad" needs
//! several independent sources, because no single one is reliable:
//!
//! * the kernel ARP table    -> IP <-> MAC (authoritative, but only for hosts
//!   we have recently exchanged packets with)
//! * an OUI table            -> MAC -> manufacturer
//! * passive mDNS listening  -> the name a device advertises for itself
//! * passive DHCP listening  -> the hostname a device tells the router
//! * reverse DNS             -> whatever the router knows
//! * a periodic subnet sweep -> forces the kernel to ARP for idle hosts
//!
//! mDNS and DHCP work here even though unicast traffic is invisible to the Pi,
//! because both are broadcast/multicast: the switch floods them to every port,
//! including ours. That is the one category of other-device traffic a passive
//! host on a switched LAN genuinely does see.

use crate::db::{WriteOp, Writer};
use crate::netinfo::{self, Subnet};
use crate::oui::{self, OuiDb};
use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// How often an otherwise-unchanged device gets its `last_seen` refreshed.
///
/// This is the whole write-amplification story. Before, a device row was
/// upserted on *every DNS query* (~100k/day) plus once per ARP poll per
/// device (~5.7k/day each), all of it rewriting rows that had not changed.
/// On an SD card that is the difference between a card that lasts and one
/// that does not.
const LAST_SEEN_HEARTBEAT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default)]
struct Device {
    mac: String,
    ip: Option<Ipv4Addr>,
    hostname: Option<String>,
    vendor: Option<String>,
    randomized: bool,
    /// Fingerprint of the fields as last written, so an identical sighting
    /// costs nothing.
    written_fingerprint: Option<u64>,
    /// When `last_seen` was last pushed to the database.
    last_seen_written: Option<Instant>,
}

impl Device {
    /// Hash of everything worth a write. `last_seen` is deliberately excluded:
    /// it changes constantly and is handled by the heartbeat instead.
    fn fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.ip.hash(&mut h);
        self.hostname.hash(&mut h);
        self.vendor.hash(&mut h);
        self.randomized.hash(&mut h);
        h.finish()
    }

    /// Decide whether this sighting is worth a row write, and record that we
    /// are about to make one. Called under the write lock so two threads
    /// cannot both conclude "yes" for the same unchanged device.
    fn take_write_slot(&mut self, now: Instant) -> bool {
        let fp = self.fingerprint();
        let changed = self.written_fingerprint != Some(fp);
        let stale = self
            .last_seen_written
            .is_none_or(|t| now.duration_since(t) >= LAST_SEEN_HEARTBEAT);

        if changed || stale {
            self.written_fingerprint = Some(fp);
            self.last_seen_written = Some(now);
            return true;
        }
        false
    }
}

#[derive(Default)]
struct Inner {
    by_mac: HashMap<String, Device>,
    /// Reverse index so a DNS client IP can be resolved to a device.
    ip_to_mac: HashMap<Ipv4Addr, String>,
    /// Names learned for an IP before we knew its MAC.
    pending_names: HashMap<Ipv4Addr, String>,
}

/// Shared, cheaply cloneable device registry.
#[derive(Clone)]
pub struct DeviceStore {
    inner: Arc<RwLock<Inner>>,
    oui: Arc<OuiDb>,
    writer: Option<Writer>,
}

impl DeviceStore {
    pub fn new(oui: OuiDb, writer: Writer) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            oui: Arc::new(oui),
            writer: Some(writer),
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            oui: Arc::new(OuiDb::new()),
            writer: None,
        }
    }

    fn persist(&self, dev: &Device) {
        let Some(w) = &self.writer else { return };
        w.send(WriteOp::Device {
            mac: dev.mac.clone(),
            ip: dev.ip.map(|i| i.to_string()),
            hostname: dev.hostname.clone(),
            vendor: dev.vendor.clone(),
            randomized: dev.randomized,
            ts: crate::db::now(),
        });
    }

    /// Record an IP/MAC pair, usually from the ARP table.
    pub fn observe(&self, ip: Ipv4Addr, mac: &str) {
        let Some(mac) = oui::normalize(mac) else {
            return;
        };

        let dev = {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            // A name we learned by IP before knowing the MAC now has an owner.
            let pending = inner.pending_names.remove(&ip);
            inner.ip_to_mac.insert(ip, mac.clone());

            let randomized = oui::is_randomized(&mac);
            let vendor = if randomized {
                Some("(randomized MAC)".to_string())
            } else {
                self.oui.lookup(&mac).map(|s| s.to_string())
            };

            let entry = inner.by_mac.entry(mac.clone()).or_insert_with(|| Device {
                mac: mac.clone(),
                ..Device::default()
            });
            entry.ip = Some(ip);
            entry.randomized = randomized;
            if entry.vendor.is_none() {
                entry.vendor = vendor;
            }
            if let Some(name) = pending {
                entry.hostname = Some(name);
            }
            entry.take_write_slot(Instant::now()).then(|| entry.clone())
        };

        if let Some(d) = dev {
            self.persist(&d);
        }
    }

    /// Record a hostname for a MAC (from DHCP, which carries both).
    pub fn observe_named(&self, mac: &str, hostname: &str) {
        let Some(mac) = oui::normalize(mac) else {
            return;
        };
        let Some(name) = sanitize_hostname(hostname) else {
            return;
        };

        let dev = {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            let randomized = oui::is_randomized(&mac);
            let vendor = if randomized {
                Some("(randomized MAC)".to_string())
            } else {
                self.oui.lookup(&mac).map(|s| s.to_string())
            };
            let entry = inner.by_mac.entry(mac.clone()).or_insert_with(|| Device {
                mac: mac.clone(),
                ..Device::default()
            });
            entry.hostname = Some(name);
            entry.randomized = randomized;
            if entry.vendor.is_none() {
                entry.vendor = vendor;
            }
            entry.take_write_slot(Instant::now()).then(|| entry.clone())
        };

        if let Some(d) = dev {
            self.persist(&d);
        }
    }

    /// Record a hostname discovered for an IP (mDNS, reverse DNS). Stashed
    /// until ARP tells us which MAC that IP belongs to.
    pub fn observe_name_for_ip(&self, ip: Ipv4Addr, hostname: &str) {
        let Some(name) = sanitize_hostname(hostname) else {
            return;
        };

        let dev = {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            match inner.ip_to_mac.get(&ip).cloned() {
                Some(mac) => {
                    let entry = inner.by_mac.entry(mac.clone()).or_insert_with(|| Device {
                        mac,
                        ip: Some(ip),
                        ..Device::default()
                    });
                    // Don't let a generic reverse-DNS name overwrite a specific
                    // self-advertised one.
                    if entry.hostname.is_none() {
                        entry.hostname = Some(name);
                    }
                    entry.take_write_slot(Instant::now()).then(|| entry.clone())
                }
                None => {
                    inner.pending_names.insert(ip, name);
                    None
                }
            }
        };

        if let Some(d) = dev {
            self.persist(&d);
        }
    }

    /// Bump last_seen for whichever device owns this IP.
    ///
    /// Called from the DNS hot path, once per query. Almost every call is
    /// expected to do nothing: the heartbeat means one row write per device
    /// per minute rather than one per query. A read lock is taken first so the
    /// overwhelmingly common "nothing to do" case never contends for the write
    /// lock with the ARP poller or the mDNS listener.
    pub fn touch_ip(&self, ip: IpAddr) {
        let IpAddr::V4(v4) = ip else { return };
        let now = Instant::now();

        {
            let Ok(inner) = self.inner.read() else { return };
            let due = inner
                .ip_to_mac
                .get(&v4)
                .and_then(|m| inner.by_mac.get(m))
                .is_some_and(|d| {
                    d.last_seen_written
                        .is_none_or(|t| now.duration_since(t) >= LAST_SEEN_HEARTBEAT)
                });
            if !due {
                return;
            }
        }

        // Due for a heartbeat. Re-check under the write lock, because another
        // query for the same device may have got here first.
        let dev = {
            let Ok(mut inner) = self.inner.write() else {
                return;
            };
            let Some(mac) = inner.ip_to_mac.get(&v4).cloned() else {
                return;
            };
            inner
                .by_mac
                .get_mut(&mac)
                .filter(|d| {
                    d.last_seen_written
                        .is_none_or(|t| now.duration_since(t) >= LAST_SEEN_HEARTBEAT)
                })
                .map(|d| {
                    d.last_seen_written = Some(now);
                    d.clone()
                })
        };
        if let Some(d) = dev {
            self.persist(&d);
        }
    }

    /// Names for IPs we have no name for yet — the reverse-DNS worker's queue.
    pub fn ips_needing_names(&self) -> Vec<Ipv4Addr> {
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .ip_to_mac
            .iter()
            .filter(|(ip, mac)| {
                !inner.pending_names.contains_key(ip)
                    && inner.by_mac.get(*mac).is_none_or(|d| d.hostname.is_none())
            })
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Harvest device names out of DNS traffic we are already handling. An
    /// `A` answer for `something.local` is a device naming itself.
    pub fn learn_from_dns(&self, msg: &Message) {
        for rec in &msg.answers {
            match &rec.data {
                RData::A(a) => {
                    let name = rec.name.to_ascii();
                    if let Some(stripped) = name.trim_end_matches('.').strip_suffix(".local") {
                        self.observe_name_for_ip(a.0, stripped);
                    }
                }
                RData::PTR(ptr) => {
                    // Reverse lookup answer: 42.1.168.192.in-addr.arpa -> name
                    if let Some(ip) = ptr_name_to_ip(&rec.name.to_ascii()) {
                        let target = ptr.0.to_ascii();
                        let target = target.trim_end_matches('.');
                        let short = target.strip_suffix(".local").unwrap_or(target);
                        self.observe_name_for_ip(ip, short);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Reject anything that isn't a plausible, printable hostname. Device-supplied
/// strings end up in the dashboard, so they must not carry control characters
/// or arbitrary length.
fn sanitize_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 64 {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }
    // A bare IP as a "hostname" tells us nothing new.
    if trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// `42.1.168.192.in-addr.arpa` -> `192.168.1.42`
fn ptr_name_to_ip(name: &str) -> Option<Ipv4Addr> {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let base = n.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().rev().enumerate() {
        octets[i] = p.parse().ok()?;
    }
    Some(Ipv4Addr::from(octets))
}

// ---------------------------------------------------------------------------
// Background workers
// ---------------------------------------------------------------------------

/// Poll the kernel neighbour table.
///
/// `iface` restricts us to neighbours on the LAN link, so a VPN or Docker
/// bridge peer never gets listed as a device on the home network.
pub async fn arp_poller(
    store: DeviceStore,
    interval: Duration,
    subnet: Option<Subnet>,
    iface: Option<String>,
) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        match netinfo::arp_table() {
            Ok(entries) => {
                for e in entries {
                    if let Some(want) = &iface
                        && &e.iface != want
                    {
                        continue;
                    }
                    if let Some(s) = &subnet
                        && !s.contains(e.ip)
                    {
                        continue;
                    }
                    store.observe(e.ip, &e.mac);
                }
            }
            Err(e) => tracing::warn!("ARP poll failed: {e:#}"),
        }
    }
}

/// Nudge every address in the LAN so the kernel populates its ARP cache.
///
/// A single UDP byte to a high, almost certainly closed port is enough to make
/// the kernel resolve the MAC first. Nothing listens, so the payload is
/// discarded — this is a discovery probe, not a port scan, and it touches each
/// address once per cycle.
pub async fn subnet_sweeper(subnet: Subnet, interval: Duration) {
    let hosts = subnet.hosts();
    if hosts.is_empty() {
        tracing::warn!("subnet {subnet} too large to sweep, skipping discovery sweep");
        return;
    }
    tracing::info!(
        "sweeping {} addresses in {subnet} every {:?}",
        hosts.len(),
        interval
    );

    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
            tracing::warn!("sweep: could not open socket");
            continue;
        };
        // Port 9 is the standard discard service.
        for ip in &hosts {
            let target = SocketAddr::new(IpAddr::V4(*ip), 9);
            let _ = sock.send_to(&[0u8], target).await;
            // Spread the sweep out; a burst of 254 packets can make cheap
            // consumer routers drop things.
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        tracing::debug!("sweep complete ({} addresses)", hosts.len());
    }
}

/// Listen for mDNS announcements on 224.0.0.251:5353.
///
/// Joining the multicast group is a passive operation: we send nothing, we just
/// read what devices already shout at the whole network.
pub async fn mdns_listener(store: DeviceStore) -> Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating mDNS socket")?;
    // Avahi or another mDNS stack is often already bound here.
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    let bind: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    socket
        .bind(&bind.into())
        .context("binding UDP 5353 for mDNS (is another resolver using it?)")?;
    socket
        .join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::UNSPECIFIED)
        .context("joining mDNS multicast group")?;

    let socket = UdpSocket::from_std(socket.into())?;
    tracing::info!("mDNS listener active on 224.0.0.251:5353");

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("mDNS recv error: {e}");
                continue;
            }
        };
        let IpAddr::V4(src) = peer.ip() else { continue };

        // mDNS packets are ordinary DNS messages.
        let Ok(msg) = Message::from_vec(&buf[..len]) else {
            continue;
        };

        // Prefer an A record matching the sender: that is the device naming
        // itself, which beats anything we could infer.
        let mut learned = false;
        for rec in &msg.answers {
            if let RData::A(a) = &rec.data
                && a.0 == src
            {
                let name = rec.name.to_ascii();
                let name = name.trim_end_matches('.');
                let short = name.strip_suffix(".local").unwrap_or(name);
                store.observe_name_for_ip(src, short);
                learned = true;
            }
        }

        // Fall back to the instance name in a SRV/PTR record.
        if !learned {
            for rec in &msg.answers {
                if let RData::SRV(_) = &rec.data {
                    let name = rec.name.to_ascii();
                    if let Some(first) = name.split('.').next() {
                        store.observe_name_for_ip(src, first);
                        break;
                    }
                }
            }
        }
    }
}

/// Listen for DHCP client broadcasts on port 67.
///
/// DHCP DISCOVER/REQUEST go to 255.255.255.255, so every host on the segment
/// receives them. Option 12 carries the hostname the device wants, and the
/// BOOTP header carries its MAC — the single most reliable naming source we
/// have. We only listen; we never reply, so the router remains the only DHCP
/// server on the network.
pub async fn dhcp_listener(store: DeviceStore) -> Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("creating DHCP socket")?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    let bind: SocketAddr = "0.0.0.0:67".parse().unwrap();
    socket.bind(&bind.into()).context(
        "binding UDP 67 for DHCP (needs root; a DHCP server on this host will conflict)",
    )?;

    let socket = UdpSocket::from_std(socket.into())?;
    tracing::info!("DHCP listener active on 0.0.0.0:67");

    let mut buf = vec![0u8; 2048];
    loop {
        let len = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("DHCP recv error: {e}");
                continue;
            }
        };
        if let Some((mac, hostname)) = parse_dhcp(&buf[..len]) {
            match hostname {
                Some(name) => store.observe_named(&mac, &name),
                // Even without a name, the MAC proves the device exists.
                None => tracing::debug!("DHCP from {mac} with no hostname option"),
            }
        }
    }
}

/// Pull the client MAC and requested hostname out of a BOOTP/DHCP packet.
fn parse_dhcp(pkt: &[u8]) -> Option<(String, Option<String>)> {
    // Fixed BOOTP header is 236 bytes, then a 4-byte magic cookie.
    if pkt.len() < 240 {
        return None;
    }
    // op: 1 = BOOTREQUEST (client -> server). Ignore replies.
    if pkt[0] != 1 {
        return None;
    }
    let hlen = pkt[2] as usize;
    if hlen == 0 || hlen > 16 {
        return None;
    }
    // chaddr starts at offset 28.
    let mac_bytes = &pkt[28..28 + hlen.min(6)];
    let mac = mac_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let mac = oui::normalize(&mac)?;

    // Magic cookie 99.130.83.99 marks the start of DHCP options.
    if pkt[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return Some((mac, None));
    }

    let mut hostname = None;
    let mut i = 240;
    while i < pkt.len() {
        let code = pkt[i];
        match code {
            0 => {
                i += 1; // pad
                continue;
            }
            255 => break, // end
            _ => {}
        }
        if i + 1 >= pkt.len() {
            break;
        }
        let len = pkt[i + 1] as usize;
        let start = i + 2;
        let end = start.checked_add(len)?;
        if end > pkt.len() {
            break;
        }
        // Option 12 = Host Name.
        if code == 12
            && let Ok(s) = std::str::from_utf8(&pkt[start..end])
        {
            hostname = Some(s.to_string());
        }
        i = end;
    }

    Some((mac, hostname))
}

/// Ask the configured upstream for PTR records of clients we cannot name.
/// On most home networks the router answers these from its DHCP leases.
pub async fn reverse_dns_worker(
    store: DeviceStore,
    upstream: SocketAddr,
    gateway: Option<Ipv4Addr>,
) {
    // The router usually knows the DHCP names; ask it before the internet.
    let target = match gateway {
        Some(gw) => SocketAddr::new(IpAddr::V4(gw), 53),
        None => upstream,
    };
    let mut tick = tokio::time::interval(Duration::from_secs(90));
    // Most home devices simply have no PTR record. Give each address a few
    // tries and then stop, rather than re-asking every 90s forever.
    const MAX_ATTEMPTS: u8 = 3;
    let mut attempts: HashMap<Ipv4Addr, u8> = HashMap::new();

    loop {
        tick.tick().await;
        for ip in store.ips_needing_names() {
            let tries = attempts.entry(ip).or_insert(0);
            if *tries >= MAX_ATTEMPTS {
                continue;
            }
            *tries += 1;

            if let Some(name) = reverse_lookup(target, ip).await {
                store.observe_name_for_ip(ip, &name);
                attempts.remove(&ip);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn reverse_lookup(server: SocketAddr, ip: Ipv4Addr) -> Option<String> {
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    let o = ip.octets();
    let arpa = format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]);
    let name = Name::from_ascii(&arpa).ok()?;

    let mut msg = Message::query();
    msg.metadata.recursion_desired = true;
    let mut q = Query::new();
    q.set_name(name);
    q.set_query_type(RecordType::PTR);
    msg.add_query(q);
    let request = msg.to_vec().ok()?;

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(server).await.ok()?;
    sock.send(&request).await.ok()?;

    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(Duration::from_millis(1200), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;

    let resp = Message::from_vec(&buf[..n]).ok()?;
    for rec in &resp.answers {
        if let RData::PTR(ptr) = &rec.data {
            let s = ptr.0.to_ascii();
            let s = s.trim_end_matches('.');
            let short = s.strip_suffix(".local").unwrap_or(s);
            // Strip a trailing search domain like ".lan" or ".home".
            let short = short.split('.').next().unwrap_or(short);
            return Some(short.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dhcp_packet(mac: [u8; 6], hostname: Option<&str>) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // BOOTREQUEST
        p[1] = 1; // ethernet
        p[2] = 6; // hlen
        p[28..34].copy_from_slice(&mac);
        p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        // Option 53: DHCP message type = DISCOVER
        p.extend_from_slice(&[53, 1, 1]);
        if let Some(h) = hostname {
            p.push(12);
            p.push(h.len() as u8);
            p.extend_from_slice(h.as_bytes());
        }
        p.push(255);
        p
    }

    #[test]
    fn parses_dhcp_hostname_and_mac() {
        let pkt = dhcp_packet([0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33], Some("kitchen-pi"));
        let (mac, host) = parse_dhcp(&pkt).expect("should parse");
        assert_eq!(mac, "b8:27:eb:11:22:33");
        assert_eq!(host.as_deref(), Some("kitchen-pi"));
    }

    #[test]
    fn parses_dhcp_without_hostname() {
        let pkt = dhcp_packet([0x5c, 0xcf, 0x7f, 0xaa, 0xbb, 0xcc], None);
        let (mac, host) = parse_dhcp(&pkt).expect("should parse");
        assert_eq!(mac, "5c:cf:7f:aa:bb:cc");
        assert!(host.is_none());
    }

    #[test]
    fn ignores_dhcp_replies_and_runts() {
        let mut pkt = dhcp_packet([1, 2, 3, 4, 5, 6], Some("x"));
        pkt[0] = 2; // BOOTREPLY
        assert!(parse_dhcp(&pkt).is_none());
        assert!(parse_dhcp(&[0u8; 10]).is_none());
    }

    #[test]
    fn survives_truncated_option_length() {
        // An option claiming more bytes than the packet holds must not panic.
        let mut pkt = dhcp_packet([1, 2, 3, 4, 5, 6], None);
        pkt.pop(); // drop the 255 terminator
        pkt.extend_from_slice(&[12, 200]); // hostname option, length 200, no data
        let (mac, host) = parse_dhcp(&pkt).expect("should still yield the MAC");
        assert_eq!(mac, "01:02:03:04:05:06");
        assert!(host.is_none());
    }

    #[test]
    fn converts_ptr_names_to_ips() {
        assert_eq!(
            ptr_name_to_ip("42.1.168.192.in-addr.arpa."),
            Some(Ipv4Addr::new(192, 168, 1, 42))
        );
        assert_eq!(ptr_name_to_ip("example.com."), None);
        assert_eq!(ptr_name_to_ip("1.2.3.in-addr.arpa."), None);
    }

    #[test]
    fn rejects_hostile_hostnames() {
        assert!(sanitize_hostname("kitchen-ipad").is_some());
        assert!(sanitize_hostname("").is_none());
        assert!(sanitize_hostname("has space").is_none());
        assert!(sanitize_hostname("<script>alert(1)</script>").is_none());
        assert!(sanitize_hostname("bell\u{7}name").is_none());
        assert!(sanitize_hostname("192.168.1.5").is_none());
        assert!(sanitize_hostname(&"x".repeat(200)).is_none());
    }

    /// Count how many device rows a store would actually write.
    fn writes_for(store: &DeviceStore) -> usize {
        store
            .inner
            .read()
            .unwrap()
            .by_mac
            .values()
            .filter(|d| d.written_fingerprint.is_some())
            .count()
    }

    #[test]
    fn an_unchanged_device_is_not_rewritten() {
        // The ARP poller re-observes every device every 15s. Before
        // debouncing, each of those was a row write for data that had not
        // changed.
        let mut d = Device {
            mac: "aa:bb:cc:00:00:01".into(),
            ip: Some(Ipv4Addr::new(192, 168, 1, 5)),
            hostname: Some("kitchen-pi".into()),
            ..Device::default()
        };
        let t0 = Instant::now();

        assert!(d.take_write_slot(t0), "first sighting must be written");
        assert!(!d.take_write_slot(t0), "an identical re-sighting must not");
        assert!(!d.take_write_slot(t0), "and still must not");
    }

    #[test]
    fn a_changed_field_forces_a_write_immediately() {
        let mut d = Device {
            mac: "aa:bb:cc:00:00:01".into(),
            ip: Some(Ipv4Addr::new(192, 168, 1, 5)),
            ..Device::default()
        };
        let t0 = Instant::now();
        assert!(d.take_write_slot(t0));
        assert!(!d.take_write_slot(t0));

        // Learning a hostname is exactly the case that must not wait a minute.
        d.hostname = Some("kitchen-pi".into());
        assert!(d.take_write_slot(t0), "a real change is written at once");

        d.ip = Some(Ipv4Addr::new(192, 168, 1, 6));
        assert!(d.take_write_slot(t0), "a new IP is a real change too");
    }

    #[test]
    fn last_seen_is_refreshed_on_a_heartbeat_not_per_query() {
        let mut d = Device {
            mac: "aa:bb:cc:00:00:01".into(),
            ip: Some(Ipv4Addr::new(192, 168, 1, 5)),
            ..Device::default()
        };
        let t0 = Instant::now();
        assert!(d.take_write_slot(t0));

        // Simulate a busy minute of DNS queries: none of them should write.
        for _ in 0..1000 {
            assert!(!d.take_write_slot(t0 + Duration::from_secs(30)));
        }
        // Once the heartbeat elapses, exactly one write happens.
        let later = t0 + LAST_SEEN_HEARTBEAT + Duration::from_secs(1);
        assert!(d.take_write_slot(later), "heartbeat keeps last_seen fresh");
        assert!(!d.take_write_slot(later), "but only once per interval");
    }

    #[test]
    fn repeated_arp_observations_collapse_to_one_write() {
        let store = DeviceStore::new_for_test();
        // What the ARP poller does every 15 seconds, forever.
        for _ in 0..50 {
            store.observe(Ipv4Addr::new(192, 168, 1, 5), "b8:27:eb:11:22:33");
        }
        assert_eq!(
            writes_for(&store),
            1,
            "50 identical ARP sightings are one device, written once"
        );
    }

    #[test]
    fn touch_ip_from_the_query_path_is_debounced() {
        let store = DeviceStore::new_for_test();
        store.observe(Ipv4Addr::new(192, 168, 1, 5), "b8:27:eb:11:22:33");

        let before = store
            .inner
            .read()
            .unwrap()
            .by_mac
            .values()
            .next()
            .unwrap()
            .last_seen_written;

        // A thousand DNS queries from this device.
        for _ in 0..1000 {
            store.touch_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        }

        let after = store
            .inner
            .read()
            .unwrap()
            .by_mac
            .values()
            .next()
            .unwrap()
            .last_seen_written;
        assert_eq!(
            before, after,
            "queries inside the heartbeat window must not touch the database"
        );
    }

    #[test]
    fn drop_counts_are_tracked_per_kind() {
        use crate::db::{QueryEvent, QueryStatus, WriteOp};
        // A tiny queue that we deliberately overrun.
        let writer = crate::db::spawn_writer(
            crate::db::open(std::path::Path::new(":memory:")).unwrap(),
            Duration::from_secs(3600), // never flush during the test
            1,
        );
        let counts = writer.drop_counts();

        // Enough events to exceed the bounded queue.
        for i in 0..20_000 {
            writer.send(WriteOp::Query(QueryEvent {
                ts: 0,
                client_ip: "192.168.1.5".into(),
                domain: format!("d{i}.example.com"),
                qtype: "A".into(),
                status: QueryStatus::Forwarded,
                elapsed_ms: None,
                answer: None,
                blocklist: None,
            }));
        }

        assert!(
            counts.queries.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "overrunning the queue must be counted as dropped queries"
        );
        assert_eq!(
            counts.devices.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "device drops are counted separately and none were sent"
        );
    }

    #[test]
    fn resolves_pending_name_once_arp_arrives() {
        let store = DeviceStore::new_for_test();
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        // Name learned before the MAC is known.
        store.observe_name_for_ip(ip, "living-room-tv");
        store.observe(ip, "b8:27:eb:99:88:77");

        let inner = store.inner.read().unwrap();
        let dev = inner
            .by_mac
            .get("b8:27:eb:99:88:77")
            .expect("device recorded");
        assert_eq!(dev.hostname.as_deref(), Some("living-room-tv"));
        assert_eq!(dev.vendor.as_deref(), Some("Raspberry Pi Foundation"));
    }

    #[test]
    fn flags_randomized_macs_instead_of_guessing_vendor() {
        let store = DeviceStore::new_for_test();
        store.observe(Ipv4Addr::new(192, 168, 1, 60), "a2:11:22:33:44:55");
        let inner = store.inner.read().unwrap();
        let dev = inner.by_mac.get("a2:11:22:33:44:55").unwrap();
        assert!(dev.randomized);
        assert_eq!(dev.vendor.as_deref(), Some("(randomized MAC)"));
    }
}
