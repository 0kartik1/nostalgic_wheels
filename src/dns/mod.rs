//! The DNS forwarder.
//!
//! This is the part that makes the whole tool work. Because the Pi sits beside
//! the router rather than in front of it, it cannot see other devices' packets.
//! What it *can* do is be their DNS server: every device asks it to resolve
//! names, which reveals the domain and the client IP. That is the same trick
//! Pi-hole uses, and it is the only reliable way to attribute traffic to a
//! device on a switched LAN.

pub mod acl;
pub mod cache;

use crate::blocklist::Blocklist;
use crate::db::{QueryEvent, QueryStatus, WriteOp, Writer};
use crate::devices::DeviceStore;
use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::net::{TcpListener, UdpSocket};

/// TTL handed out with a sinkholed answer. Short so unblocking takes effect
/// quickly, but not zero, to avoid hammering us in a retry loop.
const BLOCK_TTL: u32 = 60;

#[derive(Debug, Default)]
pub struct Stats {
    pub total: AtomicU64,
    pub blocked: AtomicU64,
    pub cache_hits: AtomicU64,
    pub upstream_errors: AtomicU64,
    /// Queries dropped because the source was not in `dns.allow_from`.
    pub denied: AtomicU64,
}

pub struct Resolver {
    cfg: crate::config::DnsConfig,
    acl: acl::Acl,
    /// Latches so an unexpected off-LAN source is reported once, loudly,
    /// instead of once per packet.
    warned_denied: std::sync::atomic::AtomicBool,
    block_nxdomain: bool,
    blocklist: Arc<RwLock<Blocklist>>,
    cache: Arc<std::sync::Mutex<cache::Cache>>,
    writer: Writer,
    devices: DeviceStore,
    pub stats: Arc<Stats>,
}

impl Resolver {
    pub fn new(
        cfg: &crate::config::Config,
        lan: Option<crate::netinfo::Subnet>,
        blocklist: Arc<RwLock<Blocklist>>,
        writer: Writer,
        devices: DeviceStore,
    ) -> Self {
        // Validated during config load, so a parse failure here cannot happen;
        // fall back to the safe default rather than panicking.
        let mut acl = acl::Acl::parse(&cfg.dns.allow_from).unwrap_or_else(|e| {
            tracing::error!("invalid dns.allow_from ({e:#}), falling back to private-only");
            acl::Acl::parse(&[]).expect("empty ACL always parses")
        });
        if let Some(s) = lan
            && acl.trust_subnet(s.network, s.prefix_len)
        {
            tracing::info!("also serving DNS to the detected LAN {s} (outside the private ranges)");
        }

        Self {
            cfg: cfg.dns.clone(),
            acl,
            warned_denied: std::sync::atomic::AtomicBool::new(false),
            block_nxdomain: cfg.blocking.mode == "nxdomain",
            blocklist,
            cache: Arc::new(std::sync::Mutex::new(cache::Cache::new(
                cfg.dns.cache_max_entries,
                cfg.dns.cache_min_ttl,
                cfg.dns.cache_max_ttl,
            ))),
            writer,
            devices,
            stats: Arc::new(Stats::default()),
        }
    }

    /// Whether this source may query us at all. Checked before the packet is
    /// even parsed, so a flood of unauthorised traffic costs almost nothing.
    ///
    /// Denied queries are dropped rather than REFUSED: replying would still
    /// send a packet to whatever address the attacker spoofed.
    pub fn allows(&self, client: IpAddr) -> bool {
        if self.acl.allows(client) {
            return true;
        }
        self.stats.denied.fetch_add(1, Ordering::Relaxed);
        if !self.warned_denied.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "dropping DNS query from {client}, which is outside dns.allow_from. \
                 If this is a legitimate client, add its subnet to dns.allow_from. \
                 Further drops are logged at debug level."
            );
        } else {
            tracing::debug!("dropping DNS query from {client} (not in dns.allow_from)");
        }
        false
    }

    pub fn is_open_to_world(&self) -> bool {
        self.acl.is_open_to_world()
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    pub fn flush_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    /// Handle one raw DNS request and produce the raw response to send back.
    ///
    /// Errors are converted into DNS-level failures rather than propagated: a
    /// resolver that stops answering takes the whole network down with it.
    pub async fn handle(&self, request: &[u8], client: SocketAddr) -> Option<Vec<u8>> {
        self.stats.total.fetch_add(1, Ordering::Relaxed);

        let msg = match Message::from_vec(request) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed query from {client}: {e}");
                return None;
            }
        };

        let id = msg.metadata.id;
        // We only serve standard queries. Anything else (UPDATE, NOTIFY) gets
        // a clean refusal instead of being blindly forwarded.
        if msg.metadata.message_type != MessageType::Query || msg.metadata.op_code != OpCode::Query
        {
            return encode(&error_response(&msg, ResponseCode::Refused));
        }

        let Some(query) = msg.queries.first().cloned() else {
            return encode(&error_response(&msg, ResponseCode::FormErr));
        };

        let name = query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let qtype = query.query_type();
        let client_ip = client.ip();

        // Blocklist check comes first: no point spending an upstream round
        // trip on a name we are going to sinkhole.
        let blocked_by = if name.is_empty() {
            None
        } else {
            self.blocklist
                .read()
                .ok()
                .and_then(|bl| bl.lookup(&name).map(|s| s.to_string()))
        };

        if let Some(list) = blocked_by {
            self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            let response = self.sinkhole(&msg, qtype);
            self.log(
                &name,
                qtype,
                client_ip,
                QueryStatus::Blocked,
                None,
                None,
                Some(list),
            );
            return encode(&response);
        }

        // Cache lookup.
        let key = cache::Key {
            name: name.clone(),
            qtype,
        };
        if self.cfg.cache {
            let cached = self.cache.lock().ok().and_then(|mut c| c.get(&key));
            if let Some(mut hit) = cached {
                hit.metadata.id = id;
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                let answer = summarize_answers(&hit);
                self.log(
                    &name,
                    qtype,
                    client_ip,
                    QueryStatus::Cached,
                    None,
                    answer,
                    None,
                );
                return encode(&hit);
            }
        }

        // Forward upstream, trying each resolver in turn.
        let started = Instant::now();
        match self.forward(request).await {
            Ok(raw) => {
                let elapsed = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
                let parsed = Message::from_vec(&raw).ok();

                let (status, answer) = match &parsed {
                    Some(m) => {
                        if self.cfg.cache
                            && let Ok(mut c) = self.cache.lock()
                        {
                            c.insert(key, m);
                        }
                        let status = match m.metadata.response_code {
                            ResponseCode::NoError => QueryStatus::Forwarded,
                            ResponseCode::NXDomain => QueryStatus::NxDomain,
                            ResponseCode::Refused => QueryStatus::Refused,
                            _ => QueryStatus::ServFail,
                        };
                        (status, summarize_answers(m))
                    }
                    None => (QueryStatus::Forwarded, None),
                };

                // An A/AAAA answer for a `.local`-style name, or a PTR, can
                // teach us a device name for free.
                if let Some(m) = &parsed {
                    self.devices.learn_from_dns(m);
                }

                self.log(&name, qtype, client_ip, status, Some(elapsed), answer, None);
                Some(raw)
            }
            Err(e) => {
                self.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("upstream failure for {name} ({qtype}): {e:#}");
                self.log(
                    &name,
                    qtype,
                    client_ip,
                    QueryStatus::ServFail,
                    None,
                    None,
                    None,
                );
                encode(&error_response(&msg, ResponseCode::ServFail))
            }
        }
    }

    /// Send the request to each upstream in order until one answers.
    ///
    /// A fresh socket per query gives us source-port randomisation for free,
    /// which is the main defence against off-path answer spoofing.
    async fn forward(&self, request: &[u8]) -> Result<Vec<u8>> {
        let timeout = std::time::Duration::from_millis(self.cfg.upstream_timeout_ms);
        let mut last_err = None;

        for upstream in &self.cfg.upstreams {
            let bind: SocketAddr = if upstream.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };

            let attempt = async {
                let sock = UdpSocket::bind(bind)
                    .await
                    .context("binding upstream socket")?;
                // connect() filters replies to this peer only.
                sock.connect(upstream)
                    .await
                    .context("connecting upstream")?;
                sock.send(request).await.context("sending to upstream")?;

                let mut buf = vec![0u8; 4096];
                loop {
                    let n = sock
                        .recv(&mut buf)
                        .await
                        .context("reading upstream reply")?;
                    // Drop anything whose transaction ID does not match.
                    if n >= 2 && buf[0..2] == request[0..2] {
                        buf.truncate(n);
                        return Ok::<Vec<u8>, anyhow::Error>(buf);
                    }
                    tracing::debug!("discarding upstream reply with mismatched id");
                }
            };

            match tokio::time::timeout(timeout, attempt).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => {
                    last_err = Some(anyhow::anyhow!("upstream {upstream} timed out"));
                }
            }
            tracing::debug!("upstream {upstream} did not answer, trying next");
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no upstreams configured")))
    }

    /// Build the answer for a blocked name.
    fn sinkhole(&self, request: &Message, qtype: RecordType) -> Message {
        let mut resp = base_response(request);

        if self.block_nxdomain {
            resp.metadata.response_code = ResponseCode::NXDomain;
            return resp;
        }

        // Point A/AAAA at the null address; everything else gets an empty
        // NOERROR, which is the least surprising way to say "nothing here".
        if let Some(query) = request.queries.first() {
            let name = query.name().clone();
            match qtype {
                RecordType::A => {
                    resp.answers.push(Record::from_rdata(
                        name,
                        BLOCK_TTL,
                        RData::A(A(Ipv4Addr::UNSPECIFIED)),
                    ));
                }
                RecordType::AAAA => {
                    resp.answers.push(Record::from_rdata(
                        name,
                        BLOCK_TTL,
                        RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                    ));
                }
                _ => {}
            }
        }
        resp
    }

    #[allow(clippy::too_many_arguments)]
    fn log(
        &self,
        domain: &str,
        qtype: RecordType,
        client: IpAddr,
        status: QueryStatus,
        elapsed_ms: Option<u32>,
        answer: Option<String>,
        blocklist: Option<String>,
    ) {
        // Seeing a query is itself proof the device is awake.
        self.devices.touch_ip(client);

        self.writer.send(WriteOp::Query(QueryEvent {
            ts: crate::db::now(),
            client_ip: client.to_string(),
            domain: domain.to_string(),
            qtype: qtype.to_string(),
            status,
            elapsed_ms,
            answer,
            blocklist,
        }));
    }
}

fn base_response(request: &Message) -> Message {
    let mut resp = Message::response(request.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = request.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.checking_disabled = request.metadata.checking_disabled;
    resp.queries = request.queries.clone();
    // RFC 6891: a response to a query carrying OPT must carry OPT too.
    if let Some(edns) = request.edns.clone() {
        resp.set_edns(edns);
    }
    resp
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut resp = base_response(request);
    resp.metadata.response_code = code;
    resp
}

fn encode(msg: &Message) -> Option<Vec<u8>> {
    match msg.to_vec() {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!("encoding DNS response: {e}");
            None
        }
    }
}

/// Condense the answer section into something readable in the dashboard.
fn summarize_answers(msg: &Message) -> Option<String> {
    if msg.answers.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for rec in msg.answers.iter().take(4) {
        let s = match &rec.data {
            RData::A(a) => a.0.to_string(),
            RData::AAAA(a) => a.0.to_string(),
            RData::CNAME(c) => c.0.to_ascii(),
            RData::PTR(p) => p.0.to_ascii(),
            RData::MX(m) => m.exchange.to_ascii(),
            RData::TXT(_) => "TXT".to_string(),
            other => other.record_type().to_string(),
        };
        parts.push(s);
    }
    if msg.answers.len() > 4 {
        parts.push(format!("+{}", msg.answers.len() - 4));
    }
    Some(parts.join(", "))
}

/// Keep a UDP answer within the size the client said it could accept.
///
/// The limit comes from the request's EDNS0 OPT record, defaulting to the
/// classic 512 bytes when there is none. Oversized answers come back as a
/// truncated (TC=1) message, which is the signal to retry over TCP.
fn fit_udp(request: &[u8], response: Vec<u8>) -> Option<Vec<u8>> {
    let req = Message::from_vec(request).ok()?;
    let limit = req.max_payload() as usize;
    if response.len() <= limit {
        return Some(response);
    }

    let resp = Message::from_vec(&response).ok()?;
    let truncated = resp.truncate();
    match truncated.to_vec() {
        Ok(bytes) if bytes.len() <= limit => Some(bytes),
        Ok(bytes) => {
            tracing::debug!(
                "truncated response still {} bytes over {limit}",
                bytes.len()
            );
            Some(bytes)
        }
        Err(e) => {
            tracing::error!("encoding truncated response: {e}");
            None
        }
    }
}

/// Serve DNS over UDP. Each request is handled in its own task so a slow
/// upstream cannot head-of-line block the rest of the network.
pub async fn serve_udp(resolver: Arc<Resolver>, listen: SocketAddr) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen).await.with_context(|| {
        format!("binding UDP {listen} (port 53 needs root or CAP_NET_BIND_SERVICE)")
    })?);
    tracing::info!("DNS listening on {listen}/udp");

    // 4096 covers EDNS0 payloads; larger answers arrive over TCP.
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("UDP recv error: {e}");
                continue;
            }
        };

        // Cheapest possible rejection: no allocation, no parse, no reply.
        if !resolver.allows(peer.ip()) {
            continue;
        }

        let request = buf[..len].to_vec();
        let resolver = Arc::clone(&resolver);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let Some(response) = resolver.handle(&request, peer).await else {
                return;
            };

            // If the answer will not fit in the client's UDP buffer, send a
            // proper TC-flagged stub so it retries over TCP. Slicing the bytes
            // would hand the client a malformed message instead.
            let out = match fit_udp(&request, response) {
                Some(bytes) => bytes,
                None => return,
            };
            if let Err(e) = socket.send_to(&out, peer).await {
                tracing::debug!("UDP send to {peer} failed: {e}");
            }
        });
    }
}

/// Serve DNS over TCP (RFC 1035 length-prefixed framing).
pub async fn serve_tcp(resolver: Arc<Resolver>, listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding TCP {listen}"))?;
    tracing::info!("DNS listening on {listen}/tcp");

    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("TCP accept error: {e}");
                continue;
            }
        };

        // Close on unauthorised sources before allocating a task for them.
        if !resolver.allows(peer.ip()) {
            continue;
        }

        let resolver = Arc::clone(&resolver);

        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Bound how long a single connection can sit idle holding a task.
            let session = async {
                loop {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return; // clean close or truncated frame
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    if len == 0 || len > 65_535 {
                        return;
                    }
                    let mut request = vec![0u8; len];
                    if stream.read_exact(&mut request).await.is_err() {
                        return;
                    }

                    let Some(response) = resolver.handle(&request, peer).await else {
                        return;
                    };
                    let Ok(len) = u16::try_from(response.len()) else {
                        return;
                    };
                    if stream.write_all(&len.to_be_bytes()).await.is_err()
                        || stream.write_all(&response).await.is_err()
                    {
                        return;
                    }
                }
            };

            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), session).await;
        });
    }
}

/// Periodically drop expired cache entries so idle memory does not creep up.
pub async fn cache_sweeper(resolver: Arc<Resolver>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tick.tick().await;
        if let Ok(mut c) = resolver.cache.lock() {
            c.sweep();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;

    fn query_bytes(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = 0x1234;
        msg.metadata.recursion_desired = true;
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii(name).unwrap());
        q.set_query_type(qtype);
        msg.add_query(q);
        msg.to_vec().unwrap()
    }

    #[test]
    fn sinkhole_returns_null_address_for_a() {
        let request = Message::from_vec(&query_bytes("ads.example.com.", RecordType::A)).unwrap();
        let cfg = crate::config::Config::default();
        let resolver = Resolver {
            cfg: cfg.dns.clone(),
            acl: acl::Acl::parse(&cfg.dns.allow_from).unwrap(),
            warned_denied: std::sync::atomic::AtomicBool::new(false),
            block_nxdomain: false,
            blocklist: Arc::new(RwLock::new(Blocklist::default())),
            cache: Arc::new(std::sync::Mutex::new(cache::Cache::new(10, 30, 300))),
            writer: crate::db::spawn_writer(
                crate::db::open(std::path::Path::new(":memory:")).unwrap(),
                std::time::Duration::from_millis(10),
                1,
            ),
            devices: DeviceStore::new_for_test(),
            stats: Arc::new(Stats::default()),
        };

        let resp = resolver.sinkhole(&request, RecordType::A);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
            other => panic!("expected A record, got {other:?}"),
        }
        // The response must echo the request's transaction ID.
        assert_eq!(resp.metadata.id, 0x1234);
    }

    #[test]
    fn refuses_non_query_opcodes() {
        let mut msg = Message::new(7, MessageType::Query, OpCode::Update);
        msg.metadata.id = 7;
        let resp = error_response(&msg, ResponseCode::Refused);
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert_eq!(resp.metadata.id, 7);
    }

    /// Build a resolver wired to an in-memory database, for tests that only
    /// exercise decision logic rather than real network I/O.
    fn test_resolver(cfg: &crate::config::Config) -> Resolver {
        Resolver {
            cfg: cfg.dns.clone(),
            acl: acl::Acl::parse(&cfg.dns.allow_from).unwrap(),
            warned_denied: std::sync::atomic::AtomicBool::new(false),
            block_nxdomain: false,
            blocklist: Arc::new(RwLock::new(Blocklist::default())),
            cache: Arc::new(std::sync::Mutex::new(cache::Cache::new(10, 30, 300))),
            writer: crate::db::spawn_writer(
                crate::db::open(std::path::Path::new(":memory:")).unwrap(),
                std::time::Duration::from_millis(10),
                1,
            ),
            devices: DeviceStore::new_for_test(),
            stats: Arc::new(Stats::default()),
        }
    }

    #[test]
    fn default_config_refuses_to_serve_the_internet() {
        // This is the open-resolver guard: by default only the LAN is served.
        let resolver = test_resolver(&crate::config::Config::default());

        assert!(resolver.allows("192.168.1.20".parse().unwrap()));
        assert!(resolver.allows("127.0.0.1".parse().unwrap()));
        assert!(!resolver.allows("8.8.8.8".parse().unwrap()));
        assert!(!resolver.allows("203.0.113.7".parse().unwrap()));

        // Denials are counted so the dashboard can surface them.
        assert_eq!(resolver.stats.denied.load(Ordering::Relaxed), 2);
        assert!(!resolver.is_open_to_world());
    }

    #[test]
    fn allow_from_any_is_respected_when_set_deliberately() {
        let mut cfg = crate::config::Config::default();
        cfg.dns.allow_from = vec!["any".to_string()];
        let resolver = test_resolver(&cfg);

        assert!(resolver.allows("8.8.8.8".parse().unwrap()));
        assert_eq!(resolver.stats.denied.load(Ordering::Relaxed), 0);
        assert!(
            resolver.is_open_to_world(),
            "startup must be able to warn about this"
        );
    }

    #[test]
    fn a_malformed_allow_from_is_rejected_at_config_load() {
        let toml = "[dns]\nallow_from = [\"not-a-subnet\"]\n";
        let cfg: crate::config::Config = toml::from_str(toml).unwrap();
        // Deserialising is permissive; validation is what must catch it.
        assert!(
            crate::dns::acl::Acl::parse(&cfg.dns.allow_from).is_err(),
            "a typo in allow_from must not silently change who is served"
        );
    }

    #[test]
    fn small_answers_pass_through_unchanged() {
        let request = query_bytes("example.com.", RecordType::A);
        let mut resp = Message::response(0x1234, OpCode::Query);
        resp.queries = Message::from_vec(&request).unwrap().queries;
        resp.answers.push(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let bytes = resp.to_vec().unwrap();
        let out = fit_udp(&request, bytes.clone()).expect("should fit");
        assert_eq!(out, bytes, "a small answer must not be rewritten");
    }

    #[test]
    fn oversized_answers_come_back_truncated() {
        let request = query_bytes("example.com.", RecordType::A);
        let mut resp = Message::response(0x1234, OpCode::Query);
        resp.queries = Message::from_vec(&request).unwrap().queries;
        // No EDNS on the request, so the limit is 512 bytes. 100 A records is
        // comfortably past that.
        for i in 0..100u8 {
            resp.answers.push(Record::from_rdata(
                Name::from_ascii(format!("host{i}.example.com.")).unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(10, 0, 0, i))),
            ));
        }
        let bytes = resp.to_vec().unwrap();
        assert!(
            bytes.len() > 512,
            "test fixture should exceed the UDP limit"
        );

        let out = fit_udp(&request, bytes).expect("should produce a stub");
        let parsed = Message::from_vec(&out).unwrap();
        assert!(parsed.metadata.truncation, "TC bit must be set");
        assert!(
            parsed.answers.is_empty(),
            "truncated stub carries no answers"
        );
        assert_eq!(parsed.metadata.id, 0x1234, "transaction ID must survive");
        assert!(out.len() <= 512);
    }

    #[test]
    fn edns_opt_is_echoed_back() {
        use hickory_proto::op::Edns;
        let mut req = Message::query();
        req.metadata.id = 0x4242;
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_ascii("ads.example.com.").unwrap());
        q.set_query_type(RecordType::A);
        req.add_query(q);
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        req.set_edns(edns);

        let resp = base_response(&req);
        assert!(resp.edns.is_some(), "OPT must be echoed per RFC 6891");
        assert_eq!(resp.max_payload(), 4096);
    }

    #[test]
    fn cache_counts_ttl_down() {
        let mut c = cache::Cache::new(10, 1, 3600);
        let mut msg = Message::response(1, OpCode::Query);
        msg.answers.push(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let key = cache::Key {
            name: "example.com".into(),
            qtype: RecordType::A,
        };
        assert!(c.insert(key.clone(), &msg));

        let hit = c.get(&key).expect("should hit");
        // Immediately after insert the TTL is intact (or one second lower).
        assert!(hit.answers[0].ttl <= 300 && hit.answers[0].ttl >= 299);
    }

    #[test]
    fn cache_rejects_servfail() {
        let mut c = cache::Cache::new(10, 1, 3600);
        let mut msg = Message::response(1, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        msg.answers.push(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let key = cache::Key {
            name: "example.com".into(),
            qtype: RecordType::A,
        };
        assert!(!c.insert(key, &msg));
    }
}
