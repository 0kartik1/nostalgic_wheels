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
use std::time::{Duration, Instant};
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
    /// UDP queries dropped because `dns.max_udp_in_flight` was reached.
    pub udp_overload_drops: AtomicU64,
    /// TCP connections closed at accept because the limit was reached.
    pub tcp_rejections: AtomicU64,
    /// Requests abandoned at `dns.request_timeout_ms`.
    pub request_timeouts: AtomicU64,
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

    pub fn max_udp_in_flight(&self) -> usize {
        self.cfg.max_udp_in_flight
    }

    pub fn max_tcp_connections(&self) -> usize {
        self.cfg.max_tcp_connections
    }

    /// Record a UDP query shed because we were already at capacity.
    pub fn note_udp_overload(&self) {
        let n = self
            .stats
            .udp_overload_drops
            .fetch_add(1, Ordering::Relaxed);
        // Loud once, then quiet: an overload produces a lot of these.
        if n == 0 {
            tracing::warn!(
                "at dns.max_udp_in_flight ({}); shedding queries until it clears. \
                 Raise the limit if this is normal load rather than a misbehaving device.",
                self.cfg.max_udp_in_flight
            );
        }
    }

    pub fn note_tcp_rejection(&self) {
        let n = self.stats.tcp_rejections.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            tracing::warn!(
                "at dns.max_tcp_connections ({}); refusing new DNS/TCP connections",
                self.cfg.max_tcp_connections
            );
        }
    }

    /// Largest UDP payload we are prepared to put on the wire or reassemble.
    pub fn udp_payload_limit(&self) -> u16 {
        self.cfg.upstream_udp_payload
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
        // A single budget for the whole request, not per upstream attempt.
        // Without this, N upstreams each timing out could hold a permit for
        // N * upstream_timeout_ms and starve everyone else during an outage.
        let budget = Duration::from_millis(self.cfg.request_timeout_ms);
        match tokio::time::timeout(budget, self.handle_inner(request, client)).await {
            Ok(out) => out,
            Err(_) => {
                let n = self.stats.request_timeouts.fetch_add(1, Ordering::Relaxed);
                if n == 0 {
                    tracing::warn!(
                        "a request from {client} exceeded dns.request_timeout_ms ({} ms); \
                         answering SERVFAIL. Further timeouts are counted in /api/status.",
                        self.cfg.request_timeout_ms
                    );
                }
                // Tell the client rather than going silent: it can fail over
                // to its secondary resolver immediately instead of waiting.
                let msg = Message::from_vec(request).ok()?;
                encode(&error_response(
                    &msg,
                    ResponseCode::ServFail,
                    self.cfg.upstream_udp_payload,
                ))
            }
        }
    }

    async fn handle_inner(&self, request: &[u8], client: SocketAddr) -> Option<Vec<u8>> {
        self.stats.total.fetch_add(1, Ordering::Relaxed);
        let payload_limit = self.cfg.upstream_udp_payload;

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
            return encode(&error_response(&msg, ResponseCode::Refused, payload_limit));
        }

        let Some(query) = msg.queries.first().cloned() else {
            return encode(&error_response(&msg, ResponseCode::FormErr, payload_limit));
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

        // Cache lookup. The key carries class and the DO/CD bits, so a cached
        // answer can only satisfy a request that asked the same question in
        // the same terms.
        let key = cache::Key::from_request(&msg, &name);
        if self.cfg.cache
            && let Some(key) = key.clone()
        {
            let cached = self.cache.lock().ok().and_then(|mut c| c.get(&key));
            if let Some(hit) = cached {
                // Build a fresh envelope from *this* request. Reusing the
                // stored message would hand this client the previous one's
                // transaction ID, RD/CD bits and EDNS options.
                let mut resp = base_response(&msg, payload_limit);
                resp.metadata.response_code = hit.response_code;
                resp.metadata.authoritative = hit.authoritative;
                resp.answers = hit.answers;
                resp.authorities = hit.authorities;
                resp.additionals = hit.additionals;

                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                let answer = summarize_answers(&resp);
                self.log(
                    &name,
                    qtype,
                    client_ip,
                    QueryStatus::Cached,
                    None,
                    answer,
                    None,
                );
                debug_assert_eq!(resp.metadata.id, id);
                return encode(&resp);
            }
        }

        // Forward upstream, trying each resolver in turn.
        let started = Instant::now();
        match self.forward(request, &msg).await {
            Ok(raw) => {
                let elapsed = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
                let parsed = Message::from_vec(&raw).ok();

                let (status, answer) = match &parsed {
                    Some(m) => {
                        if self.cfg.cache
                            && let Some(key) = key.clone()
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
                encode(&error_response(&msg, ResponseCode::ServFail, payload_limit))
            }
        }
    }

    /// Send the request to each upstream in order until one answers.
    ///
    /// A fresh socket per query gives us source-port randomisation for free,
    /// which is the main defence against off-path answer spoofing.
    async fn forward(&self, request: &[u8], parsed: &Message) -> Result<Vec<u8>> {
        let timeout = std::time::Duration::from_millis(self.cfg.upstream_timeout_ms);
        let limit = self.cfg.upstream_udp_payload;
        let mut last_err = None;

        // Never let a client's advertised EDNS size dictate how much we have to
        // buffer from upstream. A client may claim it can take 64 KiB; we only
        // promise upstream what we are actually prepared to reassemble.
        let wire = clamp_upstream_payload(request, parsed, limit);

        for upstream in &self.cfg.upstreams {
            let attempt = async {
                let reply = udp_exchange(*upstream, &wire, limit).await?;

                // A truncated UDP answer is not an answer. Retry this same
                // upstream over TCP rather than relaying TC onward: a client
                // that already used TCP has nowhere left to escalate to, and
                // caching a TC stub would be wrong for everyone.
                let truncated = Message::from_vec(&reply)
                    .map(|m| m.metadata.truncation)
                    .unwrap_or(false);
                if truncated {
                    tracing::debug!("upstream {upstream} truncated; retrying over TCP");
                    return tcp_exchange(*upstream, &wire).await;
                }
                Ok::<Vec<u8>, anyhow::Error>(reply)
            };

            match tokio::time::timeout(timeout, attempt).await {
                Ok(Ok(reply)) => {
                    // Only accept an answer to the question we actually asked.
                    match Message::from_vec(&reply) {
                        Ok(m) if answers_request(parsed, &m) => return Ok(reply),
                        Ok(_) => {
                            last_err = Some(anyhow::anyhow!(
                                "upstream {upstream} answered a different question"
                            ));
                        }
                        Err(e) => {
                            last_err =
                                Some(anyhow::anyhow!("undecodable reply from {upstream}: {e}"));
                        }
                    }
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => {
                    last_err = Some(anyhow::anyhow!("upstream {upstream} timed out"));
                }
            }
            tracing::debug!("upstream {upstream} did not answer usefully, trying next");
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no upstreams configured")))
    }

    /// Build the answer for a blocked name.
    fn sinkhole(&self, request: &Message, qtype: RecordType) -> Message {
        let mut resp = base_response(request, self.cfg.upstream_udp_payload);

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

fn base_response(request: &Message, our_max_payload: u16) -> Message {
    let mut resp = Message::response(request.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = request.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.checking_disabled = request.metadata.checking_disabled;
    resp.queries = request.queries.clone();
    // RFC 6891: a response to a query carrying OPT must carry OPT too — but
    // advertise the size *we* can reassemble, not the one the client wished for.
    if let Some(edns) = cache::response_edns(request, our_max_payload) {
        resp.set_edns(edns);
    }
    resp
}

fn error_response(request: &Message, code: ResponseCode, our_max_payload: u16) -> Message {
    let mut resp = base_response(request, our_max_payload);
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

/// Re-encode the request with its EDNS payload size clamped to `limit`.
///
/// Returns the original bytes untouched when no clamping is needed, so the
/// common path stays byte-exact and cannot be perturbed by a re-encode.
fn clamp_upstream_payload(request: &[u8], parsed: &Message, limit: u16) -> Vec<u8> {
    let needs_clamp = parsed
        .edns
        .as_ref()
        .is_some_and(|e| e.max_payload() > limit);
    if !needs_clamp {
        return request.to_vec();
    }

    let mut m = parsed.clone();
    if let Some(e) = m.edns.as_mut() {
        e.set_max_payload(limit);
    }
    match m.to_vec() {
        Ok(v) => v,
        // Re-encoding should not fail, but forwarding the original is a better
        // failure mode than dropping the query.
        Err(e) => {
            tracing::debug!("could not clamp EDNS payload, forwarding as-is: {e}");
            request.to_vec()
        }
    }
}

/// One UDP round trip to an upstream, on a fresh socket.
///
/// A new socket per query gives source-port randomisation for free, which is
/// the main defence against off-path answer spoofing. The receive buffer is
/// sized to what we advertised, so a compliant upstream's answer never gets
/// silently clipped by the kernel.
async fn udp_exchange(upstream: SocketAddr, wire: &[u8], limit: u16) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let sock = UdpSocket::bind(bind)
        .await
        .context("binding upstream socket")?;
    // connect() filters replies to this peer only.
    sock.connect(upstream)
        .await
        .context("connecting upstream")?;
    sock.send(wire).await.context("sending to upstream")?;

    // Never smaller than the 512-byte classic limit, even if configured low.
    let mut buf = vec![0u8; (limit as usize).max(512)];
    loop {
        let n = sock
            .recv(&mut buf)
            .await
            .context("reading upstream reply")?;
        // Cheap pre-filter on the transaction ID; the caller re-checks the
        // full question once the message is decoded.
        if n >= 2 && buf[0..2] == wire[0..2] {
            buf.truncate(n);
            return Ok(buf);
        }
        tracing::debug!("discarding upstream reply with mismatched id");
    }
}

/// One DNS-over-TCP round trip, used when UDP came back truncated.
async fn tcp_exchange(upstream: SocketAddr, wire: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(upstream)
        .await
        .context("connecting upstream over TCP")?;

    // RFC 1035 §4.2.2: a two-byte big-endian length precedes the message.
    let len = u16::try_from(wire.len()).context("request too large for DNS/TCP")?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("sending TCP length prefix")?;
    stream
        .write_all(wire)
        .await
        .context("sending TCP request")?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("reading TCP length prefix")?;
    let expect = u16::from_be_bytes(len_buf) as usize;
    if expect == 0 {
        anyhow::bail!("upstream sent an empty TCP response");
    }

    // Bounded by the 16-bit length prefix, so this cannot be used to make us
    // allocate without limit.
    let mut reply = vec![0u8; expect];
    stream
        .read_exact(&mut reply)
        .await
        .context("reading TCP response body")?;
    Ok(reply)
}

/// Whether `resp` actually answers `req`, rather than merely sharing its ID.
///
/// An off-path attacker who guesses the transaction ID still has to match the
/// question, and a confused upstream that answers the wrong thing is a bug we
/// would rather surface than cache.
fn answers_request(req: &Message, resp: &Message) -> bool {
    if resp.metadata.id != req.metadata.id {
        return false;
    }
    // A response to a query with no question section is not something we
    // forward, so both sides must carry exactly one matching question.
    let (Some(q), Some(a)) = (req.queries.first(), resp.queries.first()) else {
        return false;
    };
    q.query_type() == a.query_type()
        && q.query_class() == a.query_class()
        // Names are compared case-insensitively: 0x20 randomisation and plain
        // case-preserving upstreams both echo the question back in mixed case.
        && q.name().to_ascii().eq_ignore_ascii_case(&a.name().to_ascii())
}

/// Keep a UDP answer within the size the client said it could accept.
///
/// The limit comes from the request's EDNS0 OPT record, defaulting to the
/// classic 512 bytes when there is none. Oversized answers come back as a
/// truncated (TC=1) message, which is the signal to retry over TCP.
fn fit_udp(request: &[u8], response: Vec<u8>, our_max_payload: u16) -> Option<Vec<u8>> {
    let req = Message::from_vec(request).ok()?;
    // Honour the smaller of what the client asked for and what we are willing
    // to put on the wire: a client claiming 64 KiB must not provoke a heavily
    // fragmented datagram just because a TCP upstream had that much to say.
    let limit = req.max_payload().min(our_max_payload).max(512) as usize;
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

/// How long to keep retrying a bind that fails with `AddrInUse` before giving
/// up for good. Long enough to ride out a boot-time race — some other process
/// (a DHCP client hook, a distro's local resolver stub) can transiently hold
/// port 53 for the first few seconds after boot and then release it — short
/// enough that a genuinely permanent conflict still surfaces quickly.
const BIND_RETRY_WINDOW: Duration = Duration::from_secs(30);

/// Retry a bind for up to `max_wait`, backing off between attempts.
///
/// Only `AddrInUse` is retried. Anything else — most importantly
/// `PermissionDenied`, which is what an unprivileged process trying to bind
/// port 53 actually gets — fails immediately, because waiting cannot fix it.
async fn bind_with_retry<F, Fut, T>(what: &str, max_wait: Duration, mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let deadline = Instant::now() + max_wait;
    let mut delay = Duration::from_millis(250);

    loop {
        match attempt().await {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                tracing::warn!(
                    "{what}: address in use, retrying in {delay:?} — another process may be \
                     holding it briefly (common right after boot); giving up after {max_wait:?} total"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            Err(e) => {
                // EAFNOSUPPORT means the kernel has no IPv6 at all, which the
                // usual "needs root" hint would send the operator chasing the
                // wrong thing.
                let hint = if e.raw_os_error() == Some(97) {
                    "this host has no IPv6 support — unset dns.listen_v6"
                } else {
                    "port 53 needs root or CAP_NET_BIND_SERVICE"
                };
                return Err(anyhow::Error::new(e).context(format!("{what} ({hint})")));
            }
        }
    }
}

/// Create a socket for `addr`, forcing `IPV6_V6ONLY` when it is IPv6.
///
/// Linux defaults `net.ipv6.bindv6only` to 0, so a plain bind of `[::]:53`
/// also claims `0.0.0.0:53`. netwatch runs the IPv4 and IPv6 listeners as two
/// independent sockets, so that default would make whichever binds second fail
/// with `AddrInUse` — and on a host where the sysctl is 1 it would work,
/// giving two machines opposite behaviour from the same config. Being explicit
/// removes the ambiguity in both directions.
fn new_socket(addr: SocketAddr, ty: socket2::Type) -> std::io::Result<socket2::Socket> {
    let domain = socket2::Domain::for_address(addr);
    let sock = socket2::Socket::new(domain, ty, None)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    // Without this a listener left in TIME_WAIT by the previous run blocks the
    // restart, which is the exact case the bind retry exists to survive.
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock)
}

async fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = new_socket(addr, socket2::Type::DGRAM)?;
    UdpSocket::from_std(std::net::UdpSocket::from(sock))
}

async fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let sock = new_socket(addr, socket2::Type::STREAM)?;
    // 128 is the conventional default; excess connections are refused by the
    // kernel, which is the same answer the semaphore gives once accepted.
    sock.listen(128)?;
    TcpListener::from_std(std::net::TcpListener::from(sock))
}

/// Serve DNS over UDP. Each request is handled in its own task so a slow
/// upstream cannot head-of-line block the rest of the network.
pub async fn serve_udp(resolver: Arc<Resolver>, listen: SocketAddr) -> Result<()> {
    let socket = Arc::new(
        bind_with_retry(&format!("binding UDP {listen}"), BIND_RETRY_WINDOW, || {
            bind_udp(listen)
        })
        .await?,
    );
    let payload_limit = resolver.udp_payload_limit();
    // Bounds how much work can exist at once. Dropping is the right response
    // to saturation for UDP: the client retries, whereas an unbounded backlog
    // of tasks would consume memory until the Pi died and would be answering
    // stale questions by the time it drained.
    let in_flight = Arc::new(tokio::sync::Semaphore::new(resolver.max_udp_in_flight()));
    tracing::info!(
        "DNS listening on {listen}/udp (max {} in flight)",
        resolver.max_udp_in_flight()
    );

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

        // Acquire before allocating or spawning, so an overload costs us
        // nothing but the recv we already did.
        let Ok(permit) = Arc::clone(&in_flight).try_acquire_owned() else {
            resolver.note_udp_overload();
            continue;
        };

        let request = buf[..len].to_vec();
        let resolver = Arc::clone(&resolver);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            // Held for the whole request, released on every exit path
            // including panics, because it is owned by this task.
            let _permit = permit;

            let Some(response) = resolver.handle(&request, peer).await else {
                return;
            };

            // If the answer will not fit in the client's UDP buffer, send a
            // proper TC-flagged stub so it retries over TCP. Slicing the bytes
            // would hand the client a malformed message instead.
            let out = match fit_udp(&request, response, payload_limit) {
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
    let listener = bind_with_retry(&format!("binding TCP {listen}"), BIND_RETRY_WINDOW, || {
        bind_tcp(listen)
    })
    .await?;
    let conns = Arc::new(tokio::sync::Semaphore::new(resolver.max_tcp_connections()));
    tracing::info!(
        "DNS listening on {listen}/tcp (max {} connections)",
        resolver.max_tcp_connections()
    );

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

        // Over the limit: drop the accepted stream, which closes it. Better a
        // clear refusal the client can retry than an unbounded pile of idle
        // connections each holding a task and buffers.
        let Ok(permit) = Arc::clone(&conns).try_acquire_owned() else {
            resolver.note_tcp_rejection();
            continue;
        };

        let resolver = Arc::clone(&resolver);

        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Released when the connection ends, however it ends.
            let _permit = permit;

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

    // Paused-time tests for the boot-race bind retry. `start_paused` makes
    // `tokio::time::sleep` advance instantly instead of burning real wall
    // clock, so a test that simulates a 30-second retry window still runs in
    // milliseconds.

    #[tokio::test(start_paused = true)]
    async fn bind_retry_succeeds_immediately_without_retrying() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result = bind_with_retry("test", Duration::from_secs(5), || {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Ok::<_, std::io::Error>(42))
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "no retry needed, no retry taken"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bind_retry_recovers_from_a_transient_conflict() {
        // Simulates exactly what happened on the reporter's Pi: something else
        // holds the port for the first couple of attempts, then lets go.
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result = bind_with_retry("test", Duration::from_secs(30), || {
            let n = calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(if n < 2 {
                Err(std::io::Error::from(std::io::ErrorKind::AddrInUse))
            } else {
                Ok(42)
            })
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            3,
            "two failures, then the successful attempt"
        );
    }

    /// Some CI containers (and this project's own dev container) are built
    /// without IPv6, where every AF_INET6 socket fails with EAFNOSUPPORT.
    /// That is not a netwatch bug, so the v6 tests report it and stop rather
    /// than failing — but only for that specific errno, so a real regression
    /// still fails loudly.
    fn ipv6_unavailable(e: &std::io::Error) -> bool {
        // EAFNOSUPPORT = 97 on Linux; ADDRNOTAVAIL covers hosts with the
        // module loaded but no addresses configured.
        e.raw_os_error() == Some(97) || e.kind() == std::io::ErrorKind::AddrNotAvailable
    }

    /// The whole point of `new_socket`: an IPv6 listener must not also claim
    /// the IPv4 port, or the two DNS listeners would collide on hosts where
    /// `net.ipv6.bindv6only` is 0 (the Linux default, including Raspberry Pi
    /// OS). If this regresses, netwatch fails to start with IPv6 enabled.
    #[tokio::test]
    async fn v6_and_v4_udp_listeners_coexist_on_the_same_port() {
        // Bind v6 to an ephemeral port first, then ask for the same port on
        // v4. A dual-stack v6 socket would have taken both and this would fail.
        let v6 = match bind_udp("[::]:0".parse().unwrap()).await {
            Ok(s) => s,
            Err(e) if ipv6_unavailable(&e) => {
                eprintln!("skipping: no IPv6 on this host ({e})");
                return;
            }
            Err(e) => panic!("bind [::]:0: {e}"),
        };
        let port = v6.local_addr().expect("local_addr").port();
        let v4 = bind_udp(format!("0.0.0.0:{port}").parse().unwrap()).await;
        assert!(
            v4.is_ok(),
            "IPv4 bind on port {port} must succeed alongside the IPv6 listener: {:?}",
            v4.err()
        );
    }

    #[tokio::test]
    async fn v6_and_v4_tcp_listeners_coexist_on_the_same_port() {
        let v6 = match bind_tcp("[::]:0".parse().unwrap()).await {
            Ok(s) => s,
            Err(e) if ipv6_unavailable(&e) => {
                eprintln!("skipping: no IPv6 on this host ({e})");
                return;
            }
            Err(e) => panic!("bind [::]:0: {e}"),
        };
        let port = v6.local_addr().expect("local_addr").port();
        let v4 = bind_tcp(format!("0.0.0.0:{port}").parse().unwrap()).await;
        assert!(
            v4.is_ok(),
            "IPv4 bind on port {port} must succeed alongside the IPv6 listener: {:?}",
            v4.err()
        );
    }

    /// `bind_udp` has to produce a socket tokio can actually poll — the
    /// handover from socket2 loses the non-blocking flag if it is not set.
    #[tokio::test]
    async fn bound_udp_socket_is_usable() {
        let server = bind_udp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = bind_udp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        client.send_to(b"hello", addr).await.unwrap();

        let mut buf = [0u8; 16];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
            .await
            .expect("a datagram sent to a bound socket must arrive")
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn bind_retry_gives_up_after_the_window_and_reports_why() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result = bind_with_retry("binding UDP 0.0.0.0:53", Duration::from_millis(900), || {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Err::<u32, _>(std::io::Error::from(
                std::io::ErrorKind::AddrInUse,
            )))
        })
        .await;
        let err = result.expect_err("a permanent conflict must eventually surface");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("binding UDP 0.0.0.0:53"),
            "names what failed: {msg}"
        );
        assert!(
            msg.contains("CAP_NET_BIND_SERVICE"),
            "keeps the actionable hint: {msg}"
        );
        assert!(
            calls.load(Ordering::Relaxed) >= 2,
            "must have retried at least once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bind_retry_does_not_retry_permission_denied() {
        // Permission errors (no CAP_NET_BIND_SERVICE) cannot be fixed by
        // waiting, unlike a transient AddrInUse race — retrying would just
        // waste the whole 30s window before reporting a problem retrying
        // could never have solved.
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result = bind_with_retry("test", Duration::from_secs(30), || {
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Err::<u32, _>(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )))
        })
        .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "must not retry a non-AddrInUse error"
        );
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
        let resp = error_response(&msg, ResponseCode::Refused, 1232);
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

    // ---- upstream behaviour, against a real mock resolver ----------------
    //
    // These drive the actual socket path rather than a helper in isolation:
    // the mock binds a real UDP (and where needed TCP) port and speaks wire
    // format, so encoding, sizing and framing bugs surface here.

    use hickory_proto::op::Query;
    use tokio::net::UdpSocket as TokioUdp;

    /// A question we can build both a request and a matching answer from.
    fn q(name: &str, qtype: RecordType) -> Query {
        let mut query = Query::new();
        query.set_name(Name::from_ascii(name).unwrap());
        query.set_query_type(qtype);
        query
    }

    fn request_msg(name: &str, qtype: RecordType, id: u16) -> Message {
        let mut m = Message::query();
        m.metadata.id = id;
        m.metadata.recursion_desired = true;
        m.add_query(q(name, qtype));
        m
    }

    /// Build a reply carrying `n` A records, optionally flagged truncated.
    fn reply_for(req: &Message, n: usize, truncated: bool) -> Message {
        let mut r = Message::response(req.metadata.id, OpCode::Query);
        r.queries = req.queries.clone();
        r.metadata.truncation = truncated;
        if !truncated {
            for i in 0..n {
                r.answers.push(Record::from_rdata(
                    Name::from_ascii(format!("host{i}.example.com.")).unwrap(),
                    300,
                    RData::A(A(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))),
                ));
            }
        }
        r
    }

    #[tokio::test]
    async fn upstream_tc_answer_is_retried_over_tcp() {
        // The bug this pins: a truncated UDP answer used to be relayed
        // straight through. A TCP client receiving TC has nowhere to escalate
        // to, so the name simply never resolved.
        let udp = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let upstream: SocketAddr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(upstream).await.unwrap();

        // UDP side: always answer TC=1, no records.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let req = Message::from_vec(&buf[..n]).unwrap();
            let tc = reply_for(&req, 0, true);
            udp.send_to(&tc.to_vec().unwrap(), peer).await.unwrap();
        });

        // TCP side: serve the full answer with length framing.
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut body).await.unwrap();
            let req = Message::from_vec(&body).unwrap();
            let full = reply_for(&req, 40, false).to_vec().unwrap();
            s.write_all(&(full.len() as u16).to_be_bytes())
                .await
                .unwrap();
            s.write_all(&full).await.unwrap();
        });

        let mut cfg = crate::config::Config::default();
        cfg.dns.upstreams = vec![upstream];
        let resolver = test_resolver(&cfg);

        let req = request_msg("big.example.com.", RecordType::A, 0x4242);
        let wire = req.to_vec().unwrap();
        let raw = resolver.forward(&wire, &req).await.expect("TCP fallback");

        let got = Message::from_vec(&raw).unwrap();
        assert!(!got.metadata.truncation, "TC must be resolved, not relayed");
        assert_eq!(got.answers.len(), 40, "full answer came back over TCP");
    }

    #[tokio::test]
    async fn a_reply_to_a_different_question_is_rejected() {
        // Matching only the transaction ID is not enough.
        let udp = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let upstream: SocketAddr = udp.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let req = Message::from_vec(&buf[..n]).unwrap();
            // Same ID, different name entirely.
            let mut evil = Message::response(req.metadata.id, OpCode::Query);
            evil.add_query(q("attacker.example.net.", RecordType::A));
            evil.answers.push(Record::from_rdata(
                Name::from_ascii("attacker.example.net.").unwrap(),
                300,
                RData::A(A(Ipv4Addr::new(6, 6, 6, 6))),
            ));
            udp.send_to(&evil.to_vec().unwrap(), peer).await.unwrap();
        });

        let mut cfg = crate::config::Config::default();
        cfg.dns.upstreams = vec![upstream];
        cfg.dns.upstream_timeout_ms = 400;
        let resolver = test_resolver(&cfg);

        let req = request_msg("victim.example.com.", RecordType::A, 0x1111);
        let wire = req.to_vec().unwrap();
        let err = resolver
            .forward(&wire, &req)
            .await
            .expect_err("a mismatched question must not be accepted");
        assert!(
            format!("{err:#}").contains("different question"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn a_client_without_edns_still_gets_a_large_answer_via_tcp() {
        // No OPT means a 512-byte ceiling upstream, so a big answer must come
        // back through the TC path rather than being lost.
        let udp = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let upstream: SocketAddr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(upstream).await.unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let req = Message::from_vec(&buf[..n]).unwrap();
            udp.send_to(&reply_for(&req, 0, true).to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut s, _) = tcp.accept().await.unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).await.unwrap();
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut body).await.unwrap();
            let req = Message::from_vec(&body).unwrap();
            let full = reply_for(&req, 30, false).to_vec().unwrap();
            s.write_all(&(full.len() as u16).to_be_bytes())
                .await
                .unwrap();
            s.write_all(&full).await.unwrap();
        });

        let mut cfg = crate::config::Config::default();
        cfg.dns.upstreams = vec![upstream];
        let resolver = test_resolver(&cfg);

        let req = request_msg("nedns.example.com.", RecordType::A, 0x2222);
        assert!(req.edns.is_none(), "fixture must have no OPT");
        let raw = resolver
            .forward(&req.to_vec().unwrap(), &req)
            .await
            .unwrap();
        assert_eq!(Message::from_vec(&raw).unwrap().answers.len(), 30);
    }

    #[test]
    fn an_oversized_client_edns_is_clamped_before_going_upstream() {
        // A client claiming 64 KiB must not dictate how much we buffer.
        let mut req = request_msg("example.com.", RecordType::A, 7);
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(65535);
        req.set_edns(edns);

        let original = req.to_vec().unwrap();
        let clamped = clamp_upstream_payload(&original, &req, 1232);
        let sent = Message::from_vec(&clamped).unwrap();
        assert_eq!(sent.max_payload(), 1232);
    }

    #[test]
    fn a_request_already_within_the_limit_is_forwarded_byte_for_byte() {
        let mut req = request_msg("example.com.", RecordType::A, 9);
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(512);
        req.set_edns(edns);
        let original = req.to_vec().unwrap();
        assert_eq!(
            clamp_upstream_payload(&original, &req, 1232),
            original,
            "no re-encode when no clamping is needed"
        );
    }

    #[tokio::test]
    async fn udp_saturation_sheds_work_instead_of_queueing_it() {
        // Point at a black-hole upstream so every request stays in flight,
        // then send far more queries than the limit allows. The property
        // under test is that the excess is *dropped*, not accumulated.
        let blackhole = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let upstream = blackhole.local_addr().unwrap();
        // Never reply.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let _ = blackhole.recv_from(&mut buf).await;
            }
        });

        let mut cfg = crate::config::Config::default();
        cfg.dns.listen = "127.0.0.1:0".parse().unwrap();
        cfg.dns.upstreams = vec![upstream];
        cfg.dns.max_udp_in_flight = 4;
        cfg.dns.upstream_timeout_ms = 30_000;
        cfg.dns.request_timeout_ms = 30_000;
        cfg.dns.cache = false;

        let resolver = Arc::new(test_resolver(&cfg));
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = sock.local_addr().unwrap();

        // A trimmed copy of the serve_udp accept loop: same permit discipline.
        let in_flight = Arc::new(tokio::sync::Semaphore::new(resolver.max_udp_in_flight()));
        let spawned = Arc::new(AtomicU64::new(0));
        {
            let (sock, resolver, in_flight, spawned) = (
                Arc::clone(&sock),
                Arc::clone(&resolver),
                Arc::clone(&in_flight),
                Arc::clone(&spawned),
            );
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((len, peer)) = sock.recv_from(&mut buf).await else {
                        continue;
                    };
                    let Ok(permit) = Arc::clone(&in_flight).try_acquire_owned() else {
                        resolver.note_udp_overload();
                        continue;
                    };
                    let request = buf[..len].to_vec();
                    let resolver = Arc::clone(&resolver);
                    spawned.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = resolver.handle(&request, peer).await;
                    });
                }
            });
        }

        let client = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        for i in 0..60u16 {
            let req = request_msg("stall.example.com.", RecordType::A, i);
            client
                .send_to(&req.to_vec().unwrap(), server_addr)
                .await
                .unwrap();
            // Let the server loop run between sends.
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let started = spawned.load(Ordering::Relaxed);
        let dropped = resolver.stats.udp_overload_drops.load(Ordering::Relaxed);
        assert!(
            started <= cfg.dns.max_udp_in_flight as u64,
            "never more concurrent work than the limit: {started} started, limit {}",
            cfg.dns.max_udp_in_flight
        );
        assert!(
            dropped > 0,
            "the excess must be shed and counted, not silently queued"
        );
        assert_eq!(
            in_flight.available_permits(),
            0,
            "all permits are held by the stalled requests"
        );
    }

    #[tokio::test]
    async fn a_permit_is_released_when_the_request_finishes() {
        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        {
            let permit = Arc::clone(&sem).try_acquire_owned().unwrap();
            let h = tokio::spawn(async move {
                let _permit = permit;
                tokio::time::sleep(Duration::from_millis(10)).await;
            });
            assert_eq!(sem.available_permits(), 0, "held for the whole request");
            h.await.unwrap();
        }
        assert_eq!(sem.available_permits(), 1, "released on completion");
    }

    #[tokio::test]
    async fn a_request_that_outlives_its_budget_gets_servfail() {
        let blackhole = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let upstream = blackhole.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            loop {
                let _ = blackhole.recv_from(&mut buf).await;
            }
        });

        let mut cfg = crate::config::Config::default();
        cfg.dns.upstreams = vec![upstream];
        // Upstream would wait far longer than the end-to-end budget allows.
        cfg.dns.upstream_timeout_ms = 30_000;
        cfg.dns.request_timeout_ms = 150;
        cfg.dns.cache = false;
        let resolver = test_resolver(&cfg);

        let req = request_msg("slow.example.com.", RecordType::A, 0x77);
        let peer: SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let raw = resolver
            .handle(&req.to_vec().unwrap(), peer)
            .await
            .expect("a timeout must still answer");

        let resp = Message::from_vec(&raw).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(resp.metadata.id, 0x77, "answer must match the request");
        assert_eq!(resolver.stats.request_timeouts.load(Ordering::Relaxed), 1);
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
        let out = fit_udp(&request, bytes.clone(), 4096).expect("should fit");
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

        let out = fit_udp(&request, bytes, 4096).expect("should produce a stub");
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

        let resp = base_response(&req, 4096);
        assert!(resp.edns.is_some(), "OPT must be echoed per RFC 6891");
        assert_eq!(resp.max_payload(), 4096);
    }
}
