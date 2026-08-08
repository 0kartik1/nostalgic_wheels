//! SQLite storage.
//!
//! Two connections, both in WAL mode: one owned by a dedicated writer task
//! that batches inserts (so the DNS hot path never touches the disk or waits
//! on a lock), and one shared by the HTTP API for reads. WAL lets the reader
//! work while the writer commits.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What happened to a DNS query. Stored as a short string for readability
/// when poking at the database by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryStatus {
    Forwarded,
    Cached,
    Blocked,
    NxDomain,
    ServFail,
    Refused,
}

impl QueryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Cached => "cached",
            Self::Blocked => "blocked",
            Self::NxDomain => "nxdomain",
            Self::ServFail => "servfail",
            Self::Refused => "refused",
        }
    }
}

/// One logged DNS query, handed from the resolver to the writer task.
#[derive(Debug, Clone)]
pub struct QueryEvent {
    pub ts: i64,
    pub client_ip: String,
    pub domain: String,
    pub qtype: String,
    pub status: QueryStatus,
    /// Time spent talking to upstream, if we did.
    pub elapsed_ms: Option<u32>,
    /// Comma-joined answer records, truncated. Useful for spotting CDNs.
    pub answer: Option<String>,
    pub blocklist: Option<String>,
}

/// Interface throughput sample (already converted to a delta by the sampler).
#[derive(Debug, Clone)]
pub struct IfaceSample {
    pub ts: i64,
    pub iface: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_bps: i64,
    pub tx_bps: i64,
}

#[derive(Debug, Clone)]
pub enum WriteOp {
    Query(QueryEvent),
    Iface(IfaceSample),
    Latency {
        ts: i64,
        target: String,
        ms: f64,
    },
    /// Upsert a device. `None` fields leave the existing value alone.
    Device {
        mac: String,
        ip: Option<String>,
        hostname: Option<String>,
        vendor: Option<String>,
        randomized: bool,
        ts: i64,
    },
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS queries (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    client_ip TEXT    NOT NULL,
    domain    TEXT    NOT NULL,
    qtype     TEXT    NOT NULL,
    status    TEXT    NOT NULL,
    elapsed_ms INTEGER,
    answer    TEXT,
    blocklist TEXT
);
CREATE INDEX IF NOT EXISTS idx_queries_ts     ON queries(ts DESC);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain, ts DESC);
CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_queries_status ON queries(status, ts DESC);

CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,
    hostname   TEXT,
    vendor     TEXT,
    randomized INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS iface_samples (
    ts       INTEGER NOT NULL,
    iface    TEXT    NOT NULL,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    rx_bps   INTEGER NOT NULL,
    tx_bps   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iface_ts ON iface_samples(ts DESC);

CREATE TABLE IF NOT EXISTS latency (
    ts     INTEGER NOT NULL,
    target TEXT    NOT NULL,
    ms     REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_latency_ts ON latency(ts DESC);
"#;

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let conn =
        Connection::open(path).with_context(|| format!("opening database {}", path.display()))?;
    conn.execute_batch(SCHEMA).context("applying schema")?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

/// Handle the resolver and samplers use to record data. Cloneable and cheap;
/// sends never block the caller (bounded channel, drops under extreme load
/// rather than stalling DNS).
#[derive(Debug, Default)]
pub struct DropCounts {
    pub queries: AtomicU64,
    pub devices: AtomicU64,
    pub monitoring: AtomicU64,
}

#[derive(Clone)]
pub struct Writer {
    tx: mpsc::SyncSender<WriteOp>,
    dropped: Arc<DropCounts>,
}

impl Writer {
    pub fn send(&self, op: WriteOp) {
        // Which kind was lost matters: dropped queries mean an incomplete log,
        // dropped device rows only mean staler names. Counting them together
        // would hide the difference.
        let counter = match &op {
            WriteOp::Query(_) => &self.dropped.queries,
            WriteOp::Device { .. } => &self.dropped.devices,
            WriteOp::Iface(_) | WriteOp::Latency { .. } => &self.dropped.monitoring,
        };
        if self.tx.try_send(op).is_err() {
            // Either the queue is saturated or we are shutting down. Losing a
            // log line is strictly better than delaying a DNS answer.
            let n = counter.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                tracing::warn!(
                    "database write queue is full; events are being dropped. \
                     Counts are reported in /api/status."
                );
            }
        }
    }

    pub fn drop_counts(&self) -> Arc<DropCounts> {
        Arc::clone(&self.dropped)
    }
}

/// Spawn the writer thread. Returns the handle used to submit rows.
pub fn spawn_writer(conn: Connection, flush_interval: Duration, retention_days: u32) -> Writer {
    let (tx, rx) = mpsc::sync_channel::<WriteOp>(8192);
    let dropped = Arc::new(DropCounts::default());

    std::thread::Builder::new()
        .name("netwatch-db".into())
        .spawn(move || {
            let mut conn = conn;
            let mut pending: Vec<WriteOp> = Vec::with_capacity(512);
            let mut last_prune = std::time::Instant::now();

            // Block until there is at least one op, then keep draining for
            // `flush_interval` so a burst becomes a single transaction.
            while let Ok(first) = rx.recv() {
                pending.push(first);

                let deadline = std::time::Instant::now() + flush_interval;
                while pending.len() < 512 {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match rx.recv_timeout(remaining) {
                        Ok(op) => pending.push(op),
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }

                if let Err(e) = flush(&mut conn, &pending) {
                    tracing::error!("database flush failed: {e:#}");
                }
                pending.clear();

                if last_prune.elapsed() > Duration::from_secs(3600) {
                    last_prune = std::time::Instant::now();
                    if let Err(e) = prune(&conn, retention_days) {
                        tracing::error!("retention prune failed: {e:#}");
                    }
                }
            }
            tracing::info!("database writer stopped");
        })
        .expect("spawning db writer thread");

    Writer { tx, dropped }
}

fn flush(conn: &mut Connection, ops: &[WriteOp]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut q = tx.prepare_cached(
            "INSERT INTO queries (ts, client_ip, domain, qtype, status, elapsed_ms, answer, blocklist)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        let mut i = tx.prepare_cached(
            "INSERT INTO iface_samples (ts, iface, rx_bytes, tx_bytes, rx_bps, tx_bps)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let mut l =
            tx.prepare_cached("INSERT INTO latency (ts, target, ms) VALUES (?1, ?2, ?3)")?;
        // An IP belongs to one device at a time. When a device rotates its MAC
        // (privacy randomisation) or a DHCP lease moves, the previous holder
        // must give up the address — otherwise two `devices` rows share an IP
        // and every `LEFT JOIN devices ON ip = client_ip` duplicates its rows.
        let mut release_ip =
            tx.prepare_cached("UPDATE devices SET ip = NULL WHERE ip = ?1 AND mac != ?2")?;
        // COALESCE keeps a previously learned hostname/vendor when a later
        // sighting (say, a bare ARP entry) carries no name.
        let mut d = tx.prepare_cached(
            "INSERT INTO devices (mac, ip, hostname, vendor, randomized, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(mac) DO UPDATE SET
                ip        = COALESCE(excluded.ip, devices.ip),
                hostname  = COALESCE(excluded.hostname, devices.hostname),
                vendor    = COALESCE(excluded.vendor, devices.vendor),
                randomized= excluded.randomized,
                last_seen = excluded.last_seen",
        )?;

        for op in ops {
            match op {
                WriteOp::Query(e) => {
                    q.execute(params![
                        e.ts,
                        e.client_ip,
                        e.domain,
                        e.qtype,
                        e.status.as_str(),
                        e.elapsed_ms,
                        e.answer,
                        e.blocklist
                    ])?;
                }
                WriteOp::Iface(s) => {
                    i.execute(params![
                        s.ts, s.iface, s.rx_bytes, s.tx_bytes, s.rx_bps, s.tx_bps
                    ])?;
                }
                WriteOp::Latency { ts, target, ms } => {
                    l.execute(params![ts, target, ms])?;
                }
                WriteOp::Device {
                    mac,
                    ip,
                    hostname,
                    vendor,
                    randomized,
                    ts,
                } => {
                    if let Some(ip) = ip {
                        release_ip.execute(params![ip, mac])?;
                    }
                    d.execute(params![mac, ip, hostname, vendor, *randomized as i32, ts])?;
                }
            }
        }
    }
    tx.commit()?;
    Ok(())
}

fn prune(conn: &Connection, retention_days: u32) -> Result<()> {
    let cutoff = now() - (retention_days as i64) * 86_400;
    let q = conn.execute("DELETE FROM queries WHERE ts < ?1", params![cutoff])?;
    // Throughput and latency samples are dense; keep a shorter window.
    let iface_cutoff = now() - 3 * 86_400;
    conn.execute(
        "DELETE FROM iface_samples WHERE ts < ?1",
        params![iface_cutoff],
    )?;
    conn.execute("DELETE FROM latency WHERE ts < ?1", params![iface_cutoff])?;
    if q > 0 {
        tracing::info!("pruned {q} query rows older than {retention_days}d");
    }
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Read side, used by the HTTP API.
// ---------------------------------------------------------------------------

pub type ReadHandle = Arc<Mutex<Connection>>;

#[derive(Debug, Serialize)]
pub struct Summary {
    pub total_24h: i64,
    pub blocked_24h: i64,
    pub block_percent: f64,
    pub cached_24h: i64,
    pub clients_24h: i64,
    pub unique_domains_24h: i64,
    pub total_1h: i64,
    pub queries_per_min: f64,
    pub avg_upstream_ms: Option<f64>,
    pub device_count: i64,
    pub devices_active_24h: i64,
}

pub fn summary(conn: &Connection) -> Result<Summary> {
    let day = now() - 86_400;
    let hour = now() - 3_600;

    let (total, blocked, cached, clients, domains, avg_ms): (i64, i64, i64, i64, i64, Option<f64>) =
        conn.query_row(
            "SELECT COUNT(*),
                COALESCE(SUM(status = 'blocked'), 0),
                COALESCE(SUM(status = 'cached'), 0),
                COUNT(DISTINCT client_ip),
                COUNT(DISTINCT domain),
                AVG(elapsed_ms)
         FROM queries WHERE ts >= ?1",
            params![day],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )?;

    let total_1h: i64 = conn.query_row(
        "SELECT COUNT(*) FROM queries WHERE ts >= ?1",
        params![hour],
        |r| r.get(0),
    )?;

    let device_count: i64 = conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
    let devices_active: i64 = conn.query_row(
        "SELECT COUNT(*) FROM devices WHERE last_seen >= ?1",
        params![day],
        |r| r.get(0),
    )?;

    Ok(Summary {
        total_24h: total,
        blocked_24h: blocked,
        block_percent: if total > 0 {
            blocked as f64 * 100.0 / total as f64
        } else {
            0.0
        },
        cached_24h: cached,
        clients_24h: clients,
        unique_domains_24h: domains,
        total_1h,
        queries_per_min: total_1h as f64 / 60.0,
        avg_upstream_ms: avg_ms,
        device_count,
        devices_active_24h: devices_active,
    })
}

#[derive(Debug, Serialize)]
pub struct QueryRow {
    pub ts: i64,
    pub client_ip: String,
    pub client_name: Option<String>,
    pub domain: String,
    pub qtype: String,
    pub status: String,
    pub elapsed_ms: Option<u32>,
    pub answer: Option<String>,
    pub blocklist: Option<String>,
}

#[derive(Debug, Default)]
pub struct QueryFilter {
    pub limit: u32,
    pub offset: u32,
    pub search: Option<String>,
    pub client: Option<String>,
    pub status: Option<String>,
}

pub fn recent_queries(conn: &Connection, f: &QueryFilter) -> Result<Vec<QueryRow>> {
    // Built with placeholders only; user text never reaches the SQL string.
    let mut sql = String::from(
        "SELECT q.ts, q.client_ip, d.hostname, q.domain, q.qtype, q.status,
                q.elapsed_ms, q.answer, q.blocklist
         FROM queries q
         LEFT JOIN devices d ON d.ip = q.client_ip
         WHERE 1=1",
    );
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(s) = &f.search {
        sql.push_str(" AND q.domain LIKE ?");
        binds.push(Box::new(format!("%{s}%")));
    }
    if let Some(c) = &f.client {
        sql.push_str(" AND q.client_ip = ?");
        binds.push(Box::new(c.clone()));
    }
    if let Some(s) = &f.status {
        sql.push_str(" AND q.status = ?");
        binds.push(Box::new(s.clone()));
    }
    sql.push_str(" ORDER BY q.ts DESC, q.id DESC LIMIT ? OFFSET ?");
    binds.push(Box::new(f.limit.clamp(1, 1000)));
    binds.push(Box::new(f.offset));

    let mut stmt = conn.prepare(&sql)?;
    let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(refs.as_slice(), |r| {
        Ok(QueryRow {
            ts: r.get(0)?,
            client_ip: r.get(1)?,
            client_name: r.get(2)?,
            domain: r.get(3)?,
            qtype: r.get(4)?,
            status: r.get(5)?,
            elapsed_ms: r.get(6)?,
            answer: r.get(7)?,
            blocklist: r.get(8)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[derive(Debug, Serialize)]
pub struct Counted {
    pub label: String,
    pub sublabel: Option<String>,
    pub count: i64,
}

pub fn top_domains(
    conn: &Connection,
    hours: i64,
    limit: u32,
    blocked: bool,
) -> Result<Vec<Counted>> {
    let since = now() - hours.max(1) * 3_600;
    let sql = if blocked {
        "SELECT domain, blocklist, COUNT(*) c FROM queries
         WHERE ts >= ?1 AND status = 'blocked'
         GROUP BY domain ORDER BY c DESC LIMIT ?2"
    } else {
        "SELECT domain, NULL, COUNT(*) c FROM queries
         WHERE ts >= ?1 AND status != 'blocked'
         GROUP BY domain ORDER BY c DESC LIMIT ?2"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![since, limit.clamp(1, 200)], |r| {
        Ok(Counted {
            label: r.get(0)?,
            sublabel: r.get(1)?,
            count: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn top_clients(conn: &Connection, hours: i64, limit: u32) -> Result<Vec<Counted>> {
    let since = now() - hours.max(1) * 3_600;
    let mut stmt = conn.prepare(
        "SELECT q.client_ip, COALESCE(d.hostname, d.vendor), COUNT(*) c
         FROM queries q LEFT JOIN devices d ON d.ip = q.client_ip
         WHERE q.ts >= ?1
         GROUP BY q.client_ip ORDER BY c DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![since, limit.clamp(1, 200)], |r| {
        Ok(Counted {
            label: r.get(0)?,
            sublabel: r.get(1)?,
            count: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn query_types(conn: &Connection, hours: i64) -> Result<Vec<Counted>> {
    let since = now() - hours.max(1) * 3_600;
    let mut stmt = conn.prepare(
        "SELECT qtype, NULL, COUNT(*) c FROM queries WHERE ts >= ?1
         GROUP BY qtype ORDER BY c DESC LIMIT 12",
    )?;
    let rows = stmt.query_map(params![since], |r| {
        Ok(Counted {
            label: r.get(0)?,
            sublabel: r.get(1)?,
            count: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[derive(Debug, Serialize)]
pub struct Bucket {
    pub ts: i64,
    pub allowed: i64,
    pub blocked: i64,
}

/// Query volume bucketed for the dashboard chart.
pub fn timeseries(conn: &Connection, hours: i64, bucket_secs: i64) -> Result<Vec<Bucket>> {
    let bucket = bucket_secs.max(60);
    let since = now() - hours.max(1) * 3_600;
    let mut stmt = conn.prepare(
        "SELECT (ts / ?2) * ?2 AS b,
                COALESCE(SUM(status != 'blocked'), 0),
                COALESCE(SUM(status  = 'blocked'), 0)
         FROM queries WHERE ts >= ?1
         GROUP BY b ORDER BY b",
    )?;
    let rows = stmt.query_map(params![since, bucket], |r| {
        Ok(Bucket {
            ts: r.get(0)?,
            allowed: r.get(1)?,
            blocked: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[derive(Debug, Serialize)]
pub struct DeviceRow {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub randomized: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub queries_24h: i64,
    pub blocked_24h: i64,
}

pub fn devices(conn: &Connection) -> Result<Vec<DeviceRow>> {
    let day = now() - 86_400;
    let mut stmt = conn.prepare(
        "SELECT d.mac, d.ip, d.hostname, d.vendor, d.randomized, d.first_seen, d.last_seen,
                COALESCE(q.n, 0), COALESCE(q.b, 0)
         FROM devices d
         LEFT JOIN (
             SELECT client_ip,
                    COUNT(*) n,
                    SUM(status = 'blocked') b
             FROM queries WHERE ts >= ?1 GROUP BY client_ip
         ) q ON q.client_ip = d.ip
         ORDER BY d.last_seen DESC",
    )?;
    let rows = stmt.query_map(params![day], |r| {
        Ok(DeviceRow {
            mac: r.get(0)?,
            ip: r.get(1)?,
            hostname: r.get(2)?,
            vendor: r.get(3)?,
            randomized: r.get::<_, i64>(4)? != 0,
            first_seen: r.get(5)?,
            last_seen: r.get(6)?,
            queries_24h: r.get(7)?,
            blocked_24h: r.get(8)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[derive(Debug, Serialize)]
pub struct IfaceRow {
    pub ts: i64,
    pub iface: String,
    pub rx_bps: i64,
    pub tx_bps: i64,
}

pub fn iface_series(conn: &Connection, minutes: i64) -> Result<Vec<IfaceRow>> {
    let since = now() - minutes.max(1) * 60;
    let mut stmt = conn.prepare(
        "SELECT ts, iface, rx_bps, tx_bps FROM iface_samples
         WHERE ts >= ?1 ORDER BY ts",
    )?;
    let rows = stmt.query_map(params![since], |r| {
        Ok(IfaceRow {
            ts: r.get(0)?,
            iface: r.get(1)?,
            rx_bps: r.get(2)?,
            tx_bps: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn latest_latency(conn: &Connection) -> Result<Vec<(String, f64, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT target, ms, ts FROM latency
         WHERE ts = (SELECT MAX(ts) FROM latency l2 WHERE l2.target = latency.target)
         GROUP BY target",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(mac: &str, ip: &str, host: &str) -> WriteOp {
        WriteOp::Device {
            mac: mac.to_string(),
            ip: Some(ip.to_string()),
            hostname: Some(host.to_string()),
            vendor: Some("Test".to_string()),
            randomized: false,
            ts: 1_000_000,
        }
    }

    fn query(ip: &str, domain: &str) -> WriteOp {
        WriteOp::Query(QueryEvent {
            ts: now(),
            client_ip: ip.to_string(),
            domain: domain.to_string(),
            qtype: "A".to_string(),
            status: QueryStatus::Forwarded,
            elapsed_ms: Some(5),
            answer: None,
            blocklist: None,
        })
    }

    #[test]
    fn an_ip_is_only_ever_held_by_one_device() {
        let mut conn = open(Path::new(":memory:")).unwrap();

        // A phone rotates its MAC and reappears on the same address.
        flush(
            &mut conn,
            &[device("aa:bb:cc:00:00:01", "192.168.1.50", "phone-old")],
        )
        .unwrap();
        flush(
            &mut conn,
            &[device("a2:bb:cc:00:00:02", "192.168.1.50", "phone-new")],
        )
        .unwrap();

        let holders: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE ip = '192.168.1.50'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(holders, 1, "only the current device may hold the IP");

        // The old row survives with its history, just without the address.
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(total, 2, "the previous device is retained, not deleted");
    }

    #[test]
    fn query_rows_are_not_duplicated_by_the_device_join() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        flush(
            &mut conn,
            &[device("aa:bb:cc:00:00:01", "192.168.1.50", "phone-old")],
        )
        .unwrap();
        flush(
            &mut conn,
            &[device("a2:bb:cc:00:00:02", "192.168.1.50", "phone-new")],
        )
        .unwrap();
        flush(&mut conn, &[query("192.168.1.50", "example.com")]).unwrap();

        let rows = recent_queries(
            &conn,
            &QueryFilter {
                limit: 100,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1, "one query must yield exactly one log row");
        assert_eq!(rows[0].client_name.as_deref(), Some("phone-new"));

        let clients = top_clients(&conn, 24, 10).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients[0].count, 1,
            "counts must not be inflated by the join"
        );
    }

    #[test]
    fn later_sightings_do_not_erase_a_known_hostname() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        flush(
            &mut conn,
            &[device("aa:bb:cc:00:00:01", "192.168.1.60", "kitchen-pi")],
        )
        .unwrap();

        // A bare ARP sighting carries no name or vendor.
        flush(
            &mut conn,
            &[WriteOp::Device {
                mac: "aa:bb:cc:00:00:01".to_string(),
                ip: Some("192.168.1.60".to_string()),
                hostname: None,
                vendor: None,
                randomized: false,
                ts: 2_000_000,
            }],
        )
        .unwrap();

        let (host, seen): (Option<String>, i64) = conn
            .query_row(
                "SELECT hostname, last_seen FROM devices WHERE mac = 'aa:bb:cc:00:00:01'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(host.as_deref(), Some("kitchen-pi"));
        assert_eq!(seen, 2_000_000, "last_seen still advances");
    }

    #[test]
    fn summary_counts_blocked_and_cached_separately() {
        let mut conn = open(Path::new(":memory:")).unwrap();
        let mut ops = vec![query("192.168.1.10", "example.com")];
        for status in [
            QueryStatus::Blocked,
            QueryStatus::Blocked,
            QueryStatus::Cached,
        ] {
            ops.push(WriteOp::Query(QueryEvent {
                ts: now(),
                client_ip: "192.168.1.11".to_string(),
                domain: "ads.example.com".to_string(),
                qtype: "A".to_string(),
                status,
                elapsed_ms: None,
                answer: None,
                blocklist: None,
            }));
        }
        flush(&mut conn, &ops).unwrap();

        let s = summary(&conn).unwrap();
        assert_eq!(s.total_24h, 4);
        assert_eq!(s.blocked_24h, 2);
        assert_eq!(s.cached_24h, 1);
        assert_eq!(s.clients_24h, 2);
        assert!((s.block_percent - 50.0).abs() < 0.01);
    }
}
