//! HTTP API and dashboard.
//!
//! All database work happens on the blocking pool: rusqlite calls are
//! synchronous, and holding the connection mutex inside an async task would
//! stall the executor that is also answering DNS.

use crate::blocklist::{self, Blocklist};
use crate::config::Config;
use crate::db::{self, ReadHandle};
use crate::dns::Resolver;
use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub db: ReadHandle,
    pub cfg: Arc<Config>,
    pub blocklist: Arc<RwLock<Blocklist>>,
    pub resolver: Arc<Resolver>,
    pub started: std::time::Instant,
    pub list_health: blocklist::HealthMap,
    pub refresh_lock: blocklist::RefreshLock,
}

/// An API failure, carrying the status the client should see.
///
/// Unexpected errors become a bare 500: the detail goes to the log, not to the
/// response, so internal paths and error chains are never exposed over HTTP.
struct ApiError {
    status: StatusCode,
    /// Safe to show a client. `None` means "log it, tell them nothing".
    public: Option<String>,
    internal: Option<anyhow::Error>,
}

impl ApiError {
    fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            public: Some(msg.into()),
            internal: None,
        }
    }

    fn bad_gateway(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            public: Some(msg.into()),
            internal: None,
        }
    }

    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            public: Some(msg.into()),
            internal: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(e) = &self.internal {
            tracing::error!("API error: {e:#}");
        }
        let body = self.public.unwrap_or_else(|| "internal error".to_string());
        (self.status, Json(json!({ "error": body }))).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            public: None,
            internal: Some(e.into()),
        }
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

/// Run a blocking database read without blocking the async runtime.
async fn with_db<T, F>(state: &AppState, f: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&rusqlite::Connection) -> Result<T> + Send + 'static,
{
    let db = Arc::clone(&state.db);
    let out = tokio::task::spawn_blocking(move || {
        let conn = db
            .lock()
            .map_err(|_| anyhow::anyhow!("database mutex poisoned"))?;
        f(&conn)
    })
    .await??;
    Ok(out)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/favicon.svg", get(favicon))
        .route("/api/summary", get(summary))
        .route("/api/queries", get(queries))
        .route("/api/top-domains", get(top_domains))
        .route("/api/top-blocked", get(top_blocked))
        .route("/api/top-clients", get(top_clients))
        .route("/api/query-types", get(query_types))
        .route("/api/timeseries", get(timeseries))
        .route("/api/devices", get(devices))
        .route("/api/interfaces", get(interfaces))
        .route("/api/status", get(status))
        .route("/api/deny", post(add_deny).delete(remove_deny))
        .route("/api/allow", post(add_allow).delete(remove_allow))
        .route("/api/reload", post(reload))
        .route("/api/flush-cache", post(flush_cache))
        .with_state(state)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(include_str!("web/index.html")),
    )
}

/// A tiny inline icon, so the browser does not 404 looking for one.
async fn favicon() -> impl IntoResponse {
    const SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" rx="7" fill="#1a1a19"/>
<circle cx="16" cy="16" r="4" fill="#3987e5"/>
<path d="M16 3a13 13 0 0 1 13 13" stroke="#e66767" stroke-width="3" fill="none"/>
<path d="M16 29A13 13 0 0 1 3 16" stroke="#3987e5" stroke-width="3" fill="none"/>
</svg>"##;
    ([(header::CONTENT_TYPE, "image/svg+xml")], SVG)
}

async fn summary(State(state): State<AppState>) -> ApiResult<Json<db::Summary>> {
    Ok(Json(with_db(&state, db::summary).await?))
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    limit: Option<u32>,
    offset: Option<u32>,
    search: Option<String>,
    client: Option<String>,
    status: Option<String>,
}

async fn queries(
    State(state): State<AppState>,
    Query(p): Query<QueryParams>,
) -> ApiResult<Json<Vec<db::QueryRow>>> {
    let filter = db::QueryFilter {
        limit: p.limit.unwrap_or(100).clamp(1, 1000),
        offset: p.offset.unwrap_or(0),
        // Empty strings arrive from cleared form fields; treat them as absent.
        search: p.search.filter(|s| !s.trim().is_empty()),
        client: p.client.filter(|s| !s.trim().is_empty()),
        status: p.status.filter(|s| !s.trim().is_empty()),
    };
    Ok(Json(
        with_db(&state, move |c| db::recent_queries(c, &filter)).await?,
    ))
}

#[derive(Debug, Deserialize)]
struct RangeParams {
    hours: Option<i64>,
    limit: Option<u32>,
    minutes: Option<i64>,
}

async fn top_domains(
    State(state): State<AppState>,
    Query(p): Query<RangeParams>,
) -> ApiResult<Json<Vec<db::Counted>>> {
    let (h, l) = (p.hours.unwrap_or(24), p.limit.unwrap_or(15));
    Ok(Json(
        with_db(&state, move |c| db::top_domains(c, h, l, false)).await?,
    ))
}

async fn top_blocked(
    State(state): State<AppState>,
    Query(p): Query<RangeParams>,
) -> ApiResult<Json<Vec<db::Counted>>> {
    let (h, l) = (p.hours.unwrap_or(24), p.limit.unwrap_or(15));
    Ok(Json(
        with_db(&state, move |c| db::top_domains(c, h, l, true)).await?,
    ))
}

async fn top_clients(
    State(state): State<AppState>,
    Query(p): Query<RangeParams>,
) -> ApiResult<Json<Vec<db::Counted>>> {
    let (h, l) = (p.hours.unwrap_or(24), p.limit.unwrap_or(15));
    Ok(Json(
        with_db(&state, move |c| db::top_clients(c, h, l)).await?,
    ))
}

async fn query_types(
    State(state): State<AppState>,
    Query(p): Query<RangeParams>,
) -> ApiResult<Json<Vec<db::Counted>>> {
    let h = p.hours.unwrap_or(24);
    Ok(Json(with_db(&state, move |c| db::query_types(c, h)).await?))
}

async fn timeseries(
    State(state): State<AppState>,
    Query(p): Query<RangeParams>,
) -> ApiResult<Json<Vec<db::Bucket>>> {
    let hours = p.hours.unwrap_or(24).clamp(1, 24 * 30);
    // Aim for roughly 120 points regardless of the window.
    let bucket = ((hours * 3600) / 120).max(60);
    Ok(Json(
        with_db(&state, move |c| db::timeseries(c, hours, bucket)).await?,
    ))
}

async fn devices(State(state): State<AppState>) -> ApiResult<Json<Vec<db::DeviceRow>>> {
    Ok(Json(with_db(&state, db::devices).await?))
}

async fn interfaces(
    State(state): State<AppState>,
    Query(p): Query<RangeParams>,
) -> ApiResult<Json<Vec<db::IfaceRow>>> {
    let minutes = p.minutes.unwrap_or(30).clamp(1, 1440);
    Ok(Json(
        with_db(&state, move |c| db::iface_series(c, minutes)).await?,
    ))
}

#[derive(Debug, Serialize)]
struct Status {
    version: &'static str,
    uptime_secs: u64,
    dns_listen: String,
    upstreams: Vec<String>,
    blocking_enabled: bool,
    blocking_mode: String,
    blocked_domains: usize,
    blocklist_sources: Vec<blocklist::SourceStat>,
    /// Per-source download health, so a silently stale list is visible.
    blocklist_health: Vec<blocklist::SourceHealth>,
    cache_entries: usize,
    queries_total: u64,
    queries_blocked: u64,
    cache_hits: u64,
    upstream_errors: u64,
    queries_denied: u64,
    /// Saturation signals: non-zero means the Pi shed work.
    udp_overload_drops: u64,
    tcp_rejections: u64,
    request_timeouts: u64,
    max_udp_in_flight: usize,
    max_tcp_connections: usize,
    allow_from: Vec<String>,
    system: crate::netinfo::SystemInfo,
    gateway: Option<String>,
    lan_subnet: Option<String>,
    interfaces: Vec<IfaceStatus>,
    latency: Vec<LatencyStatus>,
}

#[derive(Debug, Serialize)]
struct IfaceStatus {
    iface: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

#[derive(Debug, Serialize)]
struct LatencyStatus {
    target: String,
    ms: f64,
    ts: i64,
}

async fn status(State(state): State<AppState>) -> ApiResult<Json<Status>> {
    let latency = with_db(&state, db::latest_latency).await?;
    let route = crate::netinfo::default_route();
    let lan = route
        .as_ref()
        .and_then(|r| crate::netinfo::lan_subnet(&r.iface));

    let (blocked_domains, sources) = match state.blocklist.read() {
        Ok(bl) => (bl.len(), bl.sources.clone()),
        Err(_) => (0, Vec::new()),
    };

    let interfaces = crate::netinfo::iface_counters()
        .unwrap_or_default()
        .into_iter()
        .map(|c| IfaceStatus {
            iface: c.iface,
            rx_bytes: c.rx_bytes,
            tx_bytes: c.tx_bytes,
            rx_packets: c.rx_packets,
            tx_packets: c.tx_packets,
            rx_errors: c.rx_errors,
            tx_errors: c.tx_errors,
            rx_dropped: c.rx_dropped,
            tx_dropped: c.tx_dropped,
        })
        .collect();

    Ok(Json(Status {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started.elapsed().as_secs(),
        dns_listen: state.cfg.dns.listen.to_string(),
        upstreams: state
            .cfg
            .dns
            .upstreams
            .iter()
            .map(|u| u.to_string())
            .collect(),
        blocking_enabled: state.cfg.blocking.enabled,
        blocking_mode: state.cfg.blocking.mode.clone(),
        blocked_domains,
        blocklist_sources: sources,
        blocklist_health: state
            .list_health
            .read()
            .map(|h| h.clone())
            .unwrap_or_default(),
        cache_entries: state.resolver.cache_len(),
        queries_total: state.resolver.stats.total.load(Ordering::Relaxed),
        queries_blocked: state.resolver.stats.blocked.load(Ordering::Relaxed),
        cache_hits: state.resolver.stats.cache_hits.load(Ordering::Relaxed),
        upstream_errors: state.resolver.stats.upstream_errors.load(Ordering::Relaxed),
        queries_denied: state.resolver.stats.denied.load(Ordering::Relaxed),
        udp_overload_drops: state
            .resolver
            .stats
            .udp_overload_drops
            .load(Ordering::Relaxed),
        tcp_rejections: state.resolver.stats.tcp_rejections.load(Ordering::Relaxed),
        request_timeouts: state
            .resolver
            .stats
            .request_timeouts
            .load(Ordering::Relaxed),
        max_udp_in_flight: state.cfg.dns.max_udp_in_flight,
        max_tcp_connections: state.cfg.dns.max_tcp_connections,
        allow_from: state.cfg.dns.allow_from.clone(),
        system: crate::netinfo::system_info(),
        gateway: route.map(|r| format!("{} via {}", r.gateway, r.iface)),
        lan_subnet: lan.map(|s| s.to_string()),
        interfaces,
        latency: latency
            .into_iter()
            .map(|(target, ms, ts)| LatencyStatus { target, ms, ts })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
struct DomainBody {
    domain: String,
}

/// Rebuild the matcher from disk. Called after any list edit.
/// Rebuild the matcher from disk.
///
/// Parsing ~100k domains takes long enough that doing it inline would stall
/// the executor that is also answering DNS for the whole house — clicking
/// "Block" must not pause everyone's browsing.
async fn rebuild(state: &AppState) -> ApiResult<usize> {
    let cfg = Arc::clone(&state.cfg);
    let fresh = tokio::task::spawn_blocking(move || blocklist::build(&cfg)).await?;
    let len = fresh.len();
    if let Ok(mut bl) = state.blocklist.write() {
        *bl = fresh;
    }
    // A newly blocked domain may be sitting in the cache with a real answer.
    state.resolver.flush_cache();
    Ok(len)
}

async fn add_deny(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> ApiResult<Json<serde_json::Value>> {
    // A malformed domain is the caller's mistake, not ours: 400, not 500.
    if !blocklist::is_valid_domain(&body.domain) {
        return Err(ApiError::bad_request(format!(
            "{:?} is not a valid domain",
            body.domain
        )));
    }
    blocklist::append_manual(&state.cfg.manual_deny_path(), &body.domain)?;
    let n = rebuild(&state).await?;
    Ok(Json(json!({ "ok": true, "blocked_domains": n })))
}

async fn remove_deny(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> ApiResult<Json<serde_json::Value>> {
    // A malformed domain is the caller's mistake, not ours: 400, not 500.
    if !blocklist::is_valid_domain(&body.domain) {
        return Err(ApiError::bad_request(format!(
            "{:?} is not a valid domain",
            body.domain
        )));
    }
    blocklist::remove_manual(&state.cfg.manual_deny_path(), &body.domain)?;
    let n = rebuild(&state).await?;
    Ok(Json(json!({ "ok": true, "blocked_domains": n })))
}

async fn add_allow(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> ApiResult<Json<serde_json::Value>> {
    // A malformed domain is the caller's mistake, not ours: 400, not 500.
    if !blocklist::is_valid_domain(&body.domain) {
        return Err(ApiError::bad_request(format!(
            "{:?} is not a valid domain",
            body.domain
        )));
    }
    blocklist::append_manual(&state.cfg.manual_allow_path(), &body.domain)?;
    let n = rebuild(&state).await?;
    Ok(Json(json!({ "ok": true, "blocked_domains": n })))
}

async fn remove_allow(
    State(state): State<AppState>,
    Json(body): Json<DomainBody>,
) -> ApiResult<Json<serde_json::Value>> {
    // A malformed domain is the caller's mistake, not ours: 400, not 500.
    if !blocklist::is_valid_domain(&body.domain) {
        return Err(ApiError::bad_request(format!(
            "{:?} is not a valid domain",
            body.domain
        )));
    }
    blocklist::remove_manual(&state.cfg.manual_allow_path(), &body.domain)?;
    let n = rebuild(&state).await?;
    Ok(Json(json!({ "ok": true, "blocked_domains": n })))
}

async fn reload(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    // One refresh at a time: a manual reload racing the scheduled one would
    // have both writing the same destination files.
    let Ok(_guard) = state.refresh_lock.try_lock() else {
        return Err(ApiError::conflict("a blocklist refresh is already running"));
    };

    let cfg = Arc::clone(&state.cfg);
    let outcome = blocklist::refresh_sources(&cfg, &state.list_health).await;

    // Every source failed: say so instead of reporting a cheerful success the
    // operator would have no reason to doubt. Cached lists are untouched, so
    // filtering keeps working off whatever we already had.
    if outcome.total_failure() {
        let detail = outcome
            .failures
            .iter()
            .map(|(url, why)| format!("{url}: {why}"))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ApiError::bad_gateway(format!(
            "all {} blocklist sources failed, keeping the cached copies ({detail})",
            outcome.attempted
        )));
    }

    let n = rebuild(&state).await?;
    Ok(Json(json!({
        "ok": true,
        "blocked_domains": n,
        "sources_attempted": outcome.attempted,
        "sources_succeeded": outcome.succeeded,
        "failures": outcome
            .failures
            .iter()
            .map(|(url, why)| json!({ "source": url, "error": why }))
            .collect::<Vec<_>>(),
    })))
}

async fn flush_cache(State(state): State<AppState>) -> Json<serde_json::Value> {
    state.resolver.flush_cache();
    Json(json!({ "ok": true }))
}

pub async fn serve(state: AppState, listen: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("dashboard listening on http://{listen}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
