//! Blocklist loading and matching.
//!
//! Accepts both hosts-file format (`0.0.0.0 ads.example.com`) and plain
//! one-domain-per-line lists, which covers essentially every list people
//! use with Pi-hole. Entries starting with `*.` become suffix rules.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Index into [`Blocklist::sources`].
///
/// Storing the source as an index rather than an owned `String` per entry is
/// the difference between ~9 MB and ~200 KB of labels on a 100k-domain list:
/// every entry used to carry its own copy of the same list URL.
type SourceId = u16;

#[derive(Debug, Default)]
pub struct Blocklist {
    /// Exact domain matches -> which list it came from.
    exact: HashMap<String, SourceId>,
    /// `*.example.com` style rules, stored as the bare parent domain.
    wildcards: HashMap<String, SourceId>,
    /// Always allowed, overrides everything above.
    allow: HashSet<String>,
    allow_wildcards: HashSet<String>,
    /// The interning table: `SourceId` indexes into this.
    pub sources: Vec<SourceStat>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceStat {
    pub name: String,
    pub entries: usize,
}

impl Blocklist {
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }

    fn source_name(&self, id: SourceId) -> &str {
        self.sources
            .get(id as usize)
            .map_or("unknown", |s| s.name.as_str())
    }

    /// Intern a list name, returning its id.
    fn intern(&mut self, name: &str) -> SourceId {
        if let Some(i) = self.sources.iter().position(|s| s.name == name) {
            return i as SourceId;
        }
        // Practically unreachable — nobody configures 65k lists — but wrapping
        // silently would mislabel every entry, so clamp and say so.
        if self.sources.len() >= SourceId::MAX as usize {
            tracing::warn!("too many blocklist sources to label individually");
            return SourceId::MAX - 1;
        }
        self.sources.push(SourceStat {
            name: name.to_string(),
            entries: 0,
        });
        (self.sources.len() - 1) as SourceId
    }

    /// Returns the name of the list that blocked `domain`, or `None`.
    ///
    /// `domain` must already be lowercased with no trailing dot.
    pub fn lookup(&self, domain: &str) -> Option<&str> {
        if self.is_allowed(domain) {
            return None;
        }
        if let Some(&src) = self.exact.get(domain) {
            return Some(self.source_name(src));
        }
        // Walk up the labels: a.b.example.com checks b.example.com, example.com...
        let mut rest = domain;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if rest.is_empty() {
                break;
            }
            if let Some(&src) = self.wildcards.get(rest) {
                return Some(self.source_name(src));
            }
        }
        None
    }

    fn is_allowed(&self, domain: &str) -> bool {
        if self.allow.contains(domain) {
            return true;
        }
        let mut rest = domain;
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            if rest.is_empty() {
                break;
            }
            if self.allow_wildcards.contains(rest) {
                return true;
            }
        }
        false
    }

    fn add_block(&mut self, entry: &str, source: SourceId) {
        match normalize(entry) {
            Some(Entry::Exact(d)) => {
                self.exact.entry(d).or_insert(source);
            }
            Some(Entry::Wildcard(d)) => {
                self.wildcards.entry(d).or_insert(source);
            }
            None => {}
        }
    }

    fn add_allow(&mut self, entry: &str) {
        match normalize(entry) {
            Some(Entry::Exact(d)) => {
                self.allow.insert(d);
            }
            Some(Entry::Wildcard(d)) => {
                self.allow_wildcards.insert(d);
            }
            None => {}
        }
    }

    /// Parse a list file's contents, returning how many entries were added.
    ///
    /// Also registers `source_name` and accumulates its entry count, so callers
    /// never touch `sources` directly — doing so would desynchronise the
    /// interning table from the ids already stored against each domain.
    pub fn ingest(&mut self, contents: &str, source_name: &str, allow: bool) -> usize {
        let before = if allow {
            self.allow.len() + self.allow_wildcards.len()
        } else {
            self.len()
        };
        // Allow lists carry no attribution, so they get no source slot.
        let source_id = if allow { 0 } else { self.intern(source_name) };

        for raw in contents.lines() {
            // Strip comments (# and !, the latter used by Adblock-style lists).
            let line = raw.split(['#', '!']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            // hosts format: "0.0.0.0 domain [domain...]" or "127.0.0.1 domain".
            let mut fields = line.split_whitespace();
            let first = fields.next().unwrap_or("");
            let is_hosts_line =
                matches!(first, "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "0.0.0.0.0");

            if is_hosts_line {
                for domain in fields {
                    // "localhost" entries in hosts files are not ad domains.
                    if domain.eq_ignore_ascii_case("localhost")
                        || domain.eq_ignore_ascii_case("localhost.localdomain")
                        || domain.eq_ignore_ascii_case("broadcasthost")
                    {
                        continue;
                    }
                    if allow {
                        self.add_allow(domain);
                    } else {
                        self.add_block(domain, source_id);
                    }
                }
            } else if fields.next().is_none() {
                // Bare domain on its own line.
                if allow {
                    self.add_allow(first);
                } else {
                    self.add_block(first, source_id);
                }
            }
        }

        let after = if allow {
            self.allow.len() + self.allow_wildcards.len()
        } else {
            self.len()
        };
        let added = after.saturating_sub(before);
        if !allow && let Some(stat) = self.sources.get_mut(source_id as usize) {
            stat.entries += added;
        }
        added
    }

    pub fn ingest_file(&mut self, path: &Path, allow: bool) -> Result<usize> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading list {}", path.display()))?;
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());
        Ok(self.ingest(&contents, &name, allow))
    }
}

enum Entry {
    Exact(String),
    Wildcard(String),
}

/// Validate and canonicalise a list entry. Rejects anything that is not a
/// plausible domain so a malformed list cannot poison the matcher.
fn normalize(entry: &str) -> Option<Entry> {
    let e = entry.trim().trim_end_matches('.').to_ascii_lowercase();
    let (wildcard, domain) = match e.strip_prefix("*.") {
        Some(rest) => (true, rest.to_string()),
        None => (false, e),
    };

    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return None;
    }
    // Reject IP literals and anything with characters a hostname cannot have.
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }

    Some(if wildcard {
        Entry::Wildcard(domain)
    } else {
        Entry::Exact(domain)
    })
}

/// Per-source download health, kept across refreshes so the dashboard can
/// distinguish "never fetched" from "fetched yesterday, failing since".
#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceHealth {
    pub url: String,
    /// Unix seconds of the last attempt, successful or not.
    pub last_attempt: Option<i64>,
    pub last_success: Option<i64>,
    pub bytes: Option<u64>,
    /// One of: never_fetched, ok, stale, error.
    pub state: &'static str,
    /// Human-readable reason when `state` is not ok. Deliberately kept to the
    /// protocol-level cause — never a filesystem path or internal detail.
    pub error: Option<String>,
}

impl SourceHealth {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            last_attempt: None,
            last_success: None,
            bytes: None,
            state: "never_fetched",
            error: None,
        }
    }
}

/// Shared, mutable view of how each configured source is doing.
pub type HealthMap = Arc<RwLock<Vec<SourceHealth>>>;

pub fn new_health(cfg: &crate::config::Config) -> HealthMap {
    Arc::new(RwLock::new(
        cfg.blocking
            .sources
            .iter()
            .map(|u| SourceHealth::new(u))
            .collect(),
    ))
}

/// What a refresh actually achieved.
#[derive(Debug, Default)]
pub struct RefreshOutcome {
    pub attempted: usize,
    pub succeeded: usize,
    /// (url, reason) for each source that failed.
    pub failures: Vec<(String, String)>,
}

impl RefreshOutcome {
    /// True when we tried to fetch something and every single one failed.
    /// A refresh with nothing configured is not a failure.
    pub fn total_failure(&self) -> bool {
        self.attempted > 0 && self.succeeded == 0
    }
}

/// Cap on a single downloaded list. StevenBlack's unified list is ~3 MB; this
/// leaves generous headroom while stopping a hostile or misconfigured URL from
/// filling a Pi's SD card or its memory.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

/// Serialises refreshes. A manual /api/reload and the scheduled refresh must
/// not run at once: they would fight over the same destination files.
pub type RefreshLock = Arc<tokio::sync::Mutex<()>>;

pub fn new_refresh_lock() -> RefreshLock {
    Arc::new(tokio::sync::Mutex::new(()))
}

/// Download the configured remote lists into the on-disk cache.
///
/// A failing source leaves its previously cached copy untouched, so a network
/// blip degrades to "stale lists" rather than "no filtering". The caller gets
/// a structured outcome instead of a blanket Ok.
pub async fn refresh_sources(cfg: &crate::config::Config, health: &HealthMap) -> RefreshOutcome {
    let mut outcome = RefreshOutcome::default();

    let dir = cfg.blocking.state_dir.join("lists");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!("creating {}: {e}", dir.display());
        // Every source will fail for the same reason; report it once per source
        // so the dashboard shows why.
        for url in &cfg.blocking.sources {
            outcome.attempted += 1;
            outcome
                .failures
                .push((url.clone(), "list directory is not writable".to_string()));
        }
        return outcome;
    }

    // reqwest is built with `rustls-no-provider`, and its client builder
    // *panics* if no provider is installed. main() installs one, but relying
    // on caller ordering would turn a refactor into a crash inside a spawned
    // task, so make this module self-sufficient.
    ensure_crypto_provider();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(concat!("netwatch/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("building HTTP client: {e}");
            for url in &cfg.blocking.sources {
                outcome.attempted += 1;
                outcome
                    .failures
                    .push((url.clone(), "HTTP client unavailable".to_string()));
            }
            return outcome;
        }
    };

    for url in &cfg.blocking.sources {
        outcome.attempted += 1;
        let now = crate::db::now();
        set_health(health, url, |h| {
            h.last_attempt = Some(now);
        });

        match fetch_one(&client, url, &cfg.cached_list_path(url)).await {
            Ok(bytes) => {
                outcome.succeeded += 1;
                tracing::info!("downloaded blocklist {url} ({bytes} bytes)");
                set_health(health, url, |h| {
                    h.last_success = Some(now);
                    h.bytes = Some(bytes);
                    h.state = "ok";
                    h.error = None;
                });
            }
            Err(e) => {
                let reason = format!("{e:#}");
                tracing::error!("refreshing {url}: {reason}");
                outcome.failures.push((url.clone(), reason.clone()));
                set_health(health, url, |h| {
                    // A source that succeeded before is stale, not broken:
                    // filtering still works off the cached copy.
                    h.state = if h.last_success.is_some() {
                        "stale"
                    } else {
                        "error"
                    };
                    h.error = Some(reason);
                });
            }
        }
    }

    outcome
}

/// Install the ring crypto provider exactly once. Idempotent and cheap.
pub(crate) fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // An error here means someone else already installed one, which is
        // exactly the outcome we want.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn set_health(health: &HealthMap, url: &str, f: impl FnOnce(&mut SourceHealth)) {
    if let Ok(mut list) = health.write()
        && let Some(entry) = list.iter_mut().find(|h| h.url == url)
    {
        f(entry);
    }
}

/// Fetch one list to a temp file and rename it into place. Returns byte count.
async fn fetch_one(client: &reqwest::Client, url: &str, dest: &Path) -> Result<u64> {
    let resp = client.get(url).send().await.context("request failed")?;
    let status = resp.status();
    anyhow::ensure!(status.is_success(), "HTTP {status}");

    // Reject an over-large list before downloading it when the server is
    // honest enough to tell us up front.
    if let Some(len) = resp.content_length() {
        anyhow::ensure!(
            len <= MAX_LIST_BYTES,
            "list is {len} bytes, over the {MAX_LIST_BYTES} byte limit"
        );
    }

    // Unique temp name in the destination directory, so a rename is atomic
    // (same filesystem) and two concurrent refreshes cannot collide.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dest.with_extension(format!("tmp.{}.{seq}", std::process::id()));

    // Stream so the size cap applies even when Content-Length lied or was
    // absent, rather than buffering an unbounded body first.
    let mut resp = resp;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading body")? {
        anyhow::ensure!(
            body.len() as u64 + chunk.len() as u64 <= MAX_LIST_BYTES,
            "list exceeded the {MAX_LIST_BYTES} byte limit mid-download"
        );
        body.extend_from_slice(&chunk);
    }
    anyhow::ensure!(!body.is_empty(), "empty response body");

    let written = body.len() as u64;
    std::fs::write(&tmp, &body).context("writing temporary list")?;
    if let Err(e) = std::fs::rename(&tmp, dest) {
        // Do not leave the temp file behind on failure.
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context("replacing cached list"));
    }
    Ok(written)
}

/// Build the in-memory matcher from every configured file + cached download,
/// then layer the manual allow/deny lists on top.
pub fn build(cfg: &crate::config::Config) -> Blocklist {
    let mut bl = Blocklist::default();
    if !cfg.blocking.enabled {
        return bl;
    }

    for url in &cfg.blocking.sources {
        let path = cfg.cached_list_path(url);
        if !path.exists() {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                // `ingest` registers the source itself; pushing here too would
                // list it twice in the dashboard.
                bl.ingest(&contents, url, false);
            }
            Err(e) => tracing::error!("reading cached list {}: {e}", path.display()),
        }
    }

    for file in &cfg.blocking.files {
        if let Err(e) = bl.ingest_file(file, false) {
            tracing::error!("{e:#}");
        }
    }

    let deny = cfg.manual_deny_path();
    if deny.exists()
        && let Err(e) = bl.ingest_file(&deny, false)
    {
        tracing::error!("{e:#}");
    }

    let allow = cfg.manual_allow_path();
    if allow.exists()
        && let Err(e) = bl.ingest_file(&allow, true)
    {
        tracing::error!("{e:#}");
    }

    tracing::info!(
        "blocklist ready: {} domains from {} sources",
        bl.len(),
        bl.sources.len()
    );
    bl
}

/// Whether a string is a domain we are willing to add to a manual list.
/// Exposed so the API can reject bad input as a client error rather than
/// discovering it as a failure deep inside a write.
pub fn is_valid_domain(domain: &str) -> bool {
    normalize(domain).is_some()
}

/// Append a domain to one of the manual lists, ignoring duplicates.
pub fn append_manual(path: &Path, domain: &str) -> Result<()> {
    use std::io::Write;
    let domain = domain.trim().to_ascii_lowercase();
    anyhow::ensure!(
        normalize(&domain).is_some(),
        "{domain:?} is not a valid domain"
    );

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(existing) = std::fs::read_to_string(path)
        && existing.lines().any(|l| l.trim() == domain)
    {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{domain}")?;
    Ok(())
}

/// Remove a domain from one of the manual lists.
pub fn remove_manual(path: &Path, domain: &str) -> Result<()> {
    let domain = domain.trim().to_ascii_lowercase();
    let Ok(existing) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    let kept: Vec<&str> = existing.lines().filter(|l| l.trim() != domain).collect();
    std::fs::write(path, kept.join("\n") + "\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_and_bare_formats() {
        let mut bl = Blocklist::default();
        bl.ingest(
            "# comment\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.net\nbare.org\n0.0.0.0 localhost\n",
            "test",
            false,
        );
        assert_eq!(bl.lookup("ads.example.com"), Some("test"));
        assert_eq!(bl.lookup("tracker.net"), Some("test"));
        assert_eq!(bl.lookup("bare.org"), Some("test"));
        assert_eq!(bl.lookup("localhost"), None);
        assert_eq!(bl.lookup("example.com"), None);
    }

    #[test]
    fn wildcards_match_subdomains_only() {
        let mut bl = Blocklist::default();
        bl.ingest("*.doubleclick.net\n", "test", false);
        assert_eq!(bl.lookup("stats.g.doubleclick.net"), Some("test"));
        assert_eq!(bl.lookup("ad.doubleclick.net"), Some("test"));
        // The apex itself is not covered by a `*.` rule.
        assert_eq!(bl.lookup("doubleclick.net"), None);
    }

    #[test]
    fn allowlist_overrides_blocklist() {
        let mut bl = Blocklist::default();
        bl.ingest("*.example.com\nads.example.com\n", "test", false);
        bl.ingest("ads.example.com\n", "allow", true);
        assert_eq!(bl.lookup("ads.example.com"), None);
        assert_eq!(bl.lookup("other.example.com"), Some("test"));
    }

    #[test]
    fn rejects_junk_entries() {
        assert!(normalize("").is_none());
        assert!(normalize("nodot").is_none());
        assert!(normalize("1.2.3.4").is_none());
        assert!(normalize("has space.com").is_none());
        assert!(normalize("bad..com").is_none());
        assert!(normalize("ok.example.com").is_some());
    }

    #[test]
    fn attributes_each_domain_to_the_right_list() {
        let mut bl = Blocklist::default();
        bl.ingest("ads.one.com\n", "list-a", false);
        bl.ingest("ads.two.com\n", "list-b", false);
        bl.ingest("*.three.com\n", "list-c", false);

        assert_eq!(bl.lookup("ads.one.com"), Some("list-a"));
        assert_eq!(bl.lookup("ads.two.com"), Some("list-b"));
        assert_eq!(bl.lookup("x.three.com"), Some("list-c"));
        assert_eq!(bl.sources.len(), 3, "one slot per distinct list");
    }

    #[test]
    fn a_list_ingested_twice_gets_one_source_slot() {
        let mut bl = Blocklist::default();
        bl.ingest("a.example.com\n", "same-list", false);
        bl.ingest("b.example.com\n", "same-list", false);

        assert_eq!(
            bl.sources.len(),
            1,
            "the source must be interned, not duplicated"
        );
        assert_eq!(bl.sources[0].entries, 2, "counts accumulate across calls");
        assert_eq!(bl.lookup("a.example.com"), Some("same-list"));
        assert_eq!(bl.lookup("b.example.com"), Some("same-list"));
    }

    #[test]
    fn allow_lists_do_not_create_source_slots() {
        let mut bl = Blocklist::default();
        bl.ingest("ads.example.com\n", "blocklist", false);
        bl.ingest("ads.example.com\n", "allow.list", true);
        assert_eq!(bl.sources.len(), 1, "only the blocklist is a source");
        assert_eq!(bl.sources[0].name, "blocklist");
    }

    #[test]
    fn first_list_to_claim_a_domain_keeps_the_attribution() {
        let mut bl = Blocklist::default();
        bl.ingest("dupe.example.com\n", "first", false);
        bl.ingest("dupe.example.com\n", "second", false);
        assert_eq!(bl.lookup("dupe.example.com"), Some("first"));
    }

    #[test]
    fn strips_trailing_dot_and_uppercase() {
        let mut bl = Blocklist::default();
        bl.ingest("ADS.Example.COM.\n", "test", false);
        assert_eq!(bl.lookup("ads.example.com"), Some("test"));
    }
}

#[cfg(test)]
mod refresh_tests {
    use super::*;

    fn cfg_with(sources: Vec<String>, dir: &Path) -> crate::config::Config {
        let mut c = crate::config::Config::default();
        c.blocking.sources = sources;
        c.blocking.state_dir = dir.to_path_buf();
        c
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "netwatch-test-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(d.join("lists")).unwrap();
        d
    }

    #[tokio::test]
    async fn every_source_failing_is_reported_as_a_total_failure() {
        let dir = tmpdir("allfail");
        // Port 1 on loopback refuses instantly: a deterministic failure that
        // needs no network.
        let cfg = cfg_with(vec!["http://127.0.0.1:1/list.txt".to_string()], &dir);
        let health = new_health(&cfg);

        let outcome = refresh_sources(&cfg, &health).await;
        assert_eq!(outcome.attempted, 1);
        assert_eq!(outcome.succeeded, 0);
        assert!(
            outcome.total_failure(),
            "must not report a cheerful success"
        );
        assert_eq!(outcome.failures.len(), 1);

        let h = &health.read().unwrap()[0];
        assert_eq!(h.state, "error", "never fetched, so this is an error");
        assert!(h.last_attempt.is_some());
        assert!(h.last_success.is_none());
        assert!(h.error.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_failure_after_a_success_is_stale_and_keeps_the_cached_list() {
        let dir = tmpdir("stale");
        let cfg = cfg_with(vec!["http://127.0.0.1:1/list.txt".to_string()], &dir);
        let health = new_health(&cfg);

        // Pretend a previous refresh worked, and leave a cached list on disk.
        let cached = cfg.cached_list_path(&cfg.blocking.sources[0]);
        std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
        std::fs::write(&cached, "ads.example.com\n").unwrap();
        set_health(&health, &cfg.blocking.sources[0], |h| {
            h.last_success = Some(1);
            h.state = "ok";
        });

        let outcome = refresh_sources(&cfg, &health).await;
        assert!(outcome.total_failure());

        let h = &health.read().unwrap()[0];
        assert_eq!(
            h.state, "stale",
            "a previously-good source degrades, not breaks"
        );
        assert_eq!(
            std::fs::read_to_string(&cached).unwrap(),
            "ads.example.com\n",
            "the cached list must survive a failed refresh"
        );

        // And the matcher still blocks off that cached copy.
        let bl = build(&cfg);
        assert!(bl.lookup("ads.example.com").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn partial_success_is_not_a_total_failure() {
        let dir = tmpdir("partial");
        // One source that works (a local file server) and one that does not.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let body = "0.0.0.0 tracker.example.com\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });

        let cfg = cfg_with(
            vec![
                format!("http://{addr}/good.txt"),
                "http://127.0.0.1:1/bad.txt".to_string(),
            ],
            &dir,
        );
        let health = new_health(&cfg);
        let outcome = refresh_sources(&cfg, &health).await;

        assert_eq!(outcome.attempted, 2);
        assert_eq!(outcome.succeeded, 1);
        assert!(!outcome.total_failure(), "one good source is not a failure");
        assert_eq!(outcome.failures.len(), 1);

        let h = health.read().unwrap();
        assert_eq!(h[0].state, "ok");
        assert!(h[0].bytes.unwrap() > 0);
        assert_eq!(h[1].state, "error");
        drop(h);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn concurrent_refreshes_are_serialised_by_the_lock() {
        let lock = new_refresh_lock();
        let held = lock.clone().lock_owned().await;
        // A second refresh must back off rather than run alongside the first.
        assert!(
            lock.try_lock().is_err(),
            "the coordinator must refuse an overlapping refresh"
        );
        drop(held);
        assert!(lock.try_lock().is_ok(), "and allow one once free");
    }

    #[tokio::test]
    async fn temp_files_do_not_collide_and_are_cleaned_up() {
        let dir = tmpdir("tmpfiles");
        let cfg = cfg_with(vec!["http://127.0.0.1:1/x.txt".to_string()], &dir);
        let health = new_health(&cfg);
        refresh_sources(&cfg, &health).await;

        let leftovers: Vec<_> = std::fs::read_dir(dir.join("lists"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed download must not leave temp files behind"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
