//! Blocklist loading and matching.
//!
//! Accepts both hosts-file format (`0.0.0.0 ads.example.com`) and plain
//! one-domain-per-line lists, which covers essentially every list people
//! use with Pi-hole. Entries starting with `*.` become suffix rules.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

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

/// Download the configured remote lists into the on-disk cache. Failures are
/// logged, not fatal: a stale cached copy is better than no filtering.
pub async fn refresh_sources(cfg: &crate::config::Config) -> Result<()> {
    let dir = cfg.blocking.state_dir.join("lists");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(concat!("netwatch/", env!("CARGO_PKG_VERSION")))
        .build()?;

    for url in &cfg.blocking.sources {
        let dest = cfg.cached_list_path(url);
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) => {
                    // Write to a temp file then rename, so a partial download
                    // never replaces a good list.
                    let tmp = dest.with_extension("tmp");
                    if let Err(e) = std::fs::write(&tmp, &body) {
                        tracing::error!("writing {}: {e}", tmp.display());
                        continue;
                    }
                    if let Err(e) = std::fs::rename(&tmp, &dest) {
                        tracing::error!("renaming into {}: {e}", dest.display());
                        continue;
                    }
                    tracing::info!("downloaded blocklist {url} ({} bytes)", body.len());
                }
                Err(e) => tracing::error!("reading body of {url}: {e}"),
            },
            Ok(resp) => tracing::error!("fetching {url}: HTTP {}", resp.status()),
            Err(e) => tracing::error!("fetching {url}: {e}"),
        }
    }
    Ok(())
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
