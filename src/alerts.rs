//! Turning the collected data into the handful of things worth interrupting
//! someone for.
//!
//! A dashboard only reports to whoever is looking at it. These two conditions
//! are the ones that matter when nobody is:
//!
//! * a device appears on the network for the first time — the security-relevant
//!   event on a home LAN, and the one you want to know about within minutes
//!   rather than whenever you next open a browser tab;
//! * a client emits an NXDOMAIN storm — the usual shape of malware walking a
//!   generated domain list hunting for its command-and-control host.
//!
//! Kept deliberately narrow. A monitor that alerts on everything teaches you to
//! ignore it, at which point it alerts on nothing.

use crate::config::AlertConfig;
use crate::db::{self, WriteOp, Writer};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many pending alerts to hold before dropping. Alerts are rare — a full
/// queue means the notifier is wedged, and blocking discovery or the DNS path
/// behind a slow HTTP POST would be far worse than losing a notification.
const QUEUE_DEPTH: usize = 256;

/// Ceiling on one notification attempt. Short on purpose: a down ntfy must not
/// hold a task open long enough to matter.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
        }
    }

    /// ntfy's priority scale, where 3 is the default and 4 raises the phone's
    /// notification importance.
    fn ntfy_priority(self) -> &'static str {
        match self {
            Self::Info => "3",
            Self::Warning => "4",
        }
    }

    fn ntfy_tag(self) -> &'static str {
        match self {
            Self::Info => "bulb",
            Self::Warning => "warning",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub kind: &'static str,
    pub severity: Severity,
    /// What the alert is about: a MAC, or a client IP. Also the cooldown key.
    pub subject: String,
    pub title: String,
    pub detail: String,
}

impl Alert {
    pub fn new_device(mac: &str, hostname: Option<&str>, vendor: Option<&str>) -> Self {
        let who = hostname.unwrap_or("an unnamed device");
        let make = vendor.unwrap_or("unknown vendor");
        Self {
            kind: "new_device",
            severity: Severity::Info,
            subject: mac.to_string(),
            title: "New device on the network".to_string(),
            detail: format!("{who} ({make}) — {mac}"),
        }
    }

    pub fn nxdomain_storm(client: &str, count: i64, window_mins: u32) -> Self {
        Self {
            kind: "nxdomain_storm",
            severity: Severity::Warning,
            subject: client.to_string(),
            title: "Unusual NXDOMAIN volume".to_string(),
            detail: format!(
                "{client} got {count} NXDOMAIN answers in {window_mins} minutes. \
                 That is the usual shape of malware looking for a command-and-control \
                 host, though a broken app can do it too."
            ),
        }
    }
}

/// Cheaply cloneable handle for raising an alert from anywhere.
///
/// Sending never blocks and never fails loudly: a raised alert that cannot be
/// queued is dropped and counted, exactly like a dropped log line.
#[derive(Clone)]
pub struct AlertSink {
    tx: tokio::sync::mpsc::Sender<Alert>,
    cooldown: Arc<Mutex<HashMap<(&'static str, String), Instant>>>,
    cooldown_for: Duration,
}

impl AlertSink {
    pub fn raise(&self, alert: Alert) {
        // A persistent condition — a device that stays on the network, a client
        // that keeps failing lookups — would otherwise re-alert on every scan.
        if !self.take_cooldown_slot(alert.kind, &alert.subject) {
            return;
        }
        if self.tx.try_send(alert).is_err() {
            tracing::warn!("alert queue full or closed; an alert was dropped");
        }
    }

    /// Returns true if this (kind, subject) has not alerted inside the cooldown.
    fn take_cooldown_slot(&self, kind: &'static str, subject: &str) -> bool {
        let Ok(mut map) = self.cooldown.lock() else {
            // A poisoned mutex should not silence alerting.
            return true;
        };
        let now = Instant::now();
        let key = (kind, subject.to_string());
        if let Some(last) = map.get(&key)
            && now.duration_since(*last) < self.cooldown_for
        {
            return false;
        }
        // Bound the map so a network churning through randomised MACs cannot
        // grow it without limit.
        if map.len() > 4096 {
            map.retain(|_, t| now.duration_since(*t) < self.cooldown_for);
        }
        map.insert(key, now);
        true
    }
}

impl AlertSink {
    /// Construct a sink wired to a caller-supplied channel, for tests in other
    /// modules that need to observe what was raised.
    #[cfg(test)]
    pub fn for_test(tx: tokio::sync::mpsc::Sender<Alert>, cooldown_for: Duration) -> Self {
        Self {
            tx,
            cooldown: Arc::new(Mutex::new(HashMap::new())),
            cooldown_for,
        }
    }
}

/// Build the sink and the task that drains it.
///
/// Returns `None` when alerting is disabled, so callers can skip the work
/// entirely rather than feeding a sink that discards everything.
pub fn spawn(
    cfg: &AlertConfig,
    writer: Writer,
) -> Option<(AlertSink, tokio::task::JoinHandle<()>)> {
    if !cfg.enabled {
        return None;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Alert>(QUEUE_DEPTH);
    let sink = AlertSink {
        tx,
        cooldown: Arc::new(Mutex::new(HashMap::new())),
        cooldown_for: Duration::from_secs(u64::from(cfg.cooldown_mins) * 60),
    };

    let ntfy_url = cfg.ntfy_url.trim().to_string();
    let client = build_client(&ntfy_url);

    let task = tokio::spawn(async move {
        while let Some(alert) = rx.recv().await {
            // Notify first so `notified` records what actually happened, but
            // store regardless of the outcome: a failed push must never lose
            // the alert.
            let notified = match &client {
                Some(c) => notify(c, &ntfy_url, &alert).await,
                None => false,
            };
            writer.send(WriteOp::Alert {
                ts: db::now(),
                kind: alert.kind.to_string(),
                severity: alert.severity.as_str().to_string(),
                subject: alert.subject.clone(),
                detail: alert.detail.clone(),
                notified,
            });
            tracing::info!(
                "alert [{}] {}: {}",
                alert.severity.as_str(),
                alert.kind,
                alert.detail
            );
        }
    });

    Some((sink, task))
}

fn build_client(ntfy_url: &str) -> Option<reqwest::Client> {
    if ntfy_url.is_empty() {
        // Storing alerts for the dashboard is still useful without a push
        // target, so this is a normal configuration rather than an error.
        tracing::info!("alerts enabled; no alerts.ntfy_url set, so they are recorded only");
        return None;
    }
    // reqwest is built with rustls-no-provider, so its builder panics unless a
    // provider is installed first.
    crate::blocklist::ensure_crypto_provider();
    match reqwest::Client::builder()
        .timeout(NOTIFY_TIMEOUT)
        .user_agent(concat!("netwatch/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::error!(
                "building the alert HTTP client failed, alerts will be recorded only: {e}"
            );
            None
        }
    }
}

/// POST one alert to ntfy. Returns whether it was accepted.
///
/// No retry: the alert is already being stored, and a wedged notifier must not
/// back up behind attempts nobody is waiting for.
async fn notify(client: &reqwest::Client, url: &str, alert: &Alert) -> bool {
    let res = client
        .post(url)
        .header("Title", &alert.title)
        .header("Priority", alert.severity.ntfy_priority())
        .header("Tags", alert.severity.ntfy_tag())
        .body(alert.detail.clone())
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => true,
        // The URL is a shared secret — anyone holding it can read and publish
        // to the topic — so the status is logged but never the address.
        Ok(r) => {
            tracing::warn!("ntfy rejected an alert: HTTP {}", r.status());
            false
        }
        Err(e) => {
            tracing::warn!("could not deliver an alert to ntfy: {e}");
            false
        }
    }
}

/// Periodically evaluate the threshold conditions that cannot be spotted at
/// the moment they happen.
pub async fn storm_watcher(
    db: Arc<Mutex<Connection>>,
    sink: AlertSink,
    window_mins: u32,
    threshold: u32,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    // A missed tick must not cause a burst of catch-up scans.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tick.tick().await;

        let db = Arc::clone(&db);
        // SQLite work belongs off the async runtime; this one scans the query
        // log, which on a busy day is not free.
        let found = tokio::task::spawn_blocking(move || {
            let conn = db.lock().ok()?;
            db::nxdomain_offenders(&conn, window_mins, threshold).ok()
        })
        .await;

        match found {
            Ok(Some(offenders)) => {
                for (client, count) in offenders {
                    sink.raise(Alert::nxdomain_storm(&client, count, window_mins));
                }
            }
            Ok(None) => tracing::debug!("NXDOMAIN scan skipped: database busy"),
            Err(e) => tracing::warn!("NXDOMAIN scan task failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sink_with_cooldown(secs: u64) -> (AlertSink, tokio::sync::mpsc::Receiver<Alert>) {
        let (tx, rx) = tokio::sync::mpsc::channel(QUEUE_DEPTH);
        (
            AlertSink {
                tx,
                cooldown: Arc::new(Mutex::new(HashMap::new())),
                cooldown_for: Duration::from_secs(secs),
            },
            rx,
        )
    }

    /// The whole point of the cooldown: a condition that persists across scans
    /// — a device that stays on the network, a client that keeps failing —
    /// must report once, not once every scan interval.
    #[tokio::test]
    async fn a_repeated_condition_alerts_once() {
        let (sink, mut rx) = sink_with_cooldown(3600);

        for _ in 0..5 {
            sink.raise(Alert::nxdomain_storm("192.168.1.5", 200, 10));
        }

        assert!(rx.try_recv().is_ok(), "the first one gets through");
        assert!(
            rx.try_recv().is_err(),
            "repeats inside the cooldown must be suppressed"
        );
    }

    /// Cooldown is per subject: one noisy client must not mask a different one.
    #[tokio::test]
    async fn different_subjects_alert_independently() {
        let (sink, mut rx) = sink_with_cooldown(3600);

        sink.raise(Alert::nxdomain_storm("192.168.1.5", 200, 10));
        sink.raise(Alert::nxdomain_storm("192.168.1.9", 300, 10));

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_ok(),
            "a second client is a separate condition"
        );
    }

    /// ...and per kind, so a new device and a storm from the same subject are
    /// both reported.
    #[tokio::test]
    async fn different_kinds_about_one_subject_alert_independently() {
        let (sink, mut rx) = sink_with_cooldown(3600);

        sink.raise(Alert::new_device("aa:bb:cc:dd:ee:01", None, None));
        sink.raise(Alert::nxdomain_storm("aa:bb:cc:dd:ee:01", 200, 10));

        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn the_cooldown_expires() {
        let (sink, mut rx) = sink_with_cooldown(0);

        sink.raise(Alert::nxdomain_storm("192.168.1.5", 200, 10));
        sink.raise(Alert::nxdomain_storm("192.168.1.5", 250, 10));

        assert!(rx.try_recv().is_ok());
        assert!(
            rx.try_recv().is_ok(),
            "with no cooldown configured, a fresh condition alerts again"
        );
    }

    /// A failed push must never lose the alert: the dashboard is the system of
    /// record and ntfy is a convenience on top of it. `notify` returning false
    /// is what makes the caller store it with notified = 0 rather than skip it.
    #[tokio::test]
    async fn a_failed_delivery_reports_false_rather_than_erroring() {
        crate::blocklist::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(250))
            .build()
            .unwrap();

        // Port 1 on loopback refuses immediately.
        let ok = notify(
            &client,
            "http://127.0.0.1:1/topic",
            &Alert::new_device("aa:bb:cc:dd:ee:01", None, None),
        )
        .await;

        assert!(
            !ok,
            "an unreachable ntfy reports failure, it does not panic"
        );
    }

    /// No URL configured is a normal setup, not an error: alerts still land in
    /// the dashboard.
    #[test]
    fn no_ntfy_url_means_no_client_rather_than_a_failure() {
        assert!(build_client("").is_none());
    }

    /// The message is what lands on a phone at an awkward hour, so it has to
    /// identify the device without needing the dashboard open.
    #[test]
    fn a_new_device_alert_names_the_device() {
        let a = Alert::new_device("aa:bb:cc:dd:ee:01", Some("living-room-tv"), Some("Samsung"));
        assert!(a.detail.contains("living-room-tv"));
        assert!(a.detail.contains("Samsung"));
        assert!(a.detail.contains("aa:bb:cc:dd:ee:01"));
        assert_eq!(a.severity, Severity::Info);
    }

    #[test]
    fn an_unnamed_new_device_still_produces_a_usable_message() {
        let a = Alert::new_device("aa:bb:cc:dd:ee:01", None, None);
        assert!(a.detail.contains("aa:bb:cc:dd:ee:01"));
        assert!(
            !a.detail.contains("None"),
            "no debug formatting leaks: {}",
            a.detail
        );
    }

    #[test]
    fn a_storm_alert_is_a_warning_and_says_how_many() {
        let a = Alert::nxdomain_storm("192.168.1.5", 412, 10);
        assert_eq!(a.severity, Severity::Warning);
        assert!(a.detail.contains("412"));
        assert!(a.detail.contains("10 minutes"));
    }
}
