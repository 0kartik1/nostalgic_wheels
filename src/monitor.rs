//! Periodic sampling of interface throughput and link latency.

use crate::db::{IfaceSample, WriteOp, Writer};
use crate::netinfo;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Sample `/proc/net/dev` and turn the cumulative counters into a rate.
pub async fn throughput_sampler(writer: Writer, interval: Duration) {
    let mut last: HashMap<String, (u64, u64, Instant)> = HashMap::new();
    let mut tick = tokio::time::interval(interval);

    loop {
        tick.tick().await;
        let counters = match netinfo::iface_counters() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("reading interface counters: {e:#}");
                continue;
            }
        };

        let now_instant = Instant::now();
        let ts = crate::db::now();

        for c in counters {
            if let Some((prev_rx, prev_tx, prev_at)) = last.get(&c.iface).copied() {
                let secs = now_instant.duration_since(prev_at).as_secs_f64();
                if secs <= 0.0 {
                    continue;
                }
                // Counters are 64-bit but wrap on 32-bit kernels; saturating
                // subtraction turns a wrap into a single zero sample instead of
                // an absurd spike.
                let rx_delta = c.rx_bytes.saturating_sub(prev_rx);
                let tx_delta = c.tx_bytes.saturating_sub(prev_tx);

                writer.send(WriteOp::Iface(IfaceSample {
                    ts,
                    iface: c.iface.clone(),
                    rx_bytes: c.rx_bytes as i64,
                    tx_bytes: c.tx_bytes as i64,
                    rx_bps: ((rx_delta as f64 * 8.0) / secs) as i64,
                    tx_bps: ((tx_delta as f64 * 8.0) / secs) as i64,
                }));
            }
            last.insert(c.iface.clone(), (c.rx_bytes, c.tx_bytes, now_instant));
        }
    }
}

/// Time the round trip to the router and to an upstream resolver, so the
/// dashboard can distinguish "my LAN is slow" from "my ISP is slow".
pub async fn latency_sampler(writer: Writer, upstream: SocketAddr, interval: Duration) {
    let mut tick = tokio::time::interval(interval);

    loop {
        tick.tick().await;
        let ts = crate::db::now();

        if let Some(route) = netinfo::default_route() {
            let gw = SocketAddr::new(IpAddr::V4(route.gateway), 53);
            let ms = match netinfo::tcp_probe_ms(gw, 1500).await {
                Some(v) => Some(v),
                // Not every router accepts TCP/53; port 80 nearly always works.
                None => {
                    let http = SocketAddr::new(IpAddr::V4(route.gateway), 80);
                    netinfo::tcp_probe_ms(http, 1500).await
                }
            };
            if let Some(ms) = ms {
                writer.send(WriteOp::Latency {
                    ts,
                    target: "gateway".into(),
                    ms,
                });
            }
        }

        if let Some(ms) = netinfo::tcp_probe_ms(upstream, 2500).await {
            writer.send(WriteOp::Latency {
                ts,
                target: "upstream".into(),
                ms,
            });
        }
    }
}
