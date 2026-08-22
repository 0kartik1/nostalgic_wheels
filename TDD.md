# netwatch — Technical Design Document

**Repo:** [0kartik1/nostalgic_wheels](https://github.com/0kartik1/nostalgic_wheels)  
**Crate / binary name:** `netwatch`  
**Language:** Rust 2024 edition, MSRV **1.88**  
**Purpose of this file:** a durable map of how the code works so later chats can `@TDD.md` instead of re-reading the tree.

Last surveyed against the tree as of 2026-08-22 (single-binary, no runtime deps).

---

## 1. What this program is

A **LAN DNS forwarder + ad/tracker blocker + device inventory + local dashboard**, meant to run on a Raspberry Pi (or any systemd Linux box) **beside the home router**, not in front of it.

It does **not** sniff switched unicast traffic. Visibility comes from devices **asking it for DNS**. Same trick as Pi-hole / AdGuard Home.

```
Modem ── Router ─┬─ phones, laptops, TVs
                 └─ Pi running netwatch
                      :53  DNS (UDP + optional TCP)
                      :8080 dashboard (loopback by default)
```

**Cannot see (by design):** HTTPS paths/query strings, per-device byte counts of all LAN traffic, devices that bypass this resolver (hardcoded DNS, some DoH).

**Can see:** domain, client IP, (usually) which device, block vs forward vs cache, Pi link health, new MACs, NXDOMAIN storms.

---

## 2. Constraints that shape every module

These are not optional style notes; they are load-bearing.

| Constraint | Consequence in code |
|------------|---------------------|
| Pi is **not** in the traffic path | No packet capture; DNS is the sensor |
| Switch does not flood unicast | Only **broadcast/multicast** (DHCP, mDNS) plus **ARP table** after we talk to a host |
| If DNS dies, the **house looks offline** | Bad config must fail before restart (`--check-config`); DNS bind failure **exits** so systemd restarts; panics must not abort the process (`panic = "abort"` is deliberately **not** set) |
| SD card wear | Batched SQLite writer, device-row debounce (60s heartbeat), query retention |
| Open resolver = amplification weapon | Default ACL is loopback + RFC1918; denied queries are **dropped**, not REFUSED |
| Dashboard can change DNS policy | Default `web.listen = 127.0.0.1:8080`; off-loopback **requires** `admin_token` ≥ 16 chars or process refuses to start |
| IPv6 neighbours have no `/proc/net/arp` equivalent | IPv6 DNS is answered if `listen_v6` is set; **no device attribution** |
| Firefox DoH bypasses the Pi | Default NXDOMAIN for `use-application-dns.net` |

**Cloud VM is not a drop-in host:** ARP/mDNS/DHCP/sweep and per-device IPs only work on the **same L2/L3 LAN**. A public UDP/53 without auth is an open resolver.

---

## 3. Repository layout

```
nostalgic_wheels/
├── Cargo.toml / Cargo.lock     # package name netwatch
├── config.example.toml         # copied to /etc/netwatch/config.toml on install
├── TDD.md                      # this document
├── README.md                   # operator-facing; design rationale + install
├── src/main.rs                 # process wiring, task spawn, shutdown
├── src/config.rs               # TOML, defaults, validate()
├── src/dns/mod.rs              # Resolver, UDP/TCP servers, forward, sinkhole
├── src/dns/acl.rs              # allow_from
├── src/dns/cache.rs            # TTL-aware answer cache
├── src/blocklist.rs            # download, parse, match
├── src/devices.rs              # MAC/IP/name registry + listeners
├── src/oui.rs                  # MAC vendor + randomized-MAC bit
├── src/db.rs                   # SQLite schema, writer thread, read queries
├── src/api.rs                  # Axum HTTP + embeds dashboard
├── src/web/index.html          # single-file dashboard (inline CSS/JS)
├── src/alerts.rs               # new device, NXDOMAIN storm, optional ntfy
├── src/monitor.rs              # iface throughput + gateway/upstream RTT
├── src/netinfo.rs              # /proc/net/route, /proc/net/dev, /proc/net/arp
├── tests/check_config.rs       # CLI --check-config integration
├── deploy/install.sh
├── deploy/netwatch.service
├── scripts/pi-audit.sh         # read-only Pi health dump (unrelated to DNS)
└── .github/workflows/ci.yml    # fmt, clippy, test, ARM cross-compile
```

---

## 4. Runtime architecture

One Tokio multi-thread runtime. Shared state is `Arc` + `RwLock`/`Mutex`/`atomics`. SQLite writes never happen on the DNS task.

```
main()
  ├─ Config load → validate
  ├─ SQLite: write conn + read conn (WAL)
  ├─ spawn_writer()  ── dedicated thread, batched commits
  ├─ Blocklist build (disk cache; fetch if empty)
  ├─ OuiDb
  ├─ alerts::spawn
  ├─ DeviceStore::new + hydrate(known_devices)
  ├─ netinfo::default_route + lan_subnet
  ├─ dns::Resolver
  └─ spawn tasks:
       serve_udp (v4, optional v6)
       serve_tcp (if enable_tcp)
       cache_sweeper
       alert drain + optional storm_watcher
       arp_poller, mdns_listener, dhcp_listener, subnet_sweeper, reverse_dns_worker
       throughput_sampler (10s), latency_sampler (60s)
       blocklist refresh loop
       api::serve (dashboard)
  └─ wait Ctrl-C / SIGTERM → abort tasks
```

**If `serve_udp` / `serve_tcp` return Err:** `std::process::exit(1)` so systemd `Restart=on-failure` runs. Dashboard-only “healthy” process with no DNS is considered worse.

**Bind retry:** `dns::bind_with_retry` waits up to ~30s for port 53 races at boot.

---

## 5. DNS request path (the hot path)

**Entry:** `dns::serve_udp` / `serve_tcp` → `Resolver::handle` → `handle_inner`.

**UDP:** semaphore `max_udp_in_flight` (default 128). Over limit → drop packet, no reply (client retries). ACL fail → drop, no parse.

**Per-request budget:** `dns.request_timeout_ms` (default 10s) wraps the whole handle, not per-upstream.

### Decision order (`handle_inner`)

1. Parse wire format (`hickory-proto`). Garbage → `None` (no reply).
2. Only standard `QUERY`. Else REFUSED.
3. Need ≥1 question. Else FORMERR.
4. Name: ASCII, strip trailing `.`, lowercase.
5. **Firefox canary** if `blocking.disable_firefox_doh` and name == `use-application-dns.net` → **NXDOMAIN** (must not go through zero-IP sinkhole; Firefox would treat 0.0.0.0 as a working resolver). Log status `blocked`, list label `firefox-doh-canary`.
6. **Blocklist** `lookup`. Hit → `sinkhole()`:
   - `blocking.mode = "zero_ip"` (default): A=`0.0.0.0`, AAAA=`::`, TTL **60**
   - `"nxdomain"`: NXDOMAIN
7. **Cache** if enabled. Key includes class and DO/CD bits. Hit rebuilds a **fresh envelope** from *this* request (never reuse stored TXID/EDNS).
8. **Forward** `forward()`: try `dns.upstreams` in order (defaults `1.1.1.1:53`, `9.9.9.9:53`).
   - UDP exchange on a **fresh socket** (source-port randomization).
   - Truncated UDP → retry **same** upstream over TCP (do not cache TC stubs).
   - Client EDNS size is **clamped** to `upstream_udp_payload` (default 1232) before asking upstream.
   - Response must `answers_request` (ID + question match) or it is rejected.
9. Cache insert on success (not SERVFAIL / empty / zero TTL).
10. `devices.learn_from_dns` on A/AAAA/PTR in the answer.
11. `log()` → `devices.touch_ip` + `Writer::send(Query)`.

**Statuses stored:** `forwarded | cached | blocked | nxdomain | servfail | refused`.

**Libraries:** `hickory-proto` (parse/build), **not** a full recursive resolver. Recursion is “ask these IPs.”

---

## 6. Module reference

### `src/main.rs`

CLI (`clap`):

| Flag | Role |
|------|------|
| `-c/--config` | default `/etc/netwatch/config.toml` |
| `--dns-listen`, `--web-listen`, `--database` | overrides |
| `--no-fetch` | skip first-run blocklist download |
| `--print-config` | dump effective TOML |
| `--check-config` | validate and exit 0/1 (installer uses this) |
| `--rebuild-db` | VACUUM-style rebuild for old `auto_vacuum=NONE` files |

`apply_overrides` is shared by start and `--check-config`.

### `src/config.rs`

`#[serde(deny_unknown_fields)]` on all structs — unknown TOML keys fail parse.

**`validate()` must pass to start:** non-empty upstreams; ACL parse; in-flight limits > 0; `listen_v6` actually IPv6; non-loopback web ⇒ token ≥ 16 chars; ntfy URL if set is http(s); storm thresholds > 0; `blocking.mode` is `zero_ip` or `nxdomain`.

**Paths:**

- Manual lists: `{state_dir}/deny.list`, `{state_dir}/allow.list`
- Downloaded lists: `{state_dir}/lists/{fnv-like-hash}.list`

Missing config file → **defaults**, except `--check-config` on a missing path still reports “would start on defaults.”

### `src/dns/acl.rs`

`allow_from` entries: `loopback`, `private`, `any`, or CIDR. Detected LAN subnet can be **trusted extra** if it sits outside RFC1918 (some ISP-handed public prefixes). `any` logs a loud open-resolver warning.

### `src/dns/cache.rs`

Stores RRs with **per-record TTL countdown**. `cache_min_ttl` means **do not cache answers shorter than this** (not “round TTL up”). OPT stripped. NXDOMAIN/NODATA cached off SOA TTL. SERVFAIL / empty / TTL 0 not cached.

### `src/blocklist.rs`

Matcher: exact HashMap + wildcard HashMap + allow sets. Wildcard `*.example.com` matches **example.com itself** and labels under it (walk up dots). First source to claim a domain wins for attribution; dashboard “entries” are **unique contributions**.

Formats: hosts (`0.0.0.0 name`), one-name-per-line, `*.wild`, ABP `||name^` / `@@||name^`. ABP rules with path/modifiers **skipped**.

`refresh_sources` HTTP via `reqwest`+rustls. `build()` is CPU-heavy → `spawn_blocking` on refresh. `HealthMap` + `RefreshLock` coordinate dashboard `/api/reload` vs timer.

Default source: StevenBlack hosts. Default refresh: 24h.

### `src/devices.rs`

In-memory `DeviceStore`: `by_mac`, `ip_to_mac`, `pending_names`.

**Write debounce:** persist only if fingerprint (ip/hostname/vendor/randomized) changed **or** `last_seen` heartbeat ≥ 60s. Restarts: `hydrate()` marks rows already written so reboot does not rewrite every device (and so new-device alerts do not fire for known MACs).

**Sources (all IPv4-oriented):**

| Task | Config | Mechanism |
|------|--------|-----------|
| `arp_poller` | `discovery.arp` (on) | `/proc/net/arp` |
| `mdns_listener` | `mdns` (on) | UDP 5353 / 224.0.0.251; may fail if Avahi owns the port |
| `dhcp_listener` | `dhcp` (**off**) | UDP 67 **listen only**, never answers. SO_REUSEPORT + same UID can steal DHCP from another server — why default off |
| `subnet_sweeper` | `sweep` (on) | harmless UDP to each LAN address → kernel ARP |
| `reverse_dns_worker` | `reverse_dns` (on) | PTR via first upstream, gateway first |

`DiscoveryStatus` (dhcp/mdns: Disabled / Active / Unavailable) is shown on the dashboard so “no names” is not silent.

Randomized MACs (locally administered bit): vendor shown as `(randomized MAC)`, flagged `randomized`.

### `src/oui.rs`

Built-in consumer prefixes + optional IEEE CSV (`discovery.oui_file`).

### `src/db.rs`

**Two connections, WAL, `synchronous=NORMAL`.** Writer: `mpsc::sync_channel` (bounded). `Writer::send` **never blocks** DNS; overflow increments `DropCounts` (queries vs devices vs monitoring vs alerts separately).

Schema (order of pragmas matters: `auto_vacuum=INCREMENTAL` **before** WAL):

- `queries` — log
- `devices` — PK `mac`
- `iface_samples`
- `latency` — targets `gateway` / upstream
- `alerts`

Retention: query/iface/latency by `storage.retention_days` (default 14). Alerts have a **separate** longer retention constant in `db.rs`. Incremental vacuum if pragma mode is 2; old DBs stay `NONE` → dashboard “fixed size”; CLI `--rebuild-db`.

Reads for HTTP run in `spawn_blocking` holding a `Mutex<Connection>`.

### `src/api.rs` + `src/web/index.html`

Axum 0.8. HTML **embedded** with `include_str!` — no CDN, works offline.

| Method | Path | Auth |
|--------|------|------|
| GET | `/` | no |
| GET | `/api/summary`, `status`, `queries`, `timeseries`, `top-*`, `query-types`, `devices`, `bypass-suspects`, `alerts`, `interfaces` | no |
| POST/DELETE | `/api/deny`, `/api/allow` body `{"domain"}` | Bearer if token set |
| POST | `/api/reload`, `/api/flush-cache` | same |

Loopback + no token: mutating routes allowed (physical access = auth). Security headers + CSP (inline script/style required). Body cap 16 KiB. HTTP timeout 30s.

Bypass suspects: devices seen on LAN with **≤ 5** queries in the window (`BYPASS_QUERY_THRESHOLD`).

ntfy URL is **never** returned by the API.

### `src/alerts.rs`

Kinds: **new_device**, **nxdomain_storm**. Cooldown per (kind, subject). Channel to writer + optional ntfy POST. No retry on ntfy failure (still stored). `storm_watcher` polls SQLite on `scan_interval_secs`.

Defaults: enabled, threshold 50 NXDOMAIN / 10 min, scan 300s, cooldown 60 min.

### `src/monitor.rs` + `src/netinfo.rs`

Throughput: `/proc/net/dev` deltas every 10s. Latency: TCP probe gateway :53 then :80; upstream :53 every 60s. Linux-specific proc files.

### `src/oui.rs` / thermal

Status endpoint also surfaces Pi temp/load from sysfs where present (`api` / `netinfo`).

---

## 7. Default listen / paths (mental model)

| Item | Default |
|------|---------|
| DNS | `0.0.0.0:53` UDP+TCP |
| Web | `127.0.0.1:8080` |
| DB | `/var/lib/netwatch/netwatch.db` |
| State / lists | `/var/lib/netwatch` |
| Config | `/etc/netwatch/config.toml` |
| Flush | 750 ms |
| Cache | 20k entries, min TTL 30s, max 86400s |

---

## 8. Deploy and process model

`deploy/install.sh`: system user `netwatch`, binary `/usr/local/bin/netwatch`, config `0640 root:netwatch`, **`--check-config` before restart**, does not clobber existing config.

`deploy/netwatch.service`: `User=netwatch`, `CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, `MemoryMax` ~1G, `Restart=on-failure`, `StartLimitBurst=5` / 300s (avoid silent restart storms on bad config). `After=network-online.target` and `tailscaled.service` (blocklist HTTP vs MagicDNS race; LAN DNS uses literal upstream IPs).

Port 53 often held by `systemd-resolved`; README documents `DNSStubListener=no`.

---

## 9. Dependencies (why they exist)

| Crate | Use |
|-------|-----|
| tokio | async DNS, HTTP, timers |
| hickory-proto | DNS messages |
| axum | dashboard |
| rusqlite bundled | no system sqlite |
| reqwest + rustls/ring | blocklists + ntfy (`rustls-no-provider` + ring in `main` for ARM cross without cmake/aws-lc) |
| socket2 | `IPV6_V6ONLY`, reuse, nonblocking bind |
| clap, toml, serde, tracing, anyhow | CLI, config, logs |

Release: thin LTO, strip, codegen-units=1. **Not** `panic=abort` (one task panic must not kill household DNS).

---

## 10. Tests and CI

- Unit tests live **inside** modules (`dns`, `cache`, `acl`, `devices`, `alerts`, `config` example-toml parse, etc.).
- `tests/check_config.rs` — CLI.
- CI: `stable` + MSRV `1.88`; fmt+clippy -D warnings on stable; `cargo test --all-targets`; cross `aarch64-unknown-linux-gnu` and `armv7-unknown-linux-gnueabihf`.

---

## 11. Invariants (do not break casually)

1. DNS task must not wait on disk or a full channel (`Writer` drops).
2. Denied clients get **no** DNS reply.
3. Firefox canary is NXDOMAIN, not zero_ip.
4. DeviceStore **hydrate before** discovery/alerts.
5. Wildcard block/allow includes the apex name.
6. Dashboard mutating API locked down if `web.listen` is not loopback.
7. DHCP listener default **off**.
8. IPv4 and IPv6 DNS sockets are **separate**; v6 socket is V6ONLY.
9. Cache answers are **name-scoped**, not client-scoped; response header rebuilt per client.
10. Config example must stay valid (`deny_unknown_fields` + installer copies it).

---

## 12. Product / SaaS notes (context, not implemented)

This binary is a **single-tenant LAN appliance**. Missing for a consumer product: first-run wizard, fail-open UX, remote dashboard without SSH, multi-tenant cloud DNS, per-household auth DoH. Hosting the same process on AWS does not preserve ARP/mDNS/device identity.

---

## 13. How to use this in a new Cursor chat

Paste or `@TDD.md` and say which layer you are changing (`dns`, `devices`, `db`, `api`, `config`, deploy). Only open source files that the TDD names for that layer. Re-read a file if you are editing it; do not assume this doc replaced the compiler.

If the tree drifts, update **this file in the same PR** (schema, endpoints, defaults, invariants).
