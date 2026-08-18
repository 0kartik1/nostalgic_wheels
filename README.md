# netwatch

[![CI](https://github.com/0kartik1/nostalgic_wheels/actions/workflows/ci.yml/badge.svg)](https://github.com/0kartik1/nostalgic_wheels/actions/workflows/ci.yml)

A network monitor and ad blocker for a Raspberry Pi on a home LAN, written in
Rust. It answers DNS for your network, logs every lookup with the device that
made it, blocks ad and tracker domains, and serves a live dashboard.

Single binary, no runtime dependencies. Measured resident memory: **17 MB** with
a 100,000-domain blocklist loaded, **10 MB** with blocking off.

> **Upgrading from an earlier build?** Two defaults changed for safety. The
> dashboard now listens on **loopback only**, and DHCP discovery is now **off**.
> See [Upgrading](#upgrading) — each takes one line of config to restore.

```
┌── Modem ── Router ─┬─ phone, laptop, TV, ...
                     └─ Raspberry Pi ── netwatch ── :53 DNS
                                                 └─ :8080 dashboard
```

## Read this first: what a Pi beside the router can and cannot see

This shapes everything about the design, so it is worth being blunt about.

Your Pi is plugged into a switch port on the router. **A switch only forwards a
frame to the port the destination lives on**, so the Pi never receives packets
sent between your laptop and the internet. Putting the interface in promiscuous
mode does not help; the frames are not delivered to that port in the first
place. Any tool that claims to sniff your whole network from this position is
either wrong or is using port mirroring.

So netwatch does what Pi-hole does: **it becomes the network's DNS server.**
Every device voluntarily sends its lookups to the Pi, and each lookup carries
the domain and the client's IP address. That is a real, reliable view of who is
talking to whom, and it is obtained by being *asked* rather than by
eavesdropping.

| What you asked for | What you get | How |
|---|---|---|
| Domain names per request | ✅ Yes | Every DNS query is logged |
| Which device made it | ✅ Yes | Client IP → MAC → vendor + hostname |
| MAC / device info | ✅ Yes | ARP table + OUI vendor lookup + mDNS/DHCP names |
| Blocking ads/trackers | ✅ Yes | Blocklists, sinkholed answers |
| Throughput, errors, latency | ✅ Yes (for the Pi's own link) | `/proc/net/dev`, TCP probes |
| **Full URLs** (`/path?query`) | ❌ No | HTTPS encrypts the path. Nothing short of installing a trusted root CA on every device and running a MITM proxy can read it — don't. |
| Per-device byte counts | ❌ Not from this position | Needs to be in the traffic path; see below |

### Two honest caveats

**A domain is not a visit.** Query logs show what a device *resolved*, which
includes prefetching, background sync, and connection reuse. It is an excellent
signal, not a browsing history.

**IPv6 clients are logged but not named.** netwatch listens on IPv4 only by
default; set `dns.listen_v6 = "[::]:53"` to add a second listener. It is a
second socket rather than a dual-stack one, with `IPV6_V6ONLY` forced on, so it
cannot accidentally claim the IPv4 port and fight the first listener.

Either way, IPv6 queries are answered and appear in the log by address, but get
no device attribution: Linux exposes the IPv4 ARP table at `/proc/net/arp` and
has no equivalent file for IPv6 neighbours — that needs netlink, which is a
dependency and a chunk of socket code disproportionate to the payoff here. Such
clients show as bare addresses rather than being silently dropped. If you want
names, the practical answer today is to hand out only the IPv4 DNS server on
the LAN, which is what most routers do anyway.

<a id="devices-that-bypass-you"></a>
**Devices can bypass you.** A device with a hardcoded DNS server, or using
DNS-over-HTTPS, never appears in the log at all — and the dashboard cannot tell
the difference between "quiet device" and "device I am not seeing". That makes
this the one caveat that can mislead you rather than merely limit you.

Three things push back on it, in descending order of effectiveness:

1. **The Firefox canary, on by default.** netwatch answers NXDOMAIN for
   `use-application-dns.net`, which is Mozilla's documented signal for "this
   network filters DNS". Firefox sees it and turns its own DoH off, so its
   queries come back through netwatch. Set `blocking.disable_firefox_doh =
   false` if you would rather it kept using DoH.
2. **Blocking known DoH endpoints.** There is a commented source in
   `config.example.toml` for a maintained list. This catches clients that
   resolve their DoH provider by name, which is most of them, but not one with
   a hardcoded IP.
3. **Blocking DNS-over-TLS at the router**, by dropping outbound TCP and UDP
   port **853**. DoT uses a dedicated port, so this is clean to block — unlike
   DoH, which is indistinguishable from ordinary HTTPS on port 443.

None of this is airtight against a device that genuinely does not want to be
seen; a hardcoded resolver IP or DoH-over-443 will still get through. What it
does do is close the accidental cases, which are the overwhelming majority.
Chrome checks whether the system resolver supports DoH before upgrading and
generally will not, so it is much less of a problem than Firefox was.

Rather than leave the rest as guesswork, the dashboard has a **Bypass suspects**
panel: devices that discovery can see on the network but that have resolved
almost nothing. That is the signature of a device answering its own DNS.

### If you want true packet-level visibility later

You need the traffic to physically pass through the Pi. Either:

1. **Port mirroring / SPAN** on a managed switch, copying all traffic to the
   Pi's port. Passive and safe, but consumer routers rarely support it.
2. **Put the Pi inline** as the router (two NICs, Pi does NAT). Full visibility
   including SNI hostnames and per-device byte counts — at the cost of the Pi
   becoming a single point of failure for your internet, and a Pi's NIC capping
   your throughput.

Neither is needed for what this tool does today, and option 2 in particular is
a much bigger commitment than it looks. The DNS approach gets you most of the
value for none of the risk.

## What it collects

**DNS** — timestamp, client IP and resolved device name, domain, query type,
outcome (forwarded / cached / blocked / NXDOMAIN / SERVFAIL), upstream latency,
and the answer records. Blocked entries record which list matched.

**Devices** — MAC, current IP, hostname, manufacturer, first and last seen,
per-device query and block counts. Names are learned from four independent
sources because no single one is reliable:

| Source | How it works | Reliability |
|---|---|---|
| DHCP (port 67) | Devices broadcast their hostname when renewing a lease. Passive listen only — netwatch never answers, so your router remains the only DHCP server. | Best |
| mDNS (224.0.0.251) | Apple/Android/printers announce themselves to the whole segment. | Good |
| Reverse DNS | The router usually knows its own DHCP lease names. | Varies |
| OUI table | First 3 MAC bytes → manufacturer. ~140 common consumer prefixes built in; point `oui_file` at the IEEE CSV for full coverage. | Vendor only |

DHCP and mDNS work from a switch port precisely *because* they are
broadcast/multicast — the switch floods them to every port, including the Pi's.
That is the one category of other-device traffic a passive host genuinely sees.

Idle devices are discovered by a periodic sweep that sends one harmless UDP
datagram to each address in the LAN, prompting the kernel to resolve its MAC.

Phones that randomise their MAC for privacy are detected (the
locally-administered bit) and flagged `random` rather than being reported with
a bogus vendor — such an address is not a stable device identity.

**Network health** — per-interface throughput, cumulative bytes, packet counts,
errors and drops; round-trip time to the router and to the upstream resolver
(separated, so you can tell "my Wi-Fi is bad" from "my ISP is bad"); Pi CPU
temperature, load, memory and uptime.

## Install

### Build on the Pi (simplest)

Works on a Pi 3 or newer with ≥1 GB RAM. Takes 5–20 minutes depending on model.
**Needs rustc 1.88 or newer** (via rustup — Debian/Raspbian's packaged `rustc`
is usually far behind and will fail with a version-mismatch error listing
`hickory-proto` and several `icu_*` crates).

```bash
sudo apt remove -y rustc cargo 2>/dev/null  # drop any old apt-packaged Rust
sudo apt update && sudo apt install -y build-essential curl git pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

git clone https://github.com/0kartik1/nostalgic_wheels.git
cd nostalgic_wheels
cargo build --release
sudo ./deploy/install.sh
```

If you already have rustup but hit the version error, just `rustup update
stable` and rebuild.

The installer creates a `netwatch` system user, installs the binary and a
hardened systemd unit, and prints what to do next. It is safe to re-run to
upgrade — your config and database are left alone.

### Cross-compile from a laptop

SQLite and the TLS backend both include C, so a cross toolchain is needed.
[`cross`](https://github.com/cross-rs/cross) handles it in Docker:

```bash
cargo install cross --git https://github.com/cross-rs/cross

# 64-bit Raspberry Pi OS on a Pi 3/4/5:
cross build --release --target aarch64-unknown-linux-gnu

# 32-bit Raspberry Pi OS, or a Pi Zero 2 W:
cross build --release --target armv7-unknown-linux-gnueabihf

scp target/aarch64-unknown-linux-gnu/release/netwatch pi@raspberrypi:/tmp/
```

Then on the Pi, `sudo install -m755 /tmp/netwatch /usr/local/bin/netwatch` and
copy `deploy/netwatch.service` and `config.example.toml` into place (or run the
installer from a checkout).

Check which you need with `uname -m`: `aarch64` → the first, `armv7l` → the
second.

### Freeing port 53

Most Pi OS images run `systemd-resolved`, which holds port 53. If netwatch
cannot bind:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/netwatch.conf
sudo systemctl restart systemd-resolved
sudo systemctl restart netwatch
```

**If DNS still isn't answering after a reboot specifically** (but a manual
`systemctl restart netwatch` fixes it every time), that's a different problem:
something else transiently holds port 53 for the first few seconds of boot —
a DHCP client hook, NetworkManager's local resolver, etc. — and releases it
shortly after. netwatch retries a failed bind for 30 seconds to ride this out
on its own, so a single reboot delay usually self-heals; `journalctl -u
netwatch` will show `address in use, retrying in ...` lines while this
happens. If the conflict outlasts 30 seconds, netwatch exits (rather than
running with the dashboard alive but no DNS) so systemd's `Restart=on-failure`
retries the whole thing — check `systemctl status netwatch` for a restart
count climbing, and `sudo ss -tulnp | grep :53` right after boot to catch
whatever's racing it.

## Pointing your network at it

Nothing is monitored until devices actually use the Pi for DNS.

**Whole network (recommended).** In the router's DHCP/LAN settings, set the DNS
server handed to clients to the Pi's IP. Devices pick it up as leases renew, or
immediately after a reboot. Give the Pi a static IP or a DHCP reservation first
— if its address changes, the network loses DNS.

**One device first.** Set that device's DNS manually to the Pi's IP. Good way to
confirm everything works before committing the household.

Verify:

```bash
nslookup github.com <pi-ip>          # should resolve
nslookup graph.facebook.com <pi-ip>  # should return 0.0.0.0 once lists load
```

### Who is allowed to ask

netwatch answers **only the LAN** by default (`dns.allow_from = ["loopback",
"private"]`), plus whatever subnet it detects on its own interface — so a
household whose ISP hands out public addresses instead of RFC1918 still works.

This default matters. A recursive resolver that answers anyone is an *open
resolver*, and open resolvers get conscripted into DNS amplification attacks: a
spoofed 60-byte query provokes a multi-kilobyte answer aimed at a victim. One
forwarded port would be enough. Queries from outside the allowed set are
dropped rather than refused, because replying would still send a packet to the
spoofed address.

To serve an extra subnet (a guest VLAN, a VPN range):

```toml
[dns]
allow_from = ["loopback", "private", "10.8.0.0/24"]
```

`any` disables the protection entirely and logs a warning at startup. The
dashboard's resolver panel shows the current rules and a count of dropped
queries, so a wrongly-excluded client is easy to spot.

### Worth knowing before you switch the whole house over

If netwatch stops, DNS stops and the network appears "down" to everyone, even
though the internet is fine. The systemd unit restarts on failure, and it is
worth setting a **second** DNS server in your router's settings pointing at
`1.1.1.1` as a fallback. Note the trade-off: clients that fall back to the
secondary bypass blocking and logging, so you get resilience at the cost of
completeness. Configure the secondary while you are getting set up; drop it
later if you would rather have complete logs.

## Dashboard

`http://<pi-ip>:8080`

Summary tiles, query volume over time (allowed vs blocked), interface
throughput, top allowed and blocked domains, a device table, and a filterable
live query log with one-click block/allow per domain. Light and dark themes,
usable on a phone, and every chart has a table view. No external assets, so it
works with the Pi offline.

### Reaching it, safely

The dashboard can add block rules, flush the DNS cache and trigger downloads,
so it binds **loopback only** by default. Two ways to use it from another
machine:

**SSH tunnel — nothing exposed, nothing to configure:**

```bash
ssh -L 8080:localhost:8080 pi@raspberrypi
# then browse to http://localhost:8080
```

**Or bind it to the LAN, which requires a token:**

```toml
[web]
listen = "0.0.0.0:8080"
admin_token = "<output of: openssl rand -hex 32>"   # min 16 chars
```

netwatch **refuses to start** if `listen` is off-loopback without a token —
the one combination that would silently expose rule changes to the network.

Read-only endpoints stay open so the dashboard renders immediately; the
browser asks for the token the first time you change something and keeps it in
`sessionStorage` (never in the page source, never returned by the API). The
config file is installed `root:netwatch 0640` because it can hold that secret.

This is a real boundary, not a substitute for one: still do not port-forward
port 8080. For access away from home, use a VPN such as WireGuard or
Tailscale.

### API

Everything the dashboard shows is available as JSON:

| Endpoint | Returns |
|---|---|
| `GET /api/summary` | 24h totals, block rate, device counts |
| `GET /api/status` | Resolver, blocklist, interface and Pi health state |
| `GET /api/queries?limit&offset&search&client&status` | Query log |
| `GET /api/timeseries?hours` | Allowed/blocked bucketed for charting |
| `GET /api/top-domains?hours&limit` · `top-blocked` · `top-clients` | Rankings |
| `GET /api/query-types?hours` | Breakdown by record type |
| `GET /api/devices` | Device inventory |
| `GET /api/interfaces?minutes` | Throughput samples |
| `POST`/`DELETE` `/api/deny` · `/api/allow` | `{"domain": "..."}` — applies immediately |
| `POST /api/reload` | Re-download blocklists |
| `POST /api/flush-cache` | Drop the DNS cache |

## Upgrading

Two defaults changed because the old ones were unsafe, not because the
behaviour was wrong for everyone. Both are one line to restore.

| Changed | Why | To restore the old behaviour |
|---|---|---|
| `web.listen` is now `127.0.0.1:8080` (was `0.0.0.0:8080`) | Unauthenticated endpoints that rewrite DNS policy were reachable from the whole LAN | Set `listen = "0.0.0.0:8080"` **and** an `admin_token` — see [Reaching it, safely](#reaching-it-safely) |
| `blocking.disable_firefox_doh` is new and defaults to `true` | Firefox's own DNS-over-HTTPS made its queries invisible, so the dashboard under-reported without saying so | Set `disable_firefox_doh = false` under `[blocking]` |
| `discovery.dhcp` is now `false` (was `true`) | A UDP/67 socket shares a reuseport group with any same-user DHCP server, and losing household DHCP is worse than losing hostnames | Set `dhcp = true` if nothing else on the Pi serves DHCP (`sudo ss -ulnp \| grep :67`) |

`cache_min_ttl` also changed meaning. It used to round short TTLs *up*, so a
5-second record was served for 30 — a cache handing out a longer life than the
authority granted. It is now a "don't cache anything shorter than this"
threshold. If you want the old (incorrect) caching of very short TTLs, set
`cache_min_ttl = 0` to cache them at their real TTL instead.

Databases created before this version keep SQLite's `auto_vacuum = NONE` and
cannot be switched in place, so pruning frees space inside the file without
shrinking it. The dashboard marks these "fixed size". To rebuild one (takes a
few minutes on an SD card, and DNS keeps working throughout because netwatch
reopens it afterwards):

```bash
sudo systemctl stop netwatch
sudo -u netwatch sqlite3 /var/lib/netwatch/netwatch.db "PRAGMA auto_vacuum=INCREMENTAL; VACUUM;"
sudo systemctl start netwatch
```

## Configuration

`/etc/netwatch/config.toml`, all keys optional — see
[`config.example.toml`](config.example.toml) for the full annotated set.
`netwatch --print-config` shows what is in effect.

**Always check the config before restarting.** netwatch is the whole network's
resolver, so a config it cannot parse takes DNS down for every device — and
systemd cannot recover from that, it just restarts into the same broken file:

```bash
sudo netwatch --config /etc/netwatch/config.toml --check-config \
  && sudo systemctl restart netwatch
```

`--check-config` exits 0 with `config OK`, or 1 with the parse or validation
error and the line it is on. The installer runs the same check and refuses to
restart a working service with a config that would not come back up.

Common adjustments:

```toml
[dns]
upstreams = ["9.9.9.9:53"]        # Quad9 also filters malware

[blocking]
mode = "nxdomain"                 # instead of answering 0.0.0.0
sources = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://adaway.org/hosts.txt",
]

[storage]
retention_days = 30               # longer history; a bigger database
```

Blocklists accept hosts format (`0.0.0.0 ads.example.com`) or a bare domain per
line. A leading `*.` makes a rule cover subdomains — `*.doubleclick.net`
matches `ads.doubleclick.net` but not the apex. Allow rules always win.

## Operating notes

**SD card wear.** Writes are batched into one transaction per 750 ms rather than
one per query, the query log is pruned hourly, and dense throughput samples are
kept for 3 days against the log's 14. If you are keeping this long-term, a USB
SSD is still kinder than an SD card.

**Storage.** Roughly 15 MB per million queries. A typical household generates
50k–200k lookups a day.

**Something went wrong:**

```bash
systemctl status netwatch
journalctl -u netwatch -f
journalctl -u netwatch -n 100 --no-pager
```

| Symptom | Cause |
|---|---|
| Won't start, "port 53 needs root" | `systemd-resolved` holds the port — see above |
| Dashboard empty | Devices aren't using the Pi for DNS yet |
| `0` blocked domains | First list download failed; check the log, then `POST /api/reload` |
| Devices show as `unnamed` | Normal for IoT gear that announces no name; the vendor column still identifies it |
| `mDNS discovery unavailable` | Avahi already owns port 5353. Harmless; DHCP and reverse DNS still name devices |
| One device logs nothing | It is probably using DoH or a hardcoded resolver — see [Devices can bypass you](#devices-that-bypass-you) and the dashboard's Bypass suspects panel |
| Restarting in a loop, or `Active: failed` after several tries | Almost always a bad config. `netwatch --check-config` names the line; `journalctl -u netwatch` shows the same error. systemd stops after 5 failed starts in 5 minutes rather than looping silently |

Run in the foreground to debug:

```bash
sudo systemctl stop netwatch
sudo RUST_LOG=netwatch=debug /usr/local/bin/netwatch --config /etc/netwatch/config.toml
```

## How it is built

```
src/
  main.rs        wiring: config, tasks, shutdown
  config.rs      TOML config with defaults for everything
  dns/mod.rs     the forwarder — UDP + TCP, blocking, upstream failover
  dns/cache.rs   TTL-aware answer cache
  blocklist.rs   list parsing and domain matching
  devices.rs     ARP / mDNS / DHCP / reverse-DNS device identification
  netinfo.rs     /proc and /sys parsing: routes, ARP, counters, Pi health
  monitor.rs     throughput and latency sampling
  db.rs          SQLite schema, batched writer, dashboard queries
  api.rs         HTTP API
  web/index.html the dashboard (single file, no external assets)
```

A few decisions worth explaining:

**DNS answering never touches the disk.** Query logs go over a bounded channel
to a dedicated writer thread that batches them into transactions. If that queue
ever saturates, log lines are dropped rather than delaying a DNS answer —
resolution latency is what everyone in the house feels.

**A fresh UDP socket per upstream query.** This gives source-port randomisation
for free, which is the main defence against off-path answer spoofing, and
replies whose transaction ID doesn't match are discarded.

**Two SQLite connections in WAL mode**, so the dashboard can read while the
writer commits. API reads run on the blocking pool, never on the async
executor that is also serving DNS.

**No libpcap, no netlink bindings.** Everything comes from `/proc` and ordinary
UDP sockets, which keeps the dependency tree small and the ARM cross-compile
straightforward.

**Device-supplied strings are validated before storage.** Hostnames from DHCP
and mDNS are attacker-controllable in principle, so they are length-capped and
restricted to hostname characters, and the dashboard escapes all interpolated
values.

## Development

```bash
cargo test          # 52 unit tests: protocol, ACL, parsers, matching, storage
cargo clippy --all-targets
cargo fmt

# Run locally on unprivileged ports, no root needed:
cargo run -- --dns-listen 127.0.0.1:5353 --web-listen 127.0.0.1:8080 \
             --database /tmp/netwatch.db --no-fetch
```

Tests cover the DNS truncation and EDNS paths, the client ACL (including that
it refuses the internet by default and will not silently widen an explicitly
narrow rule), blocklist parsing, wildcard matching and source attribution, DHCP
option parsing against malformed packets, `/proc` parsers with recorded
fixtures, MAC normalisation and randomisation detection, device name/MAC
correlation, and the storage invariants.

CI runs the same three checks on every push, plus a cross-compile check for
both Raspberry Pi targets — ARM is the deploy platform, so a break there
matters more than one on x86.

## License

MIT
