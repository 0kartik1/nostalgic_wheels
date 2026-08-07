# netwatch

[![CI](https://github.com/0kartik1/nostalgic_wheels/actions/workflows/ci.yml/badge.svg)](https://github.com/0kartik1/nostalgic_wheels/actions/workflows/ci.yml)

A network monitor and ad blocker for a Raspberry Pi on a home LAN, written in
Rust. It answers DNS for your network, logs every lookup with the device that
made it, blocks ad and tracker domains, and serves a live dashboard.

Single binary, no runtime dependencies. Measured resident memory: **17 MB** with
a 100,000-domain blocklist loaded, **10 MB** with blocking off.

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

**Devices can bypass you.** A device with a hardcoded DNS server, or using
DNS-over-HTTPS (most modern browsers, on by default in some), will not appear
in the log. Chrome and Firefox generally fall back to system DNS when the
network's resolver looks like a filtering one, but phones and smart TVs
sometimes ship their own. If a device shows suspiciously little traffic, that is
usually why.

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

```bash
sudo apt update && sudo apt install -y build-essential curl git pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

git clone https://github.com/0kartik1/nostalgic_wheels.git
cd nostalgic_wheels
cargo build --release
sudo ./deploy/install.sh
```

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

**There is no authentication.** Keep it on your LAN — do not port-forward it. To
reach it from outside, use a VPN such as WireGuard or Tailscale.

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

## Configuration

`/etc/netwatch/config.toml`, all keys optional — see
[`config.example.toml`](config.example.toml) for the full annotated set.
`systemctl restart netwatch` after editing, or `netwatch --print-config` to see
what is in effect.

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
| One device logs nothing | It is probably using DoH or a hardcoded resolver |

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
