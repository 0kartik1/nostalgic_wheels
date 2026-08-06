# Raspberry Pi power/performance audit

`pi-audit.sh` collects everything needed to tune a Pi for either low idle power
or maximum sustained throughput. It is **read-only** — it changes no config,
installs nothing, and starts no services.

## Running it

On the Pi:

```sh
curl -fsSLO <this-file-url>   # or scp it across
chmod +x pi-audit.sh
sudo ./pi-audit.sh -o pi-report.txt
```

`sudo` is optional but gets you the kernel log section, which is where
undervoltage and SD-card I/O errors show up. Without it that section is skipped
and everything else still works.

Then send back `pi-report.txt`.

## What it collects

| # | Section | Why it matters |
|---|---------|----------------|
| 1 | Hardware / OS identity | Model and SoC decide which knobs exist. A 32-bit userland on a 64-bit Pi leaves measurable performance unclaimed. |
| 2 | Power, thermal, throttling | `get_throttled` flags, decoded. Undervoltage and thermal capping are the two most common causes of "my Pi is slow" and both are silent. |
| 3 | CPU governor | The core energy-vs-speed tradeoff, and where per-frequency residency shows what the Pi actually does all day. |
| 4 | Memory and swap | Swapping to SD is slow and destroys cards. zram is usually the better answer. |
| 5 | Storage and I/O | SD vs USB SSD vs NVMe is frequently the real ceiling, not the CPU. Includes SD wear-level registers. |
| 6 | Boot configuration | `config.txt`, `cmdline.txt`, EEPROM — overclock, HDMI, and hardware-disable settings. |
| 7 | Services and boot cost | Idle daemons are the cheapest win available: RAM back, wakeups gone. |
| 8 | Network and radios | WiFi power-save trades latency for milliwatts. Unused radios are free savings. |
| 9 | Peripherals | USB devices draw from the same supply that feeds the SoC. |
| 10 | Logging and timers | Chatty logs cost both write endurance and idle wakeups. |
| 11 | Kernel complaints | Undervoltage, SD errors, OOM kills. |

## Note on the goal

"Energy saving" and "maximum performance" pull in opposite directions on a Pi —
the governor, the clock ceiling, and WiFi power-save each trade one against the
other directly. There is no single config that wins both.

What isn't a tradeoff, and is worth doing under either goal:

- Removing services you don't use — less RAM, fewer wakeups, faster boot.
- Fixing undervoltage — it costs power *and* caps clocks.
- Adequate cooling — a throttling Pi is both slow and no more efficient.
- Moving the root filesystem off a slow SD card.
- Getting swap under control.

Everything past that depends on the workload. The report answers which
category this Pi is in.
