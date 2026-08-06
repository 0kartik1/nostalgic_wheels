#!/usr/bin/env bash
# pi-audit.sh - read-only Raspberry Pi audit for power/performance tuning.
#
# Collects hardware, thermal, power, storage, service and network state into a
# single report. Changes nothing on the system.
#
#   ./pi-audit.sh                 # report to stdout
#   ./pi-audit.sh -o report.txt   # report to a file
#
# Runs fine unprivileged; a few sections need root and are skipped with a note
# if unavailable. Re-run under sudo for the complete picture.

set -uo pipefail

OUT=""
while getopts ":o:h" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    h) sed -n '2,13p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "usage: $0 [-o outfile]" >&2; exit 2 ;;
  esac
done

[ -n "$OUT" ] && exec > >(tee "$OUT")

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }

section() {
  printf '\n\n===============================================================\n'
  printf '  %s\n' "$1"
  printf '===============================================================\n'
}

# Run a command, or explain why we couldn't.
try() {
  local label="$1"; shift
  printf '\n--- %s ---\n' "$label"
  if ! have "$1"; then
    printf '(skipped: %s not installed)\n' "$1"
    return
  fi
  "$@" 2>&1 || printf '(command exited %d)\n' "$?"
}

# Dump a file if it exists.
show() {
  printf '\n--- %s ---\n' "$1"
  if [ -r "$1" ]; then
    tr -d '\0' < "$1"
    printf '\n'
  else
    printf '(not readable or does not exist)\n'
  fi
}

printf 'Raspberry Pi audit - %s\n' "$(date -Is)"
printf 'host=%s  user=%s  root=%s\n' "$(hostname)" "$(id -un)" "$(is_root && echo yes || echo no)"

# --------------------------------------------------------------------------
section "1. HARDWARE / OS IDENTITY"
# Model and SoC determine which tuning knobs exist at all: a Pi 5 has a power
# button and PCIe, a Pi 4 has neither, a Pi Zero has a different governor set.

show /proc/device-tree/model
show /etc/os-release
try "kernel" uname -a
printf '\n--- userland bitness ---\n'
printf 'dpkg arch: %s\n' "$(dpkg --print-architecture 2>/dev/null || echo unknown)"
printf 'kernel arch: %s\n' "$(uname -m)"
try "cpu" lscpu
printf '\n--- cpuinfo (revision/serial) ---\n'
grep -E 'Revision|Hardware|Model' /proc/cpuinfo 2>/dev/null || echo '(none)'
printf '\n--- uptime / load ---\n'
uptime
show /sys/firmware/devicetree/base/chosen/bootloader-version

# --------------------------------------------------------------------------
section "2. POWER, THERMAL AND THROTTLING"
# The single most important section. Undervoltage and thermal throttling both
# silently cap performance, and both are invisible unless you ask for them.

if have vcgencmd; then
  printf '\n--- throttle flags ---\n'
  raw="$(vcgencmd get_throttled 2>/dev/null)"
  printf '%s\n' "$raw"
  hex="${raw#throttled=}"
  if [ -n "$hex" ] && [ "$hex" != "$raw" ]; then
    v=$((hex))
    printf '\ndecoded:\n'
    bit() { [ $(( (v >> $1) & 1 )) -eq 1 ] && printf '  [X] %s\n' "$2" || printf '  [ ] %s\n' "$2"; }
    bit 0  "under-voltage detected (NOW)"
    bit 1  "arm frequency capped (NOW)"
    bit 2  "currently throttled (NOW)"
    bit 3  "soft temperature limit active (NOW)"
    bit 16 "under-voltage has occurred since boot"
    bit 17 "arm frequency capping has occurred since boot"
    bit 18 "throttling has occurred since boot"
    bit 19 "soft temperature limit has occurred since boot"
    printf '\nAny NOW flag = fix the power supply or cooling before tuning anything else.\n'
  fi

  printf '\n--- temperature ---\n'
  vcgencmd measure_temp 2>&1

  printf '\n--- clocks (Hz) ---\n'
  for c in arm core h264 isp v3d hevc emmc pixel; do
    printf '%-8s %s\n' "$c" "$(vcgencmd measure_clock "$c" 2>/dev/null | cut -d= -f2)"
  done

  printf '\n--- voltages ---\n'
  for d in core sdram_c sdram_i sdram_p; do
    printf '%-10s %s\n' "$d" "$(vcgencmd measure_volts "$d" 2>/dev/null | cut -d= -f2)"
  done

  printf '\n--- firmware ---\n'
  vcgencmd version 2>&1
  printf '\n--- gpu/cpu memory split ---\n'
  vcgencmd get_mem arm 2>&1
  vcgencmd get_mem gpu 2>&1
else
  printf '\n(vcgencmd not found - not a Pi, or raspi-utils not installed)\n'
fi

printf '\n--- thermal zones ---\n'
for z in /sys/class/thermal/thermal_zone*; do
  [ -r "$z/temp" ] || continue
  printf '%s: %s = %s mC\n' "$(basename "$z")" "$(cat "$z/type" 2>/dev/null)" "$(cat "$z/temp")"
done

printf '\n--- cooling devices (fan) ---\n'
for c in /sys/class/thermal/cooling_device*; do
  [ -r "$c/type" ] || continue
  printf '%s: %s  state=%s/%s\n' "$(basename "$c")" "$(cat "$c/type" 2>/dev/null)" \
    "$(cat "$c/cur_state" 2>/dev/null)" "$(cat "$c/max_state" 2>/dev/null)"
done

# --------------------------------------------------------------------------
section "3. CPU FREQUENCY AND GOVERNOR"
# governor=ondemand saves power at idle; performance pins max clock and costs
# a few hundred mW. Which is right depends entirely on the workload.

for p in /sys/devices/system/cpu/cpu[0-9]*/cpufreq; do
  [ -d "$p" ] || continue
  cpu="$(basename "$(dirname "$p")")"
  printf '%s: gov=%-12s cur=%-9s min=%-9s max=%s\n' "$cpu" \
    "$(cat "$p/scaling_governor" 2>/dev/null)" \
    "$(cat "$p/scaling_cur_freq" 2>/dev/null)" \
    "$(cat "$p/scaling_min_freq" 2>/dev/null)" \
    "$(cat "$p/scaling_max_freq" 2>/dev/null)"
done
show /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors
show /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies

printf '\n--- time spent per frequency (cpu0) ---\n'
cat /sys/devices/system/cpu/cpu0/cpufreq/stats/time_in_state 2>/dev/null \
  || echo '(cpufreq stats not available)'

# --------------------------------------------------------------------------
section "4. MEMORY AND SWAP"
# Swapping to an SD card is brutally slow and wears the card. zram is usually
# the better answer on a Pi.

try "memory" free -h
show /proc/swaps
printf '\n--- swappiness / dirty ratios ---\n'
for k in vm.swappiness vm.vfs_cache_pressure vm.dirty_ratio vm.dirty_background_ratio; do
  printf '%s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo '?')"
done
printf '\n--- zram ---\n'
if [ -e /sys/block/zram0 ]; then
  zramctl 2>/dev/null || echo '(zram0 exists; zramctl unavailable)'
else
  echo '(no zram configured)'
fi
show /etc/dphys-swapfile

printf '\n--- top 15 by memory ---\n'
ps -eo pid,ppid,user,%mem,%cpu,rss,comm --sort=-%mem 2>/dev/null | head -16

# --------------------------------------------------------------------------
section "5. STORAGE AND I/O"
# SD card vs USB SSD vs NVMe is often the real performance ceiling, not the CPU.

try "block devices" lsblk -o NAME,SIZE,TYPE,TRAN,ROTA,MOUNTPOINT,FSTYPE
try "disk usage" df -hT
show /etc/fstab
printf '\n--- mount options (real filesystems) ---\n'
findmnt -t ext4,ext3,vfat,btrfs,xfs,f2fs -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null \
  || mount | grep -E 'ext4|vfat|btrfs|xfs|f2fs'

printf '\n--- I/O scheduler per device ---\n'
for q in /sys/block/*/queue/scheduler; do
  [ -r "$q" ] || continue
  printf '%-12s %s\n' "$(echo "$q" | cut -d/ -f4)" "$(cat "$q")"
done

printf '\n--- SD card health / lifetime ---\n'
for d in /sys/block/mmcblk*/device; do
  [ -d "$d" ] || continue
  # life_time is two hex values (SLC/MLC wear); 0x01 = <10% used, 0x0b = >100%.
  # pre_eol_info: 0x01 normal, 0x02 warning (80% reserve used), 0x03 urgent.
  printf '%s: name=%s life_time=%s pre_eol=%s\n' "$d" \
    "$(cat "$d/name" 2>/dev/null)" \
    "$(cat "$d/life_time" 2>/dev/null)" \
    "$(cat "$d/pre_eol_info" 2>/dev/null)"
done

try "io pressure" cat /proc/pressure/io
try "iostat" iostat -x 1 2

# --------------------------------------------------------------------------
section "6. BOOT CONFIGURATION"
# config.txt is where overclocking, HDMI, and hardware-disable knobs live.

for f in /boot/firmware/config.txt /boot/config.txt; do
  [ -r "$f" ] && { show "$f"; break; }
done
for f in /boot/firmware/cmdline.txt /boot/cmdline.txt; do
  [ -r "$f" ] && { show "$f"; break; }
done
printf '\n--- EEPROM config (Pi 4/5 power behaviour) ---\n'
if have rpi-eeprom-config; then
  rpi-eeprom-config 2>&1
else
  echo '(rpi-eeprom-config not available)'
fi

# --------------------------------------------------------------------------
section "7. SERVICES AND BOOT COST"
# Idle services are the cheapest performance and power win: every daemon you
# don't need is RAM you get back and wakeups the CPU doesn't take.

try "failed units" systemctl --no-pager --failed
printf '\n--- enabled services ---\n'
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null

printf '\n--- running services ---\n'
systemctl list-units --type=service --state=running --no-pager 2>/dev/null

try "boot time" systemd-analyze
try "boot blame (top 20)" systemd-analyze blame
printf '\n--- graphical target? ---\n'
systemctl get-default 2>/dev/null

printf '\n--- top 15 by CPU ---\n'
ps -eo pid,ppid,user,%cpu,%mem,etime,comm --sort=-%cpu 2>/dev/null | head -16

printf '\n--- interrupts/wakeups (top sources) ---\n'
head -1 /proc/interrupts 2>/dev/null
sort -k2 -nr /proc/interrupts 2>/dev/null | head -12

# --------------------------------------------------------------------------
section "8. NETWORK AND RADIOS"
# WiFi power-save trades latency for milliwatts. Unused radios are free savings.

try "interfaces" ip -br addr
try "link details" ip -s link
printf '\n--- wifi power save ---\n'
if have iw; then
  for i in $(ls /sys/class/net 2>/dev/null); do
    [ -d "/sys/class/net/$i/wireless" ] || continue
    printf '%s: %s\n' "$i" "$(iw dev "$i" get power_save 2>&1)"
    iw dev "$i" link 2>&1 | sed 's/^/    /'
  done
else
  echo '(iw not installed)'
fi
printf '\n--- ethernet link speed ---\n'
if have ethtool; then
  for i in $(ls /sys/class/net 2>/dev/null); do
    case "$i" in lo|wl*) continue ;; esac
    printf '%s: %s\n' "$i" "$(ethtool "$i" 2>/dev/null | grep -E 'Speed|Duplex' | tr '\n' ' ')"
  done
else
  echo '(ethtool not installed)'
fi
printf '\n--- bluetooth ---\n'
systemctl is-enabled bluetooth 2>/dev/null; systemctl is-active bluetooth 2>/dev/null
have hciconfig && hciconfig -a 2>&1 | head -20

# --------------------------------------------------------------------------
section "9. PERIPHERALS AND EXTERNAL LOAD"
# USB devices draw real power from the same supply that feeds the SoC.

try "usb tree" lsusb -t
try "usb devices" lsusb
try "pci" lspci
printf '\n--- HDMI / display state ---\n'
for d in /sys/class/drm/card*/status; do
  [ -r "$d" ] && printf '%s: %s\n' "$(echo "$d" | cut -d/ -f5)" "$(cat "$d")"
done
if have vcgencmd; then
  printf 'display_power: %s\n' "$(vcgencmd display_power 2>&1)"
fi

# --------------------------------------------------------------------------
section "10. LOGGING AND BACKGROUND CHURN"
# Chatty logs to an SD card cost both write endurance and idle wakeups.

try "journal size" journalctl --disk-usage
show /etc/systemd/journald.conf
printf '\n--- timers ---\n'
systemctl list-timers --all --no-pager 2>/dev/null | head -25
printf '\n--- cron ---\n'
if have crontab; then crontab -l 2>&1 | head -20; else echo '(cron not installed)'; fi
ls -la /etc/cron.d/ 2>/dev/null

printf '\n--- containers (if any) ---\n'
if have docker; then docker ps -a 2>&1 | head -20; else echo '(docker not installed)'; fi

# --------------------------------------------------------------------------
section "11. RECENT KERNEL COMPLAINTS"
# Undervoltage, SD errors and OOM kills all land here.

printf '\n--- power/thermal/storage/OOM messages ---\n'
if is_root || [ -r /var/log/kern.log ]; then
  journalctl -k -p warning --no-pager -n 200 2>/dev/null \
    | grep -iE 'voltage|throttl|thermal|mmc|oom|i/o error|reset|firmware' \
    | tail -40 || echo '(none found)'
else
  dmesg 2>/dev/null | grep -iE 'voltage|throttl|thermal|mmc|oom|i/o error' | tail -40 \
    || echo '(needs root: re-run with sudo for kernel log)'
fi

printf '\n\n=== END OF REPORT ===\n'
[ -n "$OUT" ] && printf 'Saved to %s\n' "$OUT" >&2
exit 0
