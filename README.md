# tigernet

A lightweight network intrusion detection system (IDS) written in C using libpcap. It monitors live traffic on one or more network interfaces simultaneously and raises timestamped alerts when suspicious patterns are detected.

## Features at a glance

- Monitors **multiple interfaces** in parallel, each in its own thread
- Detects port scans, SYN floods, ICMP floods, UDP scans, Null scans, Xmas scans, and brute-force login attempts
- **Any TCP port** can be watched for brute-force attempts with a custom name and threshold
- Writes every alert to a **daily rotating log file** named `YYYYMMDD.log` in a configurable directory
- Fires a user-supplied **alert script** on every alert (double-forked, non-blocking)
- Includes **`alert_udp.sh`** — a ready-made script that sends JSON over UDP to any SIEM or log collector
- All thresholds configurable via **CLI flags** or a **config file**
- Alert output includes the interface name so multi-link traffic is easy to distinguish

---

## Detections

| Threat | How it works |
|---|---|
| **TCP port scan** | Tracks distinct destination ports per source IP within the sliding time window. Fires when the count exceeds the threshold. |
| **SYN flood** | Counts bare SYN packets (no ACK) per source IP. High rates indicate a DoS attempt. |
| **ICMP flood** | Counts ICMP packets per source IP. Excessive pings indicate a flood or sweep. |
| **UDP port scan** | Tracks distinct UDP destination ports per source IP, same bitset approach as TCP. |
| **TCP Null scan** | Any TCP packet with no flags set — used by scanners to fingerprint hosts and evade stateless firewalls. |
| **TCP Xmas scan** | TCP packet with FIN, PSH, and URG all set simultaneously — a classic stealth scanning technique. |
| **Brute-force (any port)** | Any TCP port can be watched. Each inbound SYN (no ACK) to a watched port counts as one login attempt. When the count exceeds the per-port threshold an alert fires, labelled with the service name you chose. SSH (port 22) and RDP (port 3389) are watched by default. |

Duplicate alerts are suppressed per source IP within each time window.

---

## Requirements

- Linux (uses `AF_PACKET` / libpcap raw socket capture)
- libpcap and pthreads development headers
- Root or `CAP_NET_RAW` to open raw capture sockets

```bash
sudo apt install libpcap-dev          # Debian / Ubuntu
sudo dnf install libpcap-devel        # Fedora / RHEL
sudo pacman -S libpcap                # Arch
```

---

## Build

```bash
make
```

Or manually:

```bash
gcc -O2 -Wall -Wextra -std=gnu11 -D_DEFAULT_SOURCE \
    -o tigernet tigernet.c -lpcap -lpthread
```

### Makefile targets

| Target | Command | Description |
|---|---|---|
| `all` | `make` | Compile `tigernet` |
| `clean` | `make clean` | Remove compiled binary |
| `install` | `sudo make install` | Install to `/usr/local/bin` |
| `uninstall` | `sudo make uninstall` | Remove from `/usr/local/bin` |

`PREFIX` and `DESTDIR` are respected for packaging (e.g. `make install PREFIX=$HOME/.local`).

---

## Usage

```
sudo ./tigernet [options]
```

### Options

| Short | Long | Description | Default |
|---|---|---|---|
| `-i <dev>` | `--interface <dev>` | Interface to monitor — **repeatable** | first available |
| `-w <sec>` | `--window <sec>` | Sliding time window in seconds | `10` |
| `-p <n>` | `--port-scan <n>` | TCP port-scan threshold (distinct ports/window) | `20` |
| `-s <n>` | `--syn-flood <n>` | SYN flood threshold (SYN packets/window) | `200` |
| `-c <n>` | `--icmp-flood <n>` | ICMP flood threshold (packets/window) | `100` |
| `-u <n>` | `--udp-scan <n>` | UDP port-scan threshold (distinct ports/window) | `30` |
| | `--watch <port:name:threshold>` | Watch a port for brute-force — **repeatable** | SSH:22:5, RDP:3389:5 |
| | `--alert-script <path>` | Script executed on every alert | none |
| | `--log-dir <dir>` | Directory for daily `YYYYMMDD.log` alert log files | `/var/log/tigernet` |
| `-v` | `--verbose` | Log every packet event to stdout | off |
| `-h` | `--help` | Show help and exit | |

### Examples

```bash
# Single interface, all defaults — logs go to /var/log/tigernet/
sudo ./tigernet -i eth0

# Monitor two interfaces simultaneously
sudo ./tigernet -i eth0 -i eth1

# Monitor three interfaces with a 60-second window
sudo ./tigernet -i eth0 -i eth1 -i wlan0 -w 60

# Write logs to a custom directory
sudo ./tigernet -i eth0 --log-dir /var/log/tigernet

# Log to a custom directory and send UDP alerts
export TIGERNET_UDP_HOST=10.0.0.1
export TIGERNET_UDP_PORT=5140
sudo -E ./tigernet -i eth0 -i eth1 \
    --log-dir /var/log/tigernet \
    --alert-script ./alert_udp.sh

# Custom brute-force watch ports with logging
sudo ./tigernet -i eth0 \
    --log-dir /var/log/tigernet \
    --watch 22:SSH:10 \
    --watch 3389:RDP:3 \
    --watch 5900:VNC:2 \
    --watch 5432:PostgreSQL:15

# Tight SSH threshold on a 60-second window, verbose
sudo ./tigernet -i eth0 -w 60 --watch 22:SSH:5 -v
```

---

## Monitoring multiple interfaces

Pass `-i` more than once to watch several interfaces at the same time:

```bash
sudo ./tigernet -i eth0 -i eth1 -i wlan0
```

You can also list them in the config file (see below). Each interface runs in its own capture thread. All threads share a single detection engine — the IP stats table and alert counters — protected by a mutex, so alerts are never duplicated across interfaces for the same source IP.

Every alert line includes an `if=` column showing which interface saw the traffic:

```
14:03:22 [ALERT] TCP PORT SCAN         src=192.168.1.42    if=eth0     30 distinct TCP ports in 10s window
14:03:44 [ALERT] SSH BRUTE-FORCE       src=203.0.113.7     if=eth1     11 attempts to SSH (port 22) in 60s window
```

The `TIGERNET_IFACE` environment variable is also passed to alert scripts so your script can route or tag alerts by interface.

Up to 16 interfaces can be monitored simultaneously (`maxInterfaces`).

---

## Daily alert log files

Every alert is appended to a log file in the log directory. A new file is created automatically when the date changes — no restart required.

### File naming

```
<logDir>/YYYYMMDD.log
```

For example, alerts on 22 April 2025 are written to `20250422.log`. The current day's filename is shown in the startup banner so you always know where to look.

### Default location

```
/var/log/tigernet/
```

Override with `--log-dir` or the `logDir` config key. The directory (including any intermediate directories) is created automatically at startup if it does not exist.

### Log format

Each line is tab-separated with a comment header on the first line of each new file:

```
# TIMESTAMP	TYPE	SRC_IP	IFACE	DETAIL
2025-04-22T14:03:22Z	TCP PORT SCAN	192.168.1.42	eth0	30 distinct TCP ports in 10s window
2025-04-22T14:03:44Z	SSH BRUTE-FORCE	203.0.113.7	eth1	11 attempts to SSH (port 22) in 60s window
2025-04-22T14:04:02Z	RDP BRUTE-FORCE	198.51.100.3	eth0	4 attempts to RDP (port 3389) in 60s window
```

Timestamps are UTC in ISO-8601 format. The tab-separated layout is easy to parse with `awk`, `cut`, `pandas`, or any log-analysis tool.

### Querying log files

```bash
# All SSH brute-force alerts today
grep 'SSH BRUTE-FORCE' /var/log/tigernet/$(date +%Y%m%d).log

# All alerts from a specific IP across all days
grep '203.0.113.7' /var/log/tigernet/*.log

# Count alerts by type for a given day
awk -F'\t' 'NR>1 {count[$2]++} END {for (t in count) print count[t], t}' \
    /var/log/tigernet/20250422.log | sort -rn

# Watch the live log file as alerts arrive
tail -f /var/log/tigernet/$(date +%Y%m%d).log
```

### Disabling log files

Set `logDir` to an empty string in the config file, or simply do not set it and remove the default by passing an empty value:

```ini
logDir =
```

If the directory cannot be created at startup, file logging is automatically disabled and a warning is printed — tigernet continues running normally.

---

## Watched ports (`--watch`)

Any TCP port can be watched for brute-force login attempts. The format is:

```
--watch <port>:<name>:<threshold>
```

| Field | Description |
|---|---|
| `port` | TCP port number (1–65535) |
| `name` | Service label used in alert messages |
| `threshold` | SYN attempts from one IP per window before alerting (default: `5`) |

`--watch` is repeatable. If a port is specified more than once the last definition wins. If no `--watch` flags and no `watch =` lines are present in the config file, tigernet defaults to watching SSH (22) and RDP (3389) at threshold 5.

```bash
# Replace defaults entirely
sudo ./tigernet --watch 22:SSH:10 --watch 3389:RDP:3

# Add database ports alongside SSH and RDP
sudo ./tigernet \
    --watch 22:SSH:5 \
    --watch 3389:RDP:5 \
    --watch 5432:PostgreSQL:10 \
    --watch 3306:MySQL:10 \
    --watch 27017:MongoDB:8
```

---

## Alert script

When `--alert-script` is set tigernet forks the script **asynchronously** for every alert using a double-fork + `setsid()`, so the packet capture loop is never blocked regardless of how slow or broken the script is. No zombie processes accumulate.

If the script path is not executable at startup tigernet prints a warning and continues.

### Environment variables passed to the script

| Variable | Example | Description |
|---|---|---|
| `TIGERNET_TYPE` | `SSH BRUTE-FORCE` | Alert category |
| `TIGERNET_SRC_IP` | `203.0.113.7` | Attacker IP address |
| `TIGERNET_DETAIL` | `11 attempts to SSH (port 22) in 60s window` | Detail message |
| `TIGERNET_TIMESTAMP` | `2025-04-22T14:03:44Z` | ISO-8601 UTC timestamp |
| `TIGERNET_HOSTNAME` | `webserver-1` | Hostname of the sensor |
| `TIGERNET_IFACE` | `eth1` | Interface that saw the traffic |

### alert_udp.sh

The included example script sends a compact JSON payload over UDP using either `socat` or `nc` (auto-detected):

```json
{
  "sensor": "webserver-1",
  "timestamp": "2025-04-22T14:03:44Z",
  "iface": "eth1",
  "type": "SSH BRUTE-FORCE",
  "src_ip": "203.0.113.7",
  "detail": "11 attempts to SSH (port 22) in 60s window"
}
```

Configure the destination before starting tigernet:

| Variable | Default | Description |
|---|---|---|
| `TIGERNET_UDP_HOST` | `127.0.0.1` | Destination host or IP |
| `TIGERNET_UDP_PORT` | `5140` | Destination UDP port |
| `TIGERNET_UDP_TOOL` | auto | Force `nc` or `socat` |

```bash
export TIGERNET_UDP_HOST=10.0.0.1
export TIGERNET_UDP_PORT=5140
sudo -E ./tigernet -i eth0 --alert-script ./alert_udp.sh
```

Receiving alerts:

```bash
socat UDP-RECV:5140 STDOUT          # continuous listener
nc -u -l 5140                       # one-shot listener
tcpdump -i lo udp port 5140 -A      # raw packet view
```

### Writing your own script

Any executable works — bash, Python, Ruby, a compiled binary. A minimal file-logger:

```bash
#!/usr/bin/env bash
printf '%s [%s] src=%s if=%s %s\n' \
    "$TIGERNET_TIMESTAMP" "$TIGERNET_TYPE" \
    "$TIGERNET_SRC_IP" "$TIGERNET_IFACE" \
    "$TIGERNET_DETAIL" >> /var/log/tigernet_alerts.log
```

---

## Configuration file

tigernet reads `~/.tigernet/tigernet.conf` before applying command-line flags. On the first run the file is created automatically with all keys commented out as a reference.

### Location

```
~/.tigernet/tigernet.conf
```

### Format

Plain text, one `key = value` pair per line. Lines beginning with `#` are comments. Whitespace around `=` is ignored. `interface` and `watch` keys are repeatable.

```ini
# tigernet configuration file

# Monitor multiple interfaces — one line per interface
interface   = eth0
interface   = eth1

window      = 60
portScan    = 20
synFlood    = 200
icmpFlood   = 100
udpScan     = 30
alertScript = /etc/tigernet/alert_udp.sh
logDir      = /var/log/tigernet
verbose     = false

# Brute-force watched ports — format: watch = <port>:<name>:<threshold>
watch = 22:SSH:10
watch = 3389:RDP:5
watch = 5900:VNC:3
watch = 23:Telnet:4
watch = 5432:PostgreSQL:15
```

### Config keys

| Key | Type | Repeatable | Description |
|---|---|---|---|
| `interface` | string | yes | Network interface to monitor |
| `window` | integer | no | Sliding time window in seconds |
| `portScan` | integer | no | TCP port-scan alert threshold |
| `synFlood` | integer | no | SYN flood alert threshold |
| `icmpFlood` | integer | no | ICMP flood alert threshold |
| `udpScan` | integer | no | UDP port-scan alert threshold |
| `alertScript` | path | no | Script to execute on every alert |
| `logDir` | path | no | Directory for daily `YYYYMMDD.log` files (default: `/var/log/tigernet`) |
| `watch` | `port:name:threshold` | yes | Add or update a watched brute-force port |
| `verbose` | boolean | no | `true`, `yes`, or `1` to enable verbose output |

### Priority order

```
built-in defaults  <  tigernet.conf  <  command-line flags
```

CLI flags always win. `--watch` and `-i` on the command line add to (or override) entries from the config file.

---

## Alert output format

```
HH:MM:SS [ALERT] <type>                src=<ip>            if=<iface>  <detail>
```

Example output with two interfaces active:

```
14:03:22 [ALERT] TCP PORT SCAN         src=192.168.1.42    if=eth0     30 distinct TCP ports in 10s window
14:03:25 [ALERT] SYN FLOOD             src=10.0.0.5        if=eth0     204 SYN packets in 10s window
14:03:31 [ALERT] TCP XMAS SCAN         src=192.168.1.99    if=eth1     TCP Xmas scan → port 443
14:03:44 [ALERT] SSH BRUTE-FORCE       src=203.0.113.7     if=eth1     11 attempts to SSH (port 22) in 60s window
14:03:51 [ALERT] RDP BRUTE-FORCE       src=198.51.100.3    if=eth0     4 attempts to RDP (port 3389) in 60s window
14:04:02 [ALERT] PostgreSQL BRUTE-FORCE  src=10.0.0.8      if=eth1     12 attempts to PostgreSQL (port 5432) in 60s window
```

---

## Files

| File | Description |
|---|---|
| `tigernet.c` | Main source — IDS engine with multi-interface threading and log file support |
| `alert_udp.sh` | Example alert script — sends JSON over UDP |
| `Makefile` | Build, install, and uninstall targets |
| `~/.tigernet/tigernet.conf` | Per-user config file (auto-created on first run) |
| `/var/log/tigernet/YYYYMMDD.log` | Daily alert log files (default location) |

---

## Implementation notes

- Each interface runs in its own **POSIX thread** (`pthread_create`). All threads share one IP stats table and alert counter, protected by `pthread_mutex_t`. The mutex is held only for the duration of single-packet processing.
- Alert log files are opened, written, and **closed per alert** — no file descriptor stays open. This means midnight rotation (new date → new filename) is fully automatic with no timer or signal needed.
- The log directory is created recursively at startup if it does not exist. If creation fails, file logging is disabled gracefully and tigernet continues running.
- Packets are captured via libpcap in **promiscuous mode**, so tigernet sees all frames on the wire, not just traffic addressed to the host.
- Per-source-IP state is stored in a **hash table** (4096 buckets, chained). Port tracking uses a **bitset** across all 65 536 ports — marking a port is O(1) with no per-packet allocation.
- Alert scripts run via **double-fork + `setsid()`** — the capture loop is never blocked, no zombies accumulate, and the script is detached from any controlling terminal.
- Brute-force counters and alert-suppression flags are arrays parallel to `watchPorts[]`; adding a watched port requires no changes to detection logic.
- The sliding window is reset **lazily** — on the first packet that arrives after the window has elapsed, rather than on a timer.
- Null and Xmas scans fire **immediately** on every matching packet, regardless of rate.
- Ctrl+C sends `pcap_breakloop()` to every open handle; all capture threads exit cleanly before `pthread_join` collects them.

---

## Limitations

- IPv4 only — IPv6 packets are skipped.
- Ethernet framing assumed; other link layers (loopback, PPP) are not handled.
- Detection is purely **signature / threshold-based** — no statistical baselining or machine learning.
- Up to **16 interfaces** and **64 watched ports** simultaneously (adjustable via `maxInterfaces` and `maxWatchPorts` at compile time).
- Log files are plain text and grow unbounded within a day; add a cron job or logrotate rule if disk space is a concern.
- tigernet is a learning and monitoring tool. For production use consider Suricata or Zeek.

---

## License

MIT — do whatever you like, attribution appreciated.
