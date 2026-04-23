# tigernet

A lightweight network intrusion detection system (IDS) written in C using libpcap. It monitors live traffic on one or more network interfaces simultaneously and raises timestamped alerts when suspicious patterns are detected.

## Features at a glance

- Monitors **multiple interfaces** in parallel, each in its own thread
- Detects **28 distinct threat categories** across scanning, flooding, amplification, spoofing, and application-layer attacks
- **Any TCP port** can be watched for brute-force attempts with a custom name and threshold
- Writes every alert to a **daily rotating log file** named `YYYYMMDD.log` in `/var/log/tigernet`
- Fires a user-supplied **alert script** on every alert (double-forked, non-blocking)
- Includes **`alert_udp.sh`** — a ready-made script that sends JSON over UDP to any SIEM or log collector
- All thresholds configurable via **CLI flags** or a **config file**

---

## Detections

### Scanning & reconnaissance

| Threat | How it works |
|---|---|
| **TCP port scan** | Tracks distinct TCP destination ports per source IP within the time window. |
| **UDP port scan** | Same bitset approach for UDP destination ports. |
| **TCP Null scan** | TCP packet with no flags set — evades many stateless firewalls. |
| **TCP Xmas scan** | FIN+PSH+URG simultaneously — classic stealth scanning. |
| **TCP FIN scan** | Only FIN set — another stealth variant used to map open ports. |
| **TCP ACK scan** | Only ACK set — used to map firewall rules rather than open ports. |
| **TCP Maimon scan** | FIN+ACK — a lesser-known stealth scan variant. |
| **OS fingerprint probe** | TCP SYN with zero window size — the signature of `nmap -O` OS detection. |
| **Ping sweep** | Tracks distinct destination IPs in ICMP echo requests. Many targets from one source indicates host discovery across a subnet. |

### Flood & DoS

| Threat | How it works |
|---|---|
| **SYN flood** | Bare SYN packets (no ACK) at high rate — classic DoS handshake exhaustion. |
| **ICMP flood** | High rate of ICMP from one source. |
| **UDP flood** | High rate of UDP packets from one source (distinct from port scan). |
| **TCP RST flood** | High rate of RST packets — used to tear down existing connections. |
| **TCP FIN flood** | High rate of FIN-only packets — a quieter session-teardown DoS. |
| **ICMP fragment flood** | ICMP packets with the More Fragments (MF) bit set — exhausts reassembly buffers. |
| **IP fragment flood** | Any IP packet with MF bit or non-zero fragment offset at high rate — evades some IDS and exhausts reassembly. |
| **SMB exploit probe** | SYN burst to port 445 — EternalBlue-style scanning for unpatched SMB. |

### Amplification & reflection

| Threat | How it works |
|---|---|
| **DNS amplification** | High rate of small UDP packets to port 53 — the most common DDoS amplifier. |
| **NTP amplification** | High rate of UDP packets to port 123. |
| **SSDP amplification** | High rate of UDP packets to port 1900 — used in IoT-based DDoS. |

### Spoofing & anomalies

| Threat | How it works |
|---|---|
| **Land attack** | TCP SYN where source IP equals destination IP — crashes vulnerable TCP stacks. |
| **Smurf indicator** | ICMP echo request to a broadcast or multicast destination — sign of amplification setup. |
| **Bogon source IP** | Packet from RFC 1918 private space, loopback (127.x), or APIPA (169.254.x) arriving on the wire — strong sign of spoofing. |
| **Martian packet** | Packet from reserved/unallocated IP space (240.0.0.0/4, multicast 224/8, or 255.255.255.255). |

### Application-layer probes

| Threat | How it works |
|---|---|
| **HTTP directory traversal** | TCP payload on port 80/443/8080 containing `../` — path traversal / LFI attempt. |
| **HTTP scanner** | Common scanner User-Agent strings in HTTP payload: Nikto, sqlmap, Masscan, ZGrab, Nmap, dirbuster, gobuster, nuclei. |

### Brute-force (any port)

Any TCP port can be watched. Each inbound SYN (no ACK) to a watched port counts as one login attempt. SSH (22) and RDP (3389) are watched by default.

---

Duplicate alerts are suppressed per source IP within each time window. Land attacks, bogon/martian packets, Smurf indicators, and application-layer probes fire immediately on every matching packet.

---

## Requirements

- Linux (`AF_PACKET` / libpcap raw socket capture)
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

---

## Usage

```
sudo ./tigernet [options]
```

### Options

| Short | Long | Description | Default |
|---|---|---|---|
| `-i <dev>` | `--interface <dev>` | Interface — **repeatable** | first available |
| `-w <sec>` | `--window <sec>` | Time window in seconds | `10` |
| `-p <n>` | `--port-scan <n>` | TCP port-scan threshold | `20` |
| `-s <n>` | `--syn-flood <n>` | SYN flood threshold | `200` |
| `-c <n>` | `--icmp-flood <n>` | ICMP flood threshold | `100` |
| `-u <n>` | `--udp-scan <n>` | UDP port-scan threshold | `30` |
| | `--udp-flood <n>` | UDP flood threshold | `500` |
| | `--rst-flood <n>` | TCP RST flood threshold | `200` |
| | `--fin-flood <n>` | TCP FIN flood threshold | `200` |
| | `--ping-sweep <n>` | Ping sweep threshold (distinct dst IPs) | `20` |
| | `--dns-amp <n>` | DNS amplification threshold | `100` |
| | `--ntp-amp <n>` | NTP amplification threshold | `50` |
| | `--ssdp-amp <n>` | SSDP amplification threshold | `50` |
| | `--frag-flood <n>` | IP fragment flood threshold | `100` |
| | `--no-bogon` | Disable bogon/martian/smurf checks on **all** interfaces | off |
| | `--internal-iface <dev>` | Suppress bogon/martian/smurf on one interface — **repeatable** | none |
| | `--no-ack-scan` | Disable TCP ACK scan detection globally | off |
| | `--no-fin-scan` | Disable TCP FIN scan detection globally | off |
| | `--no-maimon-scan` | Disable TCP Maimon scan detection globally | off |
| | `--no-os-fingerprint` | Disable OS fingerprint probe detection globally | off |
| | `--iface-no-ack-scan <dev>` | Suppress ACK scan on one interface — **repeatable** | none |
| | `--iface-no-fin-scan <dev>` | Suppress FIN scan on one interface — **repeatable** | none |
| | `--iface-no-maimon <dev>` | Suppress Maimon scan on one interface — **repeatable** | none |
| | `--iface-no-os-fp <dev>` | Suppress OS fingerprint on one interface — **repeatable** | none |
| | `--watch <port:name:thr>` | Watch port for brute-force — **repeatable** | SSH:22:5, RDP:3389:5 |
| | `--alert-script <path>` | Script executed on every alert | none |
| | `--log-dir <dir>` | Directory for daily `YYYYMMDD.log` files | `/var/log/tigernet` |
| `-v` | `--verbose` | Log every packet event | off |
| `-h` | `--help` | Show help and exit | |

### Examples

```bash
# Monitor one interface with all defaults
sudo ./tigernet -i eth0

# Monitor two interfaces simultaneously
sudo ./tigernet -i eth0 -i eth1

# Aggressive thresholds for a quiet network
sudo ./tigernet -i eth0 -w 30 --syn-flood 20 --ping-sweep 5

# Custom brute-force watch ports
sudo ./tigernet -i eth0 \
    --watch 22:SSH:5 \
    --watch 3389:RDP:3 \
    --watch 5432:PostgreSQL:10

# Full setup with logging and UDP alerts
export TIGERNET_UDP_HOST=10.0.0.1
export TIGERNET_UDP_PORT=5140
sudo -E ./tigernet -i eth0 -i eth1 \
    --log-dir /var/log/tigernet \
    --alert-script ./alert_udp.sh
```

---

## Monitoring multiple interfaces

Pass `-i` more than once. Each interface runs in its own capture thread sharing one detection engine (mutex-protected). Every alert line shows which interface saw the traffic:

```
14:03:44 [ALERT] SSH BRUTE-FORCE           src=203.0.113.7     if=eth1   11 attempts in 60s window
14:03:51 [ALERT] BOGON SOURCE              src=192.168.1.5     if=eth0   RFC-1918 source on wire
```

Up to 16 interfaces simultaneously (`maxInterfaces`).

---

## Suppressing false-positive alerts on internal interfaces

On a local network several detections generate false-positives for completely normal traffic:

| Alert | Why it fires on a LAN | Safe to suppress? |
|---|---|---|
| **BOGON SOURCE** | RFC 1918 addresses are normal on internal networks | Yes |
| **MARTIAN PACKET** | Private space is expected locally | Yes |
| **SMURF INDICATOR** | Broadcast pings are normal on a LAN | Yes |
| **TCP ACK SCAN** | Bare ACKs are sent for every acknowledged segment | Yes |
| **TCP FIN SCAN** | FIN-only packets appear during connection teardown | Yes |
| **TCP MAIMON SCAN** | FIN+ACK is the normal second step of connection teardown | Yes |
| **OS FINGERPRINT PROBE** | Zero-window SYNs occur with some overloaded TCP stacks | Yes |

Each can be suppressed **globally** (all interfaces) or **per interface**, so you can still catch them on an internet-facing link while ignoring them on the LAN.

The **land-attack** check (`src IP == dst IP`) always runs regardless of any suppress flag.

The startup banner shows which checks are globally disabled or suppressed per interface.

### Bogon / martian / smurf

```bash
# Disable on all interfaces
sudo ./tigernet -i eth0 --no-bogon

# Disable on the LAN interface only, keep active on eth0
sudo ./tigernet -i eth0 -i eth1 --internal-iface eth1
```

```ini
# tigernet.conf
noBogon       = true    # global
internalIface = eth1    # per-interface (repeatable)
```

### ACK scan, FIN scan, Maimon scan, OS fingerprint probe

Each has its own flag:

```bash
# Suppress all four globally
sudo ./tigernet -i eth0 \
    --no-ack-scan \
    --no-fin-scan \
    --no-maimon-scan \
    --no-os-fingerprint

# Suppress all four on the LAN interface only, keep them on eth0
sudo ./tigernet -i eth0 -i eth1 \
    --iface-no-ack-scan eth1 \
    --iface-no-fin-scan eth1 \
    --iface-no-maimon   eth1 \
    --iface-no-os-fp    eth1
```

```ini
# tigernet.conf — global disable
noAckScan       = true
noFinScan       = true
noMaimonScan    = true
noOsFingerprint = true

# tigernet.conf — per-interface disable (repeatable)
ifaceNoAckScan  = eth1
ifaceNoFinScan  = eth1
ifaceNoMaimon   = eth1
ifaceNoOsFp     = eth1
```

### Typical LAN-only setup

```ini
interface       = eth0
noBogon         = true
noAckScan       = true
noFinScan       = true
noMaimonScan    = true
noOsFingerprint = true
```

### Mixed internal + internet-facing setup

```ini
interface       = eth0          # internet-facing — full detection
interface       = eth1          # internal LAN
internalIface   = eth1
ifaceNoAckScan  = eth1
ifaceNoFinScan  = eth1
ifaceNoMaimon   = eth1
ifaceNoOsFp     = eth1
```

---

## Daily alert log files

Every alert is appended to `<logDir>/YYYYMMDD.log`. A new file is created automatically at midnight — no restart required.

### Default location

```
/var/log/tigernet/
```

Override with `--log-dir` or the `logDir` config key. The directory is created recursively at startup if it does not exist.

### Log format

Tab-separated, with a header on the first line of each new file:

```
# TIMESTAMP	TYPE	SRC_IP	IFACE	DETAIL
2025-04-22T14:03:22Z	TCP PORT SCAN	192.168.1.42	eth0	30 distinct TCP ports in 10s window
2025-04-22T14:03:44Z	SSH BRUTE-FORCE	203.0.113.7	eth1	11 attempts to SSH (port 22) in 60s window
2025-04-22T14:03:51Z	BOGON SOURCE	192.168.1.5	eth0	RFC-1918 source on wire
2025-04-22T14:03:55Z	DNS AMPLIFICATION	10.0.0.9	eth0	120 UDP packets to port 53 in 10s window
```

### Querying log files

```bash
# All alerts today
tail -f /var/log/tigernet/$(date +%Y%m%d).log

# Specific threat type
grep 'BOGON SOURCE' /var/log/tigernet/*.log

# Alerts from one IP across all days
grep '203.0.113.7' /var/log/tigernet/*.log

# Count by threat type for a day
awk -F'\t' 'NR>1 {count[$2]++} END {for (t in count) print count[t], t}' \
    /var/log/tigernet/$(date +%Y%m%d).log | sort -rn
```

---

## Watched ports (`--watch`)

```
--watch <port>:<name>:<threshold>
```

`--watch` is repeatable. Specifying a port again updates its name and threshold. If no `--watch` flags or `watch =` lines are given, tigernet defaults to SSH (22) and RDP (3389) at threshold 5.

```bash
sudo ./tigernet \
    --watch 22:SSH:5 \
    --watch 3389:RDP:3 \
    --watch 5900:VNC:2 \
    --watch 5432:PostgreSQL:10 \
    --watch 3306:MySQL:10 \
    --watch 27017:MongoDB:8
```

---

## Alert script

When `--alert-script` is set tigernet forks the script **asynchronously** (double-fork + `setsid()`). The capture loop is never blocked.

### Environment variables

| Variable | Example | Description |
|---|---|---|
| `TIGERNET_TYPE` | `SSH BRUTE-FORCE` | Alert category |
| `TIGERNET_SRC_IP` | `203.0.113.7` | Source IP |
| `TIGERNET_DETAIL` | `11 attempts to SSH (port 22) in 60s window` | Detail |
| `TIGERNET_TIMESTAMP` | `2025-04-22T14:03:44Z` | ISO-8601 UTC |
| `TIGERNET_HOSTNAME` | `webserver-1` | Sensor hostname |
| `TIGERNET_IFACE` | `eth1` | Interface |

### alert_udp.sh

Sends a JSON payload over UDP using `socat` or `nc`:

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

Configure destination:

```bash
export TIGERNET_UDP_HOST=10.0.0.1
export TIGERNET_UDP_PORT=5140
sudo -E ./tigernet -i eth0 --alert-script ./alert_udp.sh
```

Receive with: `socat UDP-RECV:5140 STDOUT` or `nc -u -l 5140`.

---

## Configuration file

tigernet reads `~/.tigernet/tigernet.conf` before CLI flags. Auto-created on first run.

### Location

```
~/.tigernet/tigernet.conf
```

### Format

```ini
# tigernet configuration file

# interface   = eth0    # repeatable
# interface   = eth1

window      = 60
portScan    = 20
synFlood    = 200
icmpFlood   = 100
udpScan     = 30
udpFlood    = 500
rstFlood    = 200
finFlood    = 200
pingSweep   = 20
dnsAmp      = 100
ntpAmp      = 50
ssdpAmp     = 50
fragFlood   = 100
alertScript  = /etc/tigernet/alert_udp.sh
logDir       = /var/log/tigernet
verbose      = false

# Bogon/martian/smurf suppression
# noBogon         = false     # disable globally
# internalIface   = eth1      # suppress bogon on one interface (repeatable)
#
# Stealth-scan suppression
# noAckScan       = false     # disable ACK scan globally
# noFinScan       = false     # disable FIN scan globally
# noMaimonScan    = false     # disable Maimon scan globally
# noOsFingerprint = false     # disable OS fingerprint globally
#
# Per-interface stealth-scan suppression
# ifaceNoAckScan  = eth1      # suppress ACK scan on one interface
# ifaceNoFinScan  = eth1
# ifaceNoMaimon   = eth1
# ifaceNoOsFp     = eth1

# Brute-force watched ports — format: watch = <port>:<n>:<threshold>
watch = 22:SSH:5
watch = 3389:RDP:5
watch = 5900:VNC:3
```

### Config keys

| Key | Type | Repeatable | Description |
|---|---|---|---|
| `interface` | string | yes | Network interface to monitor |
| `window` | integer | no | Sliding time window in seconds |
| `portScan` | integer | no | TCP port-scan threshold |
| `synFlood` | integer | no | SYN flood threshold |
| `icmpFlood` | integer | no | ICMP flood threshold |
| `udpScan` | integer | no | UDP port-scan threshold |
| `udpFlood` | integer | no | UDP flood threshold |
| `rstFlood` | integer | no | TCP RST flood threshold |
| `finFlood` | integer | no | TCP FIN flood threshold |
| `pingSweep` | integer | no | Ping sweep threshold (distinct destination IPs) |
| `dnsAmp` | integer | no | DNS amplification threshold |
| `ntpAmp` | integer | no | NTP amplification threshold |
| `ssdpAmp` | integer | no | SSDP amplification threshold |
| `fragFlood` | integer | no | IP fragment flood threshold |
| `noBogon` | boolean | no | Disable bogon/martian/smurf checks globally |
| `internalIface` | string | yes | Suppress bogon checks on a named interface |
| `noAckScan` | boolean | no | Disable TCP ACK scan detection globally |
| `noFinScan` | boolean | no | Disable TCP FIN scan detection globally |
| `noMaimonScan` | boolean | no | Disable TCP Maimon scan detection globally |
| `noOsFingerprint` | boolean | no | Disable OS fingerprint probe detection globally |
| `ifaceNoAckScan` | string | yes | Suppress ACK scan on a named interface |
| `ifaceNoFinScan` | string | yes | Suppress FIN scan on a named interface |
| `ifaceNoMaimon` | string | yes | Suppress Maimon scan on a named interface |
| `ifaceNoOsFp` | string | yes | Suppress OS fingerprint on a named interface |
| `alertScript` | path | no | Script to execute on every alert |
| `logDir` | path | no | Directory for daily log files |
| `watch` | `port:name:threshold` | yes | Add or update a watched brute-force port |
| `verbose` | boolean | no | `true`, `yes`, or `1` to enable verbose output |

### Priority order

```
built-in defaults  <  tigernet.conf  <  command-line flags
```

---

## Alert output format

```
HH:MM:SS [ALERT] <type>                    src=<ip>            if=<iface>  <detail>
```

Example output:

```
14:03:22 [ALERT] TCP PORT SCAN             src=192.168.1.42    if=eth0     30 distinct TCP ports in 10s window
14:03:25 [ALERT] SYN FLOOD                 src=10.0.0.5        if=eth0     204 SYN packets in 10s window
14:03:27 [ALERT] TCP FIN SCAN              src=10.0.0.5        if=eth0     TCP FIN scan -> port 22
14:03:29 [ALERT] TCP ACK SCAN              src=10.0.0.5        if=eth0     TCP ACK scan -> port 80
14:03:31 [ALERT] TCP XMAS SCAN             src=192.168.1.99    if=eth1     TCP Xmas scan -> port 443
14:03:33 [ALERT] OS FINGERPRINT PROBE      src=10.0.0.7        if=eth0     TCP SYN with zero window -> port 22
14:03:35 [ALERT] PING SWEEP                src=203.0.113.50    if=eth1     22 distinct dst IPs in 10s window
14:03:38 [ALERT] DNS AMPLIFICATION         src=198.51.100.9    if=eth0     120 UDP packets to port 53 in 10s window
14:03:41 [ALERT] BOGON SOURCE              src=10.0.0.8        if=eth0     RFC-1918/loopback/APIPA source on wire
14:03:43 [ALERT] LAND ATTACK               src=192.168.1.1     if=eth0     src IP == dst IP
14:03:44 [ALERT] SSH BRUTE-FORCE           src=203.0.113.7     if=eth1     11 attempts to SSH (port 22) in 60s
14:03:51 [ALERT] HTTP SCANNER              src=198.51.100.3    if=eth0     scanner User-Agent 'Nikto' in payload
14:03:55 [ALERT] SMB EXPLOIT PROBE         src=10.0.0.12       if=eth0     208 SYN packets to SMB port 445
```

---

## Files

| File | Description |
|---|---|
| `tigernet.c` | Main source — full IDS engine |
| `alert_udp.sh` | Example alert script — sends JSON over UDP |
| `Makefile` | Build, install, and uninstall targets |
| `~/.tigernet/tigernet.conf` | Per-user config file (auto-created on first run) |
| `/var/log/tigernet/YYYYMMDD.log` | Daily alert log files (default location) |

---

## Implementation notes

- Each interface runs in its own **POSIX thread**. All threads share one IP stats table protected by `pthread_mutex_t`.
- **Stateless per-packet detections** (Null, FIN, ACK, Xmas, Maimon, Land, Bogon, Martian, Smurf, OS fingerprint, HTTP payload) fire immediately on every matching packet.
- **Rate/count detections** (floods, scans, sweeps, amplification, brute-force) use per-source-IP counters reset lazily when the sliding window expires.
- Ping sweep tracks distinct destination IPs in a **bitset** hashed to 256 slots — O(1), no dynamic allocation.
- Port tracking (TCP and UDP scan) uses a **bitset** across all 65 536 ports — O(1) per packet.
- All per-source-IP state lives in a **hash table** (4096 buckets, chained).
- Alert scripts run via **double-fork + `setsid()`** — never blocks, no zombies.
- Log files are opened, written, and **closed per alert** — midnight rotation is automatic.
- **Size-based rotation**: when `logMaxMb > 0`, the file size is checked with `stat()` before each write. If the limit is met, the file is renamed `YYYYMMDD_1.log` (suffix increments until a free slot is found) and a fresh file is started — no background thread or timer needed.
- Ctrl+C calls `pcap_breakloop()` on every open handle; all threads exit cleanly.

---

## Limitations

- IPv4 only — IPv6 packets are skipped.
- Ethernet framing assumed; loopback and PPP are not handled.
- Detection is **signature / threshold-based** — no statistical baselining or machine learning.
- Application-layer inspection is limited to the first 512 bytes of TCP payload on HTTP ports.
- Up to **16 interfaces** and **64 watched ports** simultaneously (compile-time constants).
- Log files grow unbounded within a day; add a `logrotate` rule if disk space is a concern.
- tigernet is a learning and monitoring tool. For production use consider Suricata or Zeek.

---

## License

MIT — do whatever you like, attribution appreciated.
