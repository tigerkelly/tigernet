/*
 * tigernet.c — Network Intrusion Detection System
 *
 * Detects:
 *   - Port scans          (many distinct TCP ports from one IP in a time window)
 *   - SYN flood           (high SYN rate from one IP, few ACKs back)
 *   - ICMP flood          (excessive ping traffic from one IP)
 *   - UDP scan            (rapid UDP probes across many ports)
 *   - Null scan           (TCP packet with no flags set)
 *   - Xmas scan           (TCP packet with FIN+PSH+URG set)
 *   - Brute-force attacks (repeated inbound SYNs to any user-defined port)
 *
 * Multi-interface support:
 *   Supply -i more than once (or add multiple interface = lines in the config
 *   file) to monitor several network interfaces simultaneously.  Each
 *   interface runs in its own POSIX thread; all threads share a single
 *   detection engine protected by a mutex.
 *
 * Daily alert log files:
 *   Every alert is appended to a log file named YYYYMMDD.log in a
 *   configurable directory (default: /var/log/tigernet).  A new file is
 *   created automatically when the date changes — no restart needed.
 *   Each log line is tab-separated:
 *
 *     TIMESTAMP<TAB>TYPE<TAB>SRC_IP<TAB>IFACE<TAB>DETAIL
 *
 *   The file is opened, written, and closed per alert so midnight rotation
 *   requires no special handling.
 *
 * Alert script hook:
 *   When an alert fires, tigernet optionally forks a user-supplied script.
 *   The script receives all alert data as environment variables:
 *
 *     TIGERNET_TYPE       alert type string, e.g. "SSH BRUTE-FORCE"
 *     TIGERNET_SRC_IP     source IP address, e.g. "203.0.113.7"
 *     TIGERNET_DETAIL     human-readable detail string
 *     TIGERNET_TIMESTAMP  ISO-8601 UTC timestamp, e.g. "2025-04-22T14:03:44Z"
 *     TIGERNET_HOSTNAME   hostname of the machine running tigernet
 *     TIGERNET_IFACE      interface on which the alert was detected
 *
 * Configuration (lowest → highest priority):
 *   1. Built-in defaults
 *   2. ~/.tigernet/tigernet.conf  (key = value, one per line)
 *   3. Command-line flags
 *
 * Config file keys:
 *   interface   = eth0          # repeatable
 *   interface   = eth1
 *   window      = 10
 *   portScan    = 20
 *   synFlood    = 200
 *   icmpFlood   = 100
 *   udpScan     = 30
 *   alertScript = /etc/tigernet/alert_udp.sh
 *   logDir      = /var/log/tigernet
 *   verbose     = false
 *   watch       = 22:SSH:5      # repeatable
 *   watch       = 3389:RDP:5
 *
 * Build:
 *   sudo apt install libpcap-dev
 *   gcc -O2 -Wall -Wextra -std=gnu11 -D_DEFAULT_SOURCE \
 *       -o tigernet tigernet.c -lpcap -lpthread
 *
 * Run:
 *   sudo ./tigernet -i eth0 -i eth1
 *   sudo ./tigernet -i eth0 --log-dir /var/log/tigernet --alert-script ./alert_udp.sh
 *
 * Requires root or CAP_NET_RAW.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>

/* ── colour codes ────────────────────────────────────────────────────── */
#define RED    "\033[31m"
#define YELLOW "\033[33m"
#define GREEN  "\033[32m"
#define CYAN   "\033[36m"
#define BOLD   "\033[1m"
#define DIM    "\033[2m"
#define RESET  "\033[0m"

/* ── built-in defaults ───────────────────────────────────────────────── */
#define defWindowSeconds      10
#define defPortScanThreshold  20
#define defSynFloodThreshold  200
#define defIcmpFloodThreshold 100
#define defUdpScanThreshold   30
#define defBruteThreshold     5

#define maxTrackedIps   4096
#define maxPorts        65536
#define maxWatchPorts   64
#define maxServiceName  32
#define maxScriptPath   512
#define maxLogDirPath   512
#define maxInterfaces   16
#define maxIfaceNameLen 64
#define confPath        "/.tigernet/tigernet.conf"
#define defLogDir       "/var/log/tigernet"

/* ── watched port definition ─────────────────────────────────────────── */
typedef struct {
    uint16_t port;
    char     name[maxServiceName];
    int      threshold;
} WatchPort;

/* ── runtime config ──────────────────────────────────────────────────── */
typedef struct {
    char       ifaceNames[maxInterfaces][maxIfaceNameLen];
    int        ifaceCount;
    int        windowSeconds;
    int        portScanThreshold;
    int        synFloodThreshold;
    int        icmpFloodThreshold;
    int        udpScanThreshold;
    int        verbose;
    char       confFilePath[512];
    int        confLoaded;
    char       alertScript[maxScriptPath];
    char       logDir[maxLogDirPath];       /* directory for YYYYMMDD.log files */
    WatchPort  watchPorts[maxWatchPorts];
    int        watchCount;
} Config;

/* ── per-interface capture context (one per thread) ──────────────────── */
typedef struct {
    char    name[maxIfaceNameLen];
    pcap_t *handle;
} IfaceCtx;

/* ── per-IP tracking ─────────────────────────────────────────────────── */
typedef struct IpStats {
    uint32_t        ip;
    time_t          windowStart;
    uint32_t        synCount;
    uint32_t        icmpCount;
    uint8_t         tcpPorts[maxPorts / 8];
    uint32_t        tcpPortCount;
    uint8_t         udpPorts[maxPorts / 8];
    uint32_t        udpPortCount;
    uint32_t        bruteAttempts[maxWatchPorts];
    int             alertedBrute[maxWatchPorts];
    int             alertedPortScan;
    int             alertedSynFlood;
    int             alertedIcmpFlood;
    int             alertedUdpScan;
    struct IpStats *next;
} IpStats;

/* ── globals ─────────────────────────────────────────────────────────── */
static IpStats        *ipTable[maxTrackedIps];
static long            totalPackets = 0;
static long            totalAlerts  = 0;
static Config          cfg;

/* Mutex protecting all shared state and I/O. */
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

/* Array of pcap handles; sigHandler stops all of them. */
static pcap_t         *gHandles[maxInterfaces];
static int             gHandleCount = 0;

/* ════════════════════════════════════════════════════════════════════════
 *  Daily log file
 * ════════════════════════════════════════════════════════════════════════ */

/*
 * Ensure the log directory exists.  Creates parent directories if needed.
 * Returns 1 on success, 0 on failure.
 */
static int ensureLogDir(const char *dir) {
    /* walk the path, creating each component */
    char tmp[maxLogDirPath];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len && tmp[len - 1] == '/') tmp[--len] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, YELLOW "[tigernet] " RESET
                        "cannot create log dir '%s': %s\n", tmp, strerror(errno));
                return 0;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "cannot create log dir '%s': %s\n", tmp, strerror(errno));
        return 0;
    }
    return 1;
}

/*
 * Build the full path for today's log file into buf.
 * Format: <logDir>/YYYYMMDD.log
 */
static void todayLogPath(char *buf, size_t len) {
    time_t     t  = time(NULL);
    struct tm *tm = localtime(&t);
    char       date[16];
    strftime(date, sizeof(date), "%Y%m%d", tm);
    snprintf(buf, len, "%s/%s.log", cfg.logDir, date);
}

/*
 * Append one alert line to today's log file.
 * Creates the file (with a header) if it doesn't exist yet.
 * Called with gLock already held.
 *
 * Log format (tab-separated):
 *   TIMESTAMP  TYPE  SRC_IP  IFACE  DETAIL
 */
static void writeLogEntry(const char *timestamp, const char *type,
                          const char *srcIp, const char *iface,
                          const char *detail) {
    if (cfg.logDir[0] == '\0') return;

    char path[maxLogDirPath + 20];
    todayLogPath(path, sizeof(path));

    /* O_APPEND ensures atomic writes even if multiple processes share the file */
    int newFile = (access(path, F_OK) != 0);
    FILE *f = fopen(path, "a");
    if (!f) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "cannot open log file '%s': %s\n", path, strerror(errno));
        return;
    }

    /* write column header on the first line of a new file */
    if (newFile)
        fprintf(f, "# TIMESTAMP\tTYPE\tSRC_IP\tIFACE\tDETAIL\n");

    fprintf(f, "%s\t%s\t%s\t%s\t%s\n",
            timestamp, type, srcIp, iface, detail);

    fclose(f);
}

/* ════════════════════════════════════════════════════════════════════════
 *  Alert script execution
 * ════════════════════════════════════════════════════════════════════════ */

static void runAlertScript(const char *type, const char *srcIp,
                           const char *detail, const char *timestamp,
                           const char *iface) {
    if (cfg.alertScript[0] == '\0') return;

    pid_t pid = fork();
    if (pid < 0) {
        if (cfg.verbose)
            fprintf(stderr, YELLOW "[tigernet] " RESET
                    "fork failed for alert script: %s\n", strerror(errno));
        return;
    }
    if (pid > 0) { waitpid(pid, NULL, 0); return; }

    /* first child */
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);

    /* grandchild */
    setsid();
    if (!cfg.verbose) {
        int devNull = open("/dev/null", O_WRONLY);
        if (devNull >= 0) { dup2(devNull, STDERR_FILENO); close(devNull); }
    }

    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname));

    setenv("TIGERNET_TYPE",      type,      1);
    setenv("TIGERNET_SRC_IP",    srcIp,     1);
    setenv("TIGERNET_DETAIL",    detail,    1);
    setenv("TIGERNET_TIMESTAMP", timestamp, 1);
    setenv("TIGERNET_HOSTNAME",  hostname,  1);
    setenv("TIGERNET_IFACE",     iface,     1);

    execl("/bin/sh", "sh", cfg.alertScript, NULL);
    _exit(1);
}

/* ════════════════════════════════════════════════════════════════════════
 *  Watched-port helpers
 * ════════════════════════════════════════════════════════════════════════ */

static int addWatchPort(Config *c, uint16_t port,
                        const char *name, int threshold) {
    for (int i = 0; i < c->watchCount; i++) {
        if (c->watchPorts[i].port == port) {
            snprintf(c->watchPorts[i].name,
                     sizeof(c->watchPorts[i].name), "%s", name);
            c->watchPorts[i].threshold = threshold;
            return 1;
        }
    }
    if (c->watchCount >= maxWatchPorts) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "watch table full (%d entries), ignoring port %u\n",
                maxWatchPorts, port);
        return 0;
    }
    WatchPort *wp = &c->watchPorts[c->watchCount++];
    wp->port      = port;
    wp->threshold = threshold;
    snprintf(wp->name, sizeof(wp->name), "%s", name);
    return 1;
}

static int parseWatchSpec(Config *c, const char *spec) {
    char  buf[128];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *portStr = buf, *nameStr = NULL, *thrStr = NULL;
    char *c1 = strchr(portStr, ':');
    if (c1) {
        *c1 = '\0'; nameStr = c1 + 1;
        char *c2 = strchr(nameStr, ':');
        if (c2) { *c2 = '\0'; thrStr = c2 + 1; }
    }
    int port = atoi(portStr);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "invalid watch port '%s', skipped\n", portStr);
        return 0;
    }
    char name[maxServiceName];
    if (nameStr && *nameStr)
        snprintf(name, sizeof(name), "%s", nameStr);
    else
        snprintf(name, sizeof(name), "port%d", port);
    int thr = (thrStr && *thrStr) ? atoi(thrStr) : defBruteThreshold;
    if (thr < 1) thr = 1;
    return addWatchPort(c, (uint16_t)port, name, thr);
}

/* ── interface list helper ───────────────────────────────────────────── */

static int addInterface(Config *c, const char *name) {
    for (int i = 0; i < c->ifaceCount; i++)
        if (strcmp(c->ifaceNames[i], name) == 0) return 1;
    if (c->ifaceCount >= maxInterfaces) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "interface limit (%d) reached, ignoring '%s'\n",
                maxInterfaces, name);
        return 0;
    }
    snprintf(c->ifaceNames[c->ifaceCount++], maxIfaceNameLen, "%s", name);
    return 1;
}

/* ════════════════════════════════════════════════════════════════════════
 *  Config file parser
 * ════════════════════════════════════════════════════════════════════════ */

static char *trimWhitespace(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) end--;
    *end = '\0';
    return s;
}

static int parseBool(const char *v) {
    return (strcasecmp(v, "true") == 0 ||
            strcasecmp(v, "yes")  == 0 ||
            strcmp(v, "1")        == 0);
}

static int loadConfig(Config *c) {
    FILE *f = fopen(c->confFilePath, "r");
    if (!f) return 0;

    char line[512];
    int  lineNo = 0;
    while (fgets(line, sizeof(line), f)) {
        lineNo++;
        char *p = strchr(line, '#');
        if (p) *p = '\0';
        p = trimWhitespace(line);
        if (*p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) {
            fprintf(stderr, YELLOW "[tigernet] " RESET
                    "conf:%d: no '=' found, line skipped\n", lineNo);
            continue;
        }
        *eq = '\0';
        char *key = trimWhitespace(p);
        char *val = trimWhitespace(eq + 1);

        if      (strcmp(key, "interface")   == 0) addInterface(c, val);
        else if (strcmp(key, "window")      == 0) c->windowSeconds      = atoi(val);
        else if (strcmp(key, "portScan")    == 0) c->portScanThreshold  = atoi(val);
        else if (strcmp(key, "synFlood")    == 0) c->synFloodThreshold  = atoi(val);
        else if (strcmp(key, "icmpFlood")   == 0) c->icmpFloodThreshold = atoi(val);
        else if (strcmp(key, "udpScan")     == 0) c->udpScanThreshold   = atoi(val);
        else if (strcmp(key, "verbose")     == 0) c->verbose            = parseBool(val);
        else if (strcmp(key, "watch")       == 0) parseWatchSpec(c, val);
        else if (strcmp(key, "alertScript") == 0)
            snprintf(c->alertScript, sizeof(c->alertScript), "%s", val);
        else if (strcmp(key, "logDir")      == 0)
            snprintf(c->logDir, sizeof(c->logDir), "%s", val);
        else {
            fprintf(stderr, YELLOW "[tigernet] " RESET
                    "conf:%d: unknown key '%s', skipped\n", lineNo, key);
        }
    }
    fclose(f);
    return 1;
}

static void writeDefaultConfig(const char *path) {
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; mkdir(dir, 0700); }
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
        "# tigernet configuration file\n"
        "# Lines beginning with '#' are comments.\n"
        "#\n"
        "# Interfaces to monitor — one line per interface.\n"
        "# interface   = eth0\n"
        "# interface   = eth1\n"
        "#\n"
        "# window      = %d\n"
        "# portScan    = %d\n"
        "# synFlood    = %d\n"
        "# icmpFlood   = %d\n"
        "# udpScan     = %d\n"
        "# verbose     = false\n"
        "#\n"
        "# alertScript = /etc/tigernet/alert_udp.sh\n"
        "#\n"
        "# Directory for daily YYYYMMDD.log alert log files.\n"
        "# logDir      = /var/log/tigernet\n"
        "# Brute-force watched ports — format: watch = <port>:<n>:<threshold>\n"
        "# watch = 22:SSH:%d\n"
        "# watch = 3389:RDP:%d\n"
        "# watch = 5900:VNC:%d\n",
        defWindowSeconds, defPortScanThreshold, defSynFloodThreshold,
        defIcmpFloodThreshold, defUdpScanThreshold,
        defBruteThreshold, defBruteThreshold, defBruteThreshold);
    fclose(f);
    printf(DIM "[tigernet] Created default config: %s\n" RESET, path);
}

/* ════════════════════════════════════════════════════════════════════════
 *  Packet-processing helpers  (called with gLock held)
 * ════════════════════════════════════════════════════════════════════════ */

static const char *ipToStr(uint32_t ip) {
    struct in_addr a = { .s_addr = ip };
    return inet_ntoa(a);
}

static uint32_t hashIp(uint32_t ip) {
    ip ^= ip >> 16; ip *= 0x45d9f3b; ip ^= ip >> 16;
    return ip % maxTrackedIps;
}

static IpStats *getStats(uint32_t ip) {
    uint32_t  idx = hashIp(ip);
    IpStats  *s   = ipTable[idx];
    while (s) { if (s->ip == ip) return s; s = s->next; }
    s = calloc(1, sizeof(IpStats));
    if (!s) { perror("calloc"); exit(EXIT_FAILURE); }
    s->ip = ip; s->windowStart = time(NULL);
    s->next = ipTable[idx]; ipTable[idx] = s;
    return s;
}

static void maybeResetWindow(IpStats *s) {
    time_t now = time(NULL);
    if (now - s->windowStart < cfg.windowSeconds) return;
    s->synCount = s->icmpCount = s->tcpPortCount = s->udpPortCount = 0;
    s->alertedPortScan = s->alertedSynFlood = 0;
    s->alertedIcmpFlood = s->alertedUdpScan = 0;
    memset(s->bruteAttempts, 0, sizeof(s->bruteAttempts));
    memset(s->alertedBrute,  0, sizeof(s->alertedBrute));
    memset(s->tcpPorts, 0, sizeof(s->tcpPorts));
    memset(s->udpPorts, 0, sizeof(s->udpPorts));
    s->windowStart = now;
}

static int markPort(uint8_t *bitset, uint16_t port) {
    uint8_t bit = 1u << (port % 8);
    if (bitset[port / 8] & bit) return 0;
    bitset[port / 8] |= bit;
    return 1;
}

/* ── alert / info output  (called with gLock held) ───────────────────── */

static void isoTimestamp(char *buf, size_t len) {
    time_t t = time(NULL);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
}

static void fireAlert(const char *type, const char *srcIp,
                      const char *detail, const char *iface) {
    char ts[24];
    isoTimestamp(ts, sizeof(ts));

    /* terminal output — strip date from ISO timestamp for a compact display */
    printf(DIM "%.8s " RESET BOLD RED "[ALERT] " RESET
           BOLD "%-22s" RESET "  src=%-16s  if=%-8s  %s\n",
           ts + 11, type, srcIp, iface, detail);
    fflush(stdout);
    totalAlerts++;

    /* daily log file */
    writeLogEntry(ts, type, srcIp, iface, detail);

    /* user alert script */
    runAlertScript(type, srcIp, detail, ts, iface);
}

static void logInfo(const char *fmt, ...) {
    if (!cfg.verbose) return;
    va_list ap; va_start(ap, fmt);
    printf(CYAN "[info]  " RESET); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}

/* ── protocol handlers  (called with gLock held) ─────────────────────── */

static void handleTcp(IpStats *s, const struct tcphdr *tcp,
                      const char *srcIp, const char *iface) {
    uint16_t dport = ntohs(tcp->dest);
    uint8_t  flags = tcp->th_flags;

    if (flags == 0) {
        char d[64];
        snprintf(d, sizeof(d), "TCP NULL scan -> port %u", dport);
        fireAlert("TCP NULL SCAN", srcIp, d, iface);
        return;
    }
    if ((flags & (TH_FIN | TH_PUSH | TH_URG)) == (TH_FIN | TH_PUSH | TH_URG)) {
        char d[64];
        snprintf(d, sizeof(d), "TCP Xmas scan -> port %u", dport);
        fireAlert("TCP XMAS SCAN", srcIp, d, iface);
        return;
    }

    int isSyn = (flags & TH_SYN) && !(flags & TH_ACK);

    if (isSyn) {
        for (int i = 0; i < cfg.watchCount; i++) {
            if (dport == cfg.watchPorts[i].port) {
                s->bruteAttempts[i]++;
                logInfo("%s attempt from %s on %s  (count=%u)",
                        cfg.watchPorts[i].name, srcIp, iface,
                        s->bruteAttempts[i]);
                if (s->bruteAttempts[i] >= (uint32_t)cfg.watchPorts[i].threshold
                        && !s->alertedBrute[i]) {
                    char at[48], d[96];
                    snprintf(at, sizeof(at), "%s BRUTE-FORCE",
                             cfg.watchPorts[i].name);
                    snprintf(d, sizeof(d),
                             "%u attempts to %s (port %u) in %ds window",
                             s->bruteAttempts[i], cfg.watchPorts[i].name,
                             cfg.watchPorts[i].port, cfg.windowSeconds);
                    fireAlert(at, srcIp, d, iface);
                    s->alertedBrute[i] = 1;
                }
                break;
            }
        }
    }

    if (isSyn) {
        s->synCount++;
        logInfo("SYN from %s -> port %u on %s  (count=%u)",
                srcIp, dport, iface, s->synCount);
        if (s->synCount >= (uint32_t)cfg.synFloodThreshold
                && !s->alertedSynFlood) {
            char d[80];
            snprintf(d, sizeof(d), "%u SYN packets in %ds window",
                     s->synCount, cfg.windowSeconds);
            fireAlert("SYN FLOOD", srcIp, d, iface);
            s->alertedSynFlood = 1;
        }
    }

    if (markPort(s->tcpPorts, dport)) {
        s->tcpPortCount++;
        logInfo("new TCP port %u from %s on %s  (distinct=%u)",
                dport, srcIp, iface, s->tcpPortCount);
        if (s->tcpPortCount >= (uint32_t)cfg.portScanThreshold
                && !s->alertedPortScan) {
            char d[80];
            snprintf(d, sizeof(d), "%u distinct TCP ports in %ds window",
                     s->tcpPortCount, cfg.windowSeconds);
            fireAlert("TCP PORT SCAN", srcIp, d, iface);
            s->alertedPortScan = 1;
        }
    }
}

static void handleUdp(IpStats *s, const struct udphdr *udp,
                      const char *srcIp, const char *iface) {
    uint16_t dport = ntohs(udp->uh_dport);
    if (markPort(s->udpPorts, dport)) {
        s->udpPortCount++;
        logInfo("new UDP port %u from %s on %s  (distinct=%u)",
                dport, srcIp, iface, s->udpPortCount);
        if (s->udpPortCount >= (uint32_t)cfg.udpScanThreshold
                && !s->alertedUdpScan) {
            char d[80];
            snprintf(d, sizeof(d), "%u distinct UDP ports in %ds window",
                     s->udpPortCount, cfg.windowSeconds);
            fireAlert("UDP PORT SCAN", srcIp, d, iface);
            s->alertedUdpScan = 1;
        }
    }
}

static void handleIcmp(IpStats *s, const char *srcIp, const char *iface) {
    s->icmpCount++;
    logInfo("ICMP from %s on %s  (count=%u)", srcIp, iface, s->icmpCount);
    if (s->icmpCount >= (uint32_t)cfg.icmpFloodThreshold
            && !s->alertedIcmpFlood) {
        char d[80];
        snprintf(d, sizeof(d), "%u ICMP packets in %ds window",
                 s->icmpCount, cfg.windowSeconds);
        fireAlert("ICMP FLOOD", srcIp, d, iface);
        s->alertedIcmpFlood = 1;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 *  Per-interface capture thread
 * ════════════════════════════════════════════════════════════════════════ */

static void packetHandler(u_char *user,
                           const struct pcap_pkthdr *header,
                           const u_char *packet) {
    const IfaceCtx *ctx = (const IfaceCtx *)user;

    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip))
        return;

    const struct ether_header *eth = (const struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct ip *iph =
        (const struct ip *)(packet + sizeof(struct ether_header));
    if (iph->ip_v != 4) return;

    uint32_t      srcIp     = iph->ip_src.s_addr;
    int           ipHdrLen  = iph->ip_hl * 4;
    const u_char *transport = (const u_char *)iph + ipHdrLen;
    size_t        remaining = header->caplen
                              - sizeof(struct ether_header)
                              - (size_t)ipHdrLen;

    pthread_mutex_lock(&gLock);

    const char *srcStr = ipToStr(srcIp);
    IpStats    *s      = getStats(srcIp);
    maybeResetWindow(s);
    totalPackets++;

    switch (iph->ip_p) {
    case IPPROTO_TCP:
        if (remaining >= sizeof(struct tcphdr))
            handleTcp(s, (const struct tcphdr *)transport, srcStr, ctx->name);
        break;
    case IPPROTO_UDP:
        if (remaining >= sizeof(struct udphdr))
            handleUdp(s, (const struct udphdr *)transport, srcStr, ctx->name);
        break;
    case IPPROTO_ICMP:
        if (remaining >= sizeof(struct icmphdr))
            handleIcmp(s, srcStr, ctx->name);
        break;
    default:
        break;
    }

    pthread_mutex_unlock(&gLock);
}

static void *captureThread(void *arg) {
    IfaceCtx *ctx = (IfaceCtx *)arg;
    pcap_loop(ctx->handle, 0, packetHandler, (u_char *)ctx);
    return NULL;
}

/* ── signal handler ──────────────────────────────────────────────────── */

static void sigHandler(int sig) {
    (void)sig;
    for (int i = 0; i < gHandleCount; i++)
        if (gHandles[i]) pcap_breakloop(gHandles[i]);
}

/* ── usage ───────────────────────────────────────────────────────────── */

static void printUsage(const char *prog) {
    fprintf(stderr,
        BOLD "tigernet" RESET " — Network Intrusion Detection System\n\n"
        "Usage: %s [options]\n\n"
        "Options:\n"
        "  -i, --interface    <dev>         Interface to monitor (repeatable, default: auto)\n"
        "  -w, --window       <sec>         Time window in seconds              (default: %d)\n"
        "  -p, --port-scan    <n>           TCP port-scan threshold             (default: %d)\n"
        "  -s, --syn-flood    <n>           SYN flood threshold                 (default: %d)\n"
        "  -c, --icmp-flood   <n>           ICMP flood threshold                (default: %d)\n"
        "  -u, --udp-scan     <n>           UDP port-scan threshold             (default: %d)\n"
        "      --watch        <p:name:thr>  Watch port for brute-force (repeatable)\n"
        "      --alert-script <path>        Script to run on every alert\n"
        "      --log-dir      <dir>         Directory for daily YYYYMMDD.log files\n"
        "                                     (default: /var/log/tigernet)\n"
        "  -v, --verbose                    Print every packet event\n"
        "  -h, --help                       Show this help\n\n"
        "Examples:\n"
        "  sudo %s -i eth0 -i eth1\n"
        "  sudo %s -i eth0 --log-dir /var/log/tigernet\n"
        "  sudo %s -i eth0 --log-dir /var/log/tigernet --alert-script ./alert_udp.sh\n\n"
        "Log file format (tab-separated):\n"
        "  TIMESTAMP  TYPE  SRC_IP  IFACE  DETAIL\n\n"
        "Alert script environment variables:\n"
        "  TIGERNET_TYPE, TIGERNET_SRC_IP, TIGERNET_DETAIL,\n"
        "  TIGERNET_TIMESTAMP, TIGERNET_HOSTNAME, TIGERNET_IFACE\n\n"
        "Config file: ~/.tigernet/tigernet.conf\n"
        "  Keys: interface (repeatable), window, portScan, synFlood, icmpFlood,\n"
        "        udpScan, alertScript, logDir, verbose, watch (repeatable)\n",
        prog,
        defWindowSeconds, defPortScanThreshold, defSynFloodThreshold,
        defIcmpFloodThreshold, defUdpScanThreshold,
        prog, prog, prog);
}

/* ════════════════════════════════════════════════════════════════════════
 *  main
 * ════════════════════════════════════════════════════════════════════════ */

enum { optWatch = 1000, optAlertScript, optLogDir };

int main(int argc, char *argv[]) {

    /* 1. defaults */
    memset(&cfg, 0, sizeof(cfg));
    cfg.windowSeconds      = defWindowSeconds;
    cfg.portScanThreshold  = defPortScanThreshold;
    cfg.synFloodThreshold  = defSynFloodThreshold;
    cfg.icmpFloodThreshold = defIcmpFloodThreshold;
    cfg.udpScanThreshold   = defUdpScanThreshold;

    /* 2. config file path */
    const char *home = getenv("HOME");
    if (home)
        snprintf(cfg.confFilePath, sizeof(cfg.confFilePath), "%s%s", home, confPath);
    else
        snprintf(cfg.confFilePath, sizeof(cfg.confFilePath), ".tigernet/tigernet.conf");

    /* 3. default log dir — /var/log/tigernet (can be overridden by config
       file or CLI flag) */
    snprintf(cfg.logDir, sizeof(cfg.logDir), "%s", defLogDir);

    /* 4. load config file */
    cfg.confLoaded = loadConfig(&cfg);
    if (!cfg.confLoaded && home) writeDefaultConfig(cfg.confFilePath);

    /* 5. default watched ports */
    if (cfg.watchCount == 0) {
        addWatchPort(&cfg,   22, "SSH", defBruteThreshold);
        addWatchPort(&cfg, 3389, "RDP", defBruteThreshold);
    }

    /* 6. CLI flags */
    static const struct option longOpts[] = {
        { "interface",    required_argument, NULL, 'i'            },
        { "window",       required_argument, NULL, 'w'            },
        { "port-scan",    required_argument, NULL, 'p'            },
        { "syn-flood",    required_argument, NULL, 's'            },
        { "icmp-flood",   required_argument, NULL, 'c'            },
        { "udp-scan",     required_argument, NULL, 'u'            },
        { "watch",        required_argument, NULL, optWatch       },
        { "alert-script", required_argument, NULL, optAlertScript },
        { "log-dir",      required_argument, NULL, optLogDir      },
        { "verbose",      no_argument,       NULL, 'v'            },
        { "help",         no_argument,       NULL, 'h'            },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:w:p:s:c:u:vh",
                              longOpts, NULL)) != -1) {
        switch (opt) {
        case 'i': addInterface(&cfg, optarg); break;
        case 'w': cfg.windowSeconds      = atoi(optarg); break;
        case 'p': cfg.portScanThreshold  = atoi(optarg); break;
        case 's': cfg.synFloodThreshold  = atoi(optarg); break;
        case 'c': cfg.icmpFloodThreshold = atoi(optarg); break;
        case 'u': cfg.udpScanThreshold   = atoi(optarg); break;
        case optWatch:
            parseWatchSpec(&cfg, optarg); break;
        case optAlertScript:
            snprintf(cfg.alertScript, sizeof(cfg.alertScript), "%s", optarg);
            break;
        case optLogDir:
            snprintf(cfg.logDir, sizeof(cfg.logDir), "%s", optarg);
            break;
        case 'v': cfg.verbose = 1; break;
        case 'h': printUsage(argv[0]); return EXIT_SUCCESS;
        default:  printUsage(argv[0]); return EXIT_FAILURE;
        }
    }

    /* 7. sanity checks */
    if (cfg.windowSeconds      < 1) cfg.windowSeconds      = 1;
    if (cfg.portScanThreshold  < 1) cfg.portScanThreshold  = 1;
    if (cfg.synFloodThreshold  < 1) cfg.synFloodThreshold  = 1;
    if (cfg.icmpFloodThreshold < 1) cfg.icmpFloodThreshold = 1;
    if (cfg.udpScanThreshold   < 1) cfg.udpScanThreshold   = 1;

    /* 8. validate alert script */
    if (cfg.alertScript[0] != '\0' && access(cfg.alertScript, X_OK) != 0)
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "warning: alert script '%s' not executable: %s\n",
                cfg.alertScript, strerror(errno));

    /* 9. create log directory */
    if (cfg.logDir[0] != '\0') {
        if (!ensureLogDir(cfg.logDir)) {
            fprintf(stderr, YELLOW "[tigernet] " RESET
                    "warning: log directory unavailable, file logging disabled\n");
            cfg.logDir[0] = '\0';
        }
    }

    /* 10. auto-detect interface if none specified */
    char errbuf[PCAP_ERRBUF_SIZE];
    if (cfg.ifaceCount == 0) {
        pcap_if_t *devs;
        if (pcap_findalldevs(&devs, errbuf) == -1 || !devs) {
            fprintf(stderr, "No interfaces found: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        addInterface(&cfg, devs->name);
        pcap_freealldevs(devs);
    }

    /* 11. open a pcap handle for every interface */
    static IfaceCtx  ctxArr[maxInterfaces];
    static pthread_t threads[maxInterfaces];

    for (int i = 0; i < cfg.ifaceCount; i++) {
        snprintf(ctxArr[i].name, sizeof(ctxArr[i].name), "%s", cfg.ifaceNames[i]);
        ctxArr[i].handle = pcap_open_live(ctxArr[i].name, 65535,
                                           1, 100, errbuf);
        if (!ctxArr[i].handle) {
            fprintf(stderr, "pcap_open_live(%s): %s\n", ctxArr[i].name, errbuf);
            return EXIT_FAILURE;
        }
        struct bpf_program fp;
        if (pcap_compile(ctxArr[i].handle, &fp, "ip", 0,
                         PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(ctxArr[i].handle, &fp) == -1) {
            fprintf(stderr, "BPF filter on %s: %s\n",
                    ctxArr[i].name, pcap_geterr(ctxArr[i].handle));
            return EXIT_FAILURE;
        }
        pcap_freecode(&fp);
        gHandles[gHandleCount++] = ctxArr[i].handle;
    }

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);

    /* 12. banner */
    printf(BOLD GREEN
        "╔══════════════════════════════════════════════════╗\n"
        "║            tigernet  —  IDS  (libpcap)           ║\n"
        "╚══════════════════════════════════════════════════╝\n"
        RESET);
    printf("Config file  : %s%s\n", cfg.confFilePath,
           cfg.confLoaded ? "" : DIM "  (not found — using defaults)" RESET);
    printf("Interfaces   : %d\n", cfg.ifaceCount);
    for (int i = 0; i < cfg.ifaceCount; i++)
        printf("  [%d] %s\n", i + 1, cfg.ifaceNames[i]);
    printf("Window       : %d s\n",            cfg.windowSeconds);
    printf("Port scan    : %d ports/window\n", cfg.portScanThreshold);
    printf("SYN flood    : %d SYNs/window\n",  cfg.synFloodThreshold);
    printf("ICMP flood   : %d pkts/window\n",  cfg.icmpFloodThreshold);
    printf("UDP scan     : %d ports/window\n", cfg.udpScanThreshold);
    printf("Alert script : %s\n",
           cfg.alertScript[0] ? cfg.alertScript : DIM "(none)" RESET);
    printf("Log dir      : %s\n",
           cfg.logDir[0] ? cfg.logDir : DIM "(disabled)" RESET);

    /* show what today's log file will be named */
    if (cfg.logDir[0] != '\0') {
        char todayPath[maxLogDirPath + 20];
        todayLogPath(todayPath, sizeof(todayPath));
        printf("Today's log  : %s\n", todayPath);
    }

    printf("Verbose      : %s\n", cfg.verbose ? "yes" : "no");
    printf("Watched ports: %d\n", cfg.watchCount);
    for (int i = 0; i < cfg.watchCount; i++)
        printf("  [%d] port %-5u  name %-16s  threshold %d/window\n",
               i + 1, cfg.watchPorts[i].port,
               cfg.watchPorts[i].name, cfg.watchPorts[i].threshold);
    printf("\n");
    printf(YELLOW "Listening on %d interface%s… press Ctrl+C to stop.\n\n" RESET,
           cfg.ifaceCount, cfg.ifaceCount == 1 ? "" : "s");

    /* 13. launch capture threads */
    for (int i = 0; i < cfg.ifaceCount; i++) {
        if (pthread_create(&threads[i], NULL, captureThread, &ctxArr[i]) != 0) {
            perror("pthread_create");
            return EXIT_FAILURE;
        }
    }

    /* 14. wait for all threads */
    for (int i = 0; i < cfg.ifaceCount; i++)
        pthread_join(threads[i], NULL);

    /* 15. close handles */
    for (int i = 0; i < cfg.ifaceCount; i++)
        pcap_close(ctxArr[i].handle);

    /* 16. summary */
    printf("\n" BOLD "── Summary ──────────────────────────────────────\n" RESET);
    printf("Interfaces monitored   : %d\n", cfg.ifaceCount);
    printf("Total packets captured : %ld\n", totalPackets);
    printf("Total alerts raised    : %ld\n", totalAlerts);
    if (cfg.logDir[0] != '\0')
        printf("Log directory          : %s\n", cfg.logDir);
    printf(BOLD GREEN "Done.\n" RESET);

    /* 17. cleanup */
    for (int i = 0; i < maxTrackedIps; i++) {
        IpStats *s = ipTable[i];
        while (s) { IpStats *n = s->next; free(s); s = n; }
    }
    pthread_mutex_destroy(&gLock);
    return EXIT_SUCCESS;
}
