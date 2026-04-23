/*
 * tigernet.c — Network Intrusion Detection System
 *
 * ── Scanning & reconnaissance ──────────────────────────────────────────
 *   TCP port scan      Many distinct TCP ports from one IP in a window
 *   UDP port scan      Many distinct UDP ports from one IP in a window
 *   TCP Null scan      TCP with no flags set
 *   TCP Xmas scan      TCP with FIN+PSH+URG set
 *   TCP FIN scan       TCP with only FIN set
 *   TCP ACK scan       TCP with only ACK set (firewall mapping)
 *   TCP Maimon scan    TCP with FIN+ACK set
 *   OS fingerprint     TCP SYN with zero window size (nmap -O probe)
 *   Ping sweep         ICMP echo to many different destination IPs
 *
 * ── Flood & DoS ────────────────────────────────────────────────────────
 *   SYN flood          High rate of bare SYNs from one source
 *   ICMP flood         High rate of ICMP from one source
 *   UDP flood          High rate of UDP to one destination IP
 *   TCP RST flood      High rate of RST packets from one source
 *   TCP FIN flood      High rate of FIN-only packets from one source
 *   ICMP fragment flood ICMP with More-Fragments bit set
 *   Fragmented flood   IP MF bit / non-zero fragment offset at high rate
 *
 * ── Amplification & reflection ─────────────────────────────────────────
 *   DNS amplification  Burst of small UDP packets to port 53
 *   NTP amplification  Burst of UDP packets to port 123
 *   SSDP amplification Burst of UDP packets to port 1900
 *
 * ── Spoofing & anomalies ───────────────────────────────────────────────
 *   Land attack        SYN where src IP == dst IP
 *   Smurf indicator    ICMP echo to a broadcast/multicast destination
 *   Bogon source IP    Packets from RFC-1918 / loopback / APIPA on wire
 *   Martian packet     Packets from reserved / unallocated IP space
 *
 * ── Application-layer probes ───────────────────────────────────────────
 *   HTTP dir traversal TCP payload containing "../" on port 80/443/8080
 *   HTTP scanner UA    Common scanner User-Agent strings in HTTP payload
 *   SMB exploit probe  SYN burst to port 445 (EternalBlue-style scan)
 *
 * ── Brute-force (any port) ─────────────────────────────────────────────
 *   SSH / RDP / etc.   Repeated inbound SYNs to any user-defined port
 *
 * ── Multi-interface ────────────────────────────────────────────────────
 *   Supply -i more than once to monitor multiple interfaces in parallel.
 *   Each interface runs in its own POSIX thread; all share one detection
 *   engine (IP stats table, alert counters) protected by a mutex.
 *
 * ── Alert script hook ──────────────────────────────────────────────────
 *   An optional user script is forked (double-fork + setsid) on every
 *   alert and receives data as environment variables:
 *     TIGERNET_TYPE, TIGERNET_SRC_IP, TIGERNET_DETAIL,
 *     TIGERNET_TIMESTAMP, TIGERNET_HOSTNAME, TIGERNET_IFACE
 *
 * ── Daily log files ────────────────────────────────────────────────────
 *   Every alert is appended to <logDir>/YYYYMMDD.log (tab-separated).
 *   Default log directory: /var/log/tigernet
 *
 * Configuration (lowest → highest priority):
 *   1. Built-in defaults
 *   2. ~/.tigernet/tigernet.conf
 *   3. Command-line flags
 *
 * Build:
 *   sudo apt install libpcap-dev
 *   gcc -O2 -Wall -Wextra -std=gnu11 -D_DEFAULT_SOURCE \
 *       -o tigernet tigernet.c -lpcap -lpthread
 *
 * Run:
 *   sudo ./tigernet -i eth0 -i eth1 --log-dir /var/log/tigernet
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

/* ── built-in threshold defaults ─────────────────────────────────────── */
#define defWindowSeconds        10
#define defPortScanThreshold    20
#define defSynFloodThreshold   200
#define defIcmpFloodThreshold  100
#define defUdpScanThreshold     30
#define defUdpFloodThreshold   500   /* UDP pkts/window to one dst IP     */
#define defRstFloodThreshold   200   /* RST pkts/window from one src IP   */
#define defFinFloodThreshold   200   /* FIN pkts/window from one src IP   */
#define defPingSweepThreshold   20   /* distinct dst IPs in ICMP/window   */
#define defDnsAmpThreshold     100   /* UDP pkts to port 53/window        */
#define defNtpAmpThreshold      50   /* UDP pkts to port 123/window       */
#define defSsdpAmpThreshold     50   /* UDP pkts to port 1900/window      */
#define defFragFloodThreshold  100   /* IP fragments/window from one src  */
#define defBruteThreshold        5
#define defLogMaxMb              0   /* 0 = no size limit             */

/* ── capacity limits ─────────────────────────────────────────────────── */
#define maxTrackedIps    4096
#define maxPorts         65536
#define maxWatchPorts    64
#define maxServiceName   32
#define maxScriptPath    512
#define maxLogDirPath    512
#define maxInterfaces    16
#define maxIfaceNameLen  64
#define maxSweepDstIps   256   /* distinct ping-sweep destination IPs tracked */

/* ── paths ───────────────────────────────────────────────────────────── */
#define confPath   "/.tigernet/tigernet.conf"
#define defLogDir  "/var/log/tigernet"

/* ── watched port definition ─────────────────────────────────────────── */
typedef struct {
    uint16_t port;
    char     name[maxServiceName];
    int      threshold;
} WatchPort;

/* ── runtime config ──────────────────────────────────────────────────── */
typedef struct {
    char      ifaceNames[maxInterfaces][maxIfaceNameLen];
    int       ifaceCount;

    /* thresholds */
    int       windowSeconds;
    int       portScanThreshold;
    int       synFloodThreshold;
    int       icmpFloodThreshold;
    int       udpScanThreshold;
    int       udpFloodThreshold;
    int       rstFloodThreshold;
    int       finFloodThreshold;
    int       pingSweepThreshold;
    int       dnsAmpThreshold;
    int       ntpAmpThreshold;
    int       ssdpAmpThreshold;
    int       fragFloodThreshold;

    int       verbose;
    int       noBogon;        /* 1 = disable bogon/martian/smurf globally  */
    int       noAckScan;      /* 1 = disable TCP ACK scan detection        */
    int       noFinScan;      /* 1 = disable TCP FIN scan detection        */
    int       noMaimonScan;   /* 1 = disable TCP Maimon scan detection     */
    int       noOsFingerprint;/* 1 = disable OS fingerprint probe detection*/
    int       internalIface[maxInterfaces];    /* per-iface bogon suppress */
    int       ifaceNoAckScan[maxInterfaces];   /* per-iface ACK scan off   */
    int       ifaceNoFinScan[maxInterfaces];   /* per-iface FIN scan off   */
    int       ifaceNoMaimon[maxInterfaces];    /* per-iface Maimon off     */
    int       ifaceNoOsFp[maxInterfaces];      /* per-iface OS fp off      */
    char      confFilePath[512];
    int       confLoaded;
    char      alertScript[maxScriptPath];
    char      logDir[maxLogDirPath];
    long      logMaxMb;       /* rotate when log exceeds this many MB; 0=off */

    WatchPort watchPorts[maxWatchPorts];
    int       watchCount;
} Config;

/* ── per-interface capture context ───────────────────────────────────── */
typedef struct {
    char    name[maxIfaceNameLen];
    pcap_t *handle;
    int     isInternal;    /* 1 = suppress bogon/martian/smurf on this iface */
    int     noAckScan;     /* 1 = suppress ACK scan on this iface            */
    int     noFinScan;     /* 1 = suppress FIN scan on this iface            */
    int     noMaimonScan;  /* 1 = suppress Maimon scan on this iface         */
    int     noOsFingerprint;/* 1 = suppress OS fingerprint on this iface     */
} IfaceCtx;

/* ── per-IP tracking ─────────────────────────────────────────────────── */
typedef struct IpStats {
    uint32_t  ip;
    time_t    windowStart;

    /* existing scan/flood counters */
    uint32_t  synCount;
    uint32_t  icmpCount;
    uint8_t   tcpPorts[maxPorts / 8];
    uint32_t  tcpPortCount;
    uint8_t   udpPorts[maxPorts / 8];
    uint32_t  udpPortCount;

    /* new flood counters */
    uint32_t  rstCount;
    uint32_t  finCount;
    uint32_t  udpFloodCount;    /* UDP pkts to any single dst IP           */
    uint32_t  fragCount;        /* fragmented IP packets sent              */

    /* amplification counters */
    uint32_t  dnsCount;
    uint32_t  ntpCount;
    uint32_t  ssdpCount;

    /* ping sweep: bitset of distinct destination IPs hashed to maxSweepDstIps */
    uint8_t   sweepDsts[maxSweepDstIps / 8];
    uint32_t  sweepCount;

    /* brute-force per watched port */
    uint32_t  bruteAttempts[maxWatchPorts];
    int       alertedBrute[maxWatchPorts];

    /* alert suppression flags */
    int       alertedPortScan;
    int       alertedSynFlood;
    int       alertedIcmpFlood;
    int       alertedUdpScan;
    int       alertedUdpFlood;
    int       alertedRstFlood;
    int       alertedFinFlood;
    int       alertedPingSweep;
    int       alertedDnsAmp;
    int       alertedNtpAmp;
    int       alertedSsdpAmp;
    int       alertedFragFlood;

    struct IpStats *next;
} IpStats;

/* ── globals ─────────────────────────────────────────────────────────── */
static IpStats        *ipTable[maxTrackedIps];
static long            totalPackets = 0;
static long            totalAlerts  = 0;
static Config          cfg;
static pthread_mutex_t gLock      = PTHREAD_MUTEX_INITIALIZER;
static pcap_t         *gHandles[maxInterfaces];
static int             gHandleCount = 0;

/* ════════════════════════════════════════════════════════════════════════
 *  IP classification helpers
 * ════════════════════════════════════════════════════════════════════════ */

/* Return 1 if ip (host byte order) is a bogon source: RFC-1918, loopback,
   link-local APIPA, or the "this network" 0.x.x.x block.                 */
static int isBogon(uint32_t ip) {
    return ((ip & 0xFF000000) == 0x0A000000) ||  /* 10.0.0.0/8            */
           ((ip & 0xFFF00000) == 0xAC100000) ||  /* 172.16.0.0/12         */
           ((ip & 0xFFFF0000) == 0xC0A80000) ||  /* 192.168.0.0/16        */
           ((ip & 0xFF000000) == 0x7F000000) ||  /* 127.0.0.0/8 loopback  */
           ((ip & 0xFFFF0000) == 0xA9FE0000) ||  /* 169.254.0.0/16 APIPA  */
           ((ip & 0xFF000000) == 0x00000000);    /* 0.0.0.0/8             */
}

/* Return 1 if ip (host byte order) is a martian (reserved/unallocated).  */
static int isMartian(uint32_t ip) {
    return ((ip & 0xF0000000) == 0xF0000000) ||  /* 240.0.0.0/4 reserved  */
           ((ip & 0xFF000000) == 0xE0000000) ||  /* 224.0.0.0/8 multicast */
           (ip == 0xFFFFFFFF);                   /* limited broadcast      */
}

/* Return 1 if ip (host byte order) is a broadcast or multicast address.  */
static int isBroadcastOrMulticast(uint32_t ip) {
    return ((ip & 0xF0000000) == 0xE0000000) ||  /* multicast 224/4       */
           ((ip & 0x000000FF) == 0x000000FF) ||  /* subnet broadcast .255 */
           (ip == 0xFFFFFFFF);                   /* limited broadcast      */
}

/* ════════════════════════════════════════════════════════════════════════
 *  Daily log file
 * ════════════════════════════════════════════════════════════════════════ */

static int ensureLogDir(const char *dir) {
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

static void todayLogPath(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char date[16];
    strftime(date, sizeof(date), "%Y%m%d", tm);
    snprintf(buf, len, "%s/%s.log", cfg.logDir, date);
}

/*
 * Rotate today's log file when it exceeds cfg.logMaxMb megabytes.
 * The full log is renamed  YYYYMMDD_1.log, YYYYMMDD_2.log, … until a free
 * slot is found, then a fresh YYYYMMDD.log is started with a new header.
 * Called with gLock held and only when logMaxMb > 0.
 */
static void rotateTodayLog(const char *path) {
    char rotated[maxLogDirPath + 40];
    /* strip the .log suffix to build the base name */
    char base[maxLogDirPath + 20];
    snprintf(base, sizeof(base), "%s", path);
    char *dot = strrchr(base, '.');
    if (dot) *dot = '\0';

    for (int n = 1; n < 10000; n++) {
        snprintf(rotated, sizeof(rotated), "%s_%d.log", base, n);
        if (access(rotated, F_OK) != 0) {
            if (rename(path, rotated) != 0)
                fprintf(stderr, YELLOW "[tigernet] " RESET
                        "log rotate: rename failed: %s\n", strerror(errno));
            else
                printf(DIM "[tigernet] rotated %s -> %s\n" RESET, path, rotated);
            return;
        }
    }
    fprintf(stderr, YELLOW "[tigernet] " RESET
            "log rotate: no free slot found for %s, keeping current file\n", path);
}

static void writeLogEntry(const char *timestamp, const char *type,
                          const char *srcIp, const char *iface,
                          const char *detail) {
    if (cfg.logDir[0] == '\0') return;
    char path[maxLogDirPath + 20];
    todayLogPath(path, sizeof(path));

    /* size-based rotation: check before opening */
    if (cfg.logMaxMb > 0 && access(path, F_OK) == 0) {
        struct stat st;
        if (stat(path, &st) == 0) {
            long limitBytes = cfg.logMaxMb * 1024L * 1024L;
            if (st.st_size >= limitBytes)
                rotateTodayLog(path);
        }
    }

    int newFile = (access(path, F_OK) != 0);
    FILE *f = fopen(path, "a");
    if (!f) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "cannot open log file '%s': %s\n", path, strerror(errno));
        return;
    }
    if (newFile)
        fprintf(f, "# TIMESTAMP\tTYPE\tSRC_IP\tIFACE\tDETAIL\n");
    fprintf(f, "%s\t%s\t%s\t%s\t%s\n", timestamp, type, srcIp, iface, detail);
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
                    "fork failed: %s\n", strerror(errno));
        return;
    }
    if (pid > 0) { waitpid(pid, NULL, 0); return; }
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);
    setsid();
    if (!cfg.verbose) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
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

static int addWatchPort(Config *c, uint16_t port, const char *name, int thr) {
    for (int i = 0; i < c->watchCount; i++) {
        if (c->watchPorts[i].port == port) {
            snprintf(c->watchPorts[i].name, sizeof(c->watchPorts[i].name), "%s", name);
            c->watchPorts[i].threshold = thr;
            return 1;
        }
    }
    if (c->watchCount >= maxWatchPorts) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "watch table full, ignoring port %u\n", port);
        return 0;
    }
    WatchPort *wp = &c->watchPorts[c->watchCount++];
    wp->port = port; wp->threshold = thr;
    snprintf(wp->name, sizeof(wp->name), "%s", name);
    return 1;
}

static int parseWatchSpec(Config *c, const char *spec) {
    char buf[128];
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
    if (nameStr && *nameStr) snprintf(name, sizeof(name), "%s", nameStr);
    else                     snprintf(name, sizeof(name), "port%d", port);
    int thr = (thrStr && *thrStr) ? atoi(thrStr) : defBruteThreshold;
    if (thr < 1) thr = 1;
    return addWatchPort(c, (uint16_t)port, name, thr);
}

/* ── interface list ──────────────────────────────────────────────────── */

static int addInterface(Config *c, const char *name) {
    for (int i = 0; i < c->ifaceCount; i++)
        if (strcmp(c->ifaceNames[i], name) == 0) return 1;
    if (c->ifaceCount >= maxInterfaces) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "interface limit reached, ignoring '%s'\n", name);
        return 0;
    }
    snprintf(c->ifaceNames[c->ifaceCount++], maxIfaceNameLen, "%s", name);
    return 1;
}

/* Mark an interface as internal (suppress bogon/martian/smurf on it).
   If the interface has not been added yet it is added first.              */
static int markInternalIface(Config *c, const char *name) {
    /* ensure the interface exists in the list */
    addInterface(c, name);
    for (int i = 0; i < c->ifaceCount; i++) {
        if (strcmp(c->ifaceNames[i], name) == 0) {
            c->internalIface[i] = 1;
            return 1;
        }
    }
    return 0;
}

/* Mark per-interface scan-check overrides.  iface must already exist or  *
 * will be added.  field is one of the ifaceNo* arrays in Config.          */
static int markIfaceScan(Config *c, const char *name, int *arr) {
    addInterface(c, name);
    for (int i = 0; i < c->ifaceCount; i++) {
        if (strcmp(c->ifaceNames[i], name) == 0) { arr[i] = 1; return 1; }
    }
    return 0;
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
    return strcasecmp(v,"true")==0 || strcasecmp(v,"yes")==0 || strcmp(v,"1")==0;
}

static int loadConfig(Config *c) {
    FILE *f = fopen(c->confFilePath, "r");
    if (!f) return 0;
    char line[512]; int lineNo = 0;
    while (fgets(line, sizeof(line), f)) {
        lineNo++;
        char *p = strchr(line, '#'); if (p) *p = '\0';
        p = trimWhitespace(line); if (*p == '\0') continue;
        char *eq = strchr(p, '=');
        if (!eq) { fprintf(stderr, YELLOW "[tigernet] " RESET
                "conf:%d: no '=' found, skipped\n", lineNo); continue; }
        *eq = '\0';
        char *key = trimWhitespace(p);
        char *val = trimWhitespace(eq + 1);

        if      (!strcmp(key,"interface"))   addInterface(c, val);
        else if (!strcmp(key,"window"))      c->windowSeconds       = atoi(val);
        else if (!strcmp(key,"portScan"))    c->portScanThreshold   = atoi(val);
        else if (!strcmp(key,"synFlood"))    c->synFloodThreshold   = atoi(val);
        else if (!strcmp(key,"icmpFlood"))   c->icmpFloodThreshold  = atoi(val);
        else if (!strcmp(key,"udpScan"))     c->udpScanThreshold    = atoi(val);
        else if (!strcmp(key,"udpFlood"))    c->udpFloodThreshold   = atoi(val);
        else if (!strcmp(key,"rstFlood"))    c->rstFloodThreshold   = atoi(val);
        else if (!strcmp(key,"finFlood"))    c->finFloodThreshold   = atoi(val);
        else if (!strcmp(key,"pingSweep"))   c->pingSweepThreshold  = atoi(val);
        else if (!strcmp(key,"dnsAmp"))      c->dnsAmpThreshold     = atoi(val);
        else if (!strcmp(key,"ntpAmp"))      c->ntpAmpThreshold     = atoi(val);
        else if (!strcmp(key,"ssdpAmp"))     c->ssdpAmpThreshold    = atoi(val);
        else if (!strcmp(key,"fragFlood"))   c->fragFloodThreshold  = atoi(val);
        else if (!strcmp(key,"verbose"))      c->verbose             = parseBool(val);
        else if (!strcmp(key,"noBogon"))        c->noBogon              = parseBool(val);
        else if (!strcmp(key,"noAckScan"))       c->noAckScan            = parseBool(val);
        else if (!strcmp(key,"noFinScan"))       c->noFinScan            = parseBool(val);
        else if (!strcmp(key,"noMaimonScan"))    c->noMaimonScan         = parseBool(val);
        else if (!strcmp(key,"noOsFingerprint")) c->noOsFingerprint      = parseBool(val);
        else if (!strcmp(key,"internalIface"))   markInternalIface(c, val);
        else if (!strcmp(key,"ifaceNoAckScan"))  markIfaceScan(c, val, cfg.ifaceNoAckScan);
        else if (!strcmp(key,"ifaceNoFinScan"))  markIfaceScan(c, val, cfg.ifaceNoFinScan);
        else if (!strcmp(key,"ifaceNoMaimon"))   markIfaceScan(c, val, cfg.ifaceNoMaimon);
        else if (!strcmp(key,"ifaceNoOsFp"))     markIfaceScan(c, val, cfg.ifaceNoOsFp);
        else if (!strcmp(key,"watch"))        parseWatchSpec(c, val);
        else if (!strcmp(key,"alertScript")) snprintf(c->alertScript,sizeof(c->alertScript),"%s",val);
        else if (!strcmp(key,"logDir"))      snprintf(c->logDir,     sizeof(c->logDir),     "%s",val);
        else if (!strcmp(key,"logMaxMb"))    c->logMaxMb = atol(val);
        else fprintf(stderr, YELLOW "[tigernet] " RESET
                "conf:%d: unknown key '%s', skipped\n", lineNo, key);
    }
    fclose(f);
    return 1;
}

static void writeDefaultConfig(const char *path) {
    char dir[512]; snprintf(dir, sizeof(dir), "%s", path);
    char *sl = strrchr(dir, '/'); if (sl) { *sl = '\0'; mkdir(dir, 0700); }
    FILE *f = fopen(path, "w"); if (!f) return;
    fprintf(f,
        "# tigernet configuration file\n#\n"
        "# interface   = eth0    # repeatable\n"
        "# interface   = eth1\n#\n"
        "# window      = %d\n"
        "# portScan    = %d\n"
        "# synFlood    = %d\n"
        "# icmpFlood   = %d\n"
        "# udpScan     = %d\n"
        "# udpFlood    = %d\n"
        "# rstFlood    = %d\n"
        "# finFlood    = %d\n"
        "# pingSweep   = %d\n"
        "# dnsAmp      = %d\n"
        "# ntpAmp      = %d\n"
        "# ssdpAmp     = %d\n"
        "# fragFlood   = %d\n"
        "# verbose       = false\n"
        "#\n"
        "# Bogon/martian/smurf suppression:\n"
        "# noBogon         = false  # disable bogon/martian/smurf globally\n"
        "# internalIface   = eth0   # suppress bogon on one interface (repeatable)\n"
        "#\n"
        "# Stealth-scan suppression (useful on internal/LAN interfaces):\n"
        "# noAckScan        = false  # disable TCP ACK scan globally\n"
        "# noFinScan        = false  # disable TCP FIN scan globally\n"
        "# noMaimonScan     = false  # disable TCP Maimon scan globally\n"
        "# noOsFingerprint  = false  # disable OS fingerprint probe globally\n"
        "#\n"
        "# Per-interface stealth-scan suppression:\n"
        "# ifaceNoAckScan  = eth1   # suppress ACK scan on one interface (repeatable)\n"
        "# ifaceNoFinScan  = eth1   # suppress FIN scan on one interface (repeatable)\n"
        "# ifaceNoMaimon   = eth1   # suppress Maimon scan on one interface\n"
        "# ifaceNoOsFp     = eth1   # suppress OS fingerprint on one interface\n"
        "#\n"
        "# alertScript = /etc/tigernet/alert_udp.sh\n"
        "# logDir      = /var/log/tigernet\n"
        "# logMaxMb    = 0              # rotate log when it reaches N MB (0 = disabled)\n"
        "#\n"
        "# watch = 22:SSH:%d\n"
        "# watch = 3389:RDP:%d\n"
        "# watch = 5900:VNC:%d\n",
        defWindowSeconds, defPortScanThreshold, defSynFloodThreshold,
        defIcmpFloodThreshold, defUdpScanThreshold, defUdpFloodThreshold,
        defRstFloodThreshold, defFinFloodThreshold, defPingSweepThreshold,
        defDnsAmpThreshold, defNtpAmpThreshold, defSsdpAmpThreshold,
        defFragFloodThreshold,
        defBruteThreshold, defBruteThreshold, defBruteThreshold);
    fclose(f);
    printf(DIM "[tigernet] Created default config: %s\n" RESET, path);
}

/* ════════════════════════════════════════════════════════════════════════
 *  Packet-processing helpers  (called with gLock held)
 * ════════════════════════════════════════════════════════════════════════ */

static const char *ipToStr(uint32_t ip) {
    struct in_addr a = { .s_addr = ip }; return inet_ntoa(a);
}

static uint32_t hashIp(uint32_t ip) {
    ip ^= ip >> 16; ip *= 0x45d9f3b; ip ^= ip >> 16;
    return ip % maxTrackedIps;
}

static IpStats *getStats(uint32_t ip) {
    uint32_t idx = hashIp(ip); IpStats *s = ipTable[idx];
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
    s->synCount     = s->icmpCount    = s->tcpPortCount = s->udpPortCount = 0;
    s->rstCount     = s->finCount     = s->udpFloodCount = s->fragCount   = 0;
    s->dnsCount     = s->ntpCount     = s->ssdpCount    = s->sweepCount   = 0;
    s->alertedPortScan = s->alertedSynFlood = s->alertedIcmpFlood = 0;
    s->alertedUdpScan  = s->alertedUdpFlood = s->alertedRstFlood  = 0;
    s->alertedFinFlood = s->alertedPingSweep = 0;
    s->alertedDnsAmp   = s->alertedNtpAmp   = s->alertedSsdpAmp   = 0;
    s->alertedFragFlood = 0;
    memset(s->bruteAttempts, 0, sizeof(s->bruteAttempts));
    memset(s->alertedBrute,  0, sizeof(s->alertedBrute));
    memset(s->tcpPorts,  0, sizeof(s->tcpPorts));
    memset(s->udpPorts,  0, sizeof(s->udpPorts));
    memset(s->sweepDsts, 0, sizeof(s->sweepDsts));
    s->windowStart = now;
}

static int markPort(uint8_t *bitset, uint16_t port) {
    uint8_t bit = 1u << (port % 8);
    if (bitset[port / 8] & bit) return 0;
    bitset[port / 8] |= bit; return 1;
}

/* Mark a destination IP in the ping-sweep bitset; return 1 if new. */
static int markSweepDst(IpStats *s, uint32_t dstIp) {
    uint32_t slot = (dstIp ^ (dstIp >> 16)) % maxSweepDstIps;
    uint8_t  bit  = 1u << (slot % 8);
    if (s->sweepDsts[slot / 8] & bit) return 0;
    s->sweepDsts[slot / 8] |= bit; return 1;
}

/* ── alert / info output  (called with gLock held) ───────────────────── */

static void isoTimestamp(char *buf, size_t len) {
    time_t t = time(NULL);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
}

static void fireAlert(const char *type, const char *srcIp,
                      const char *detail, const char *iface) {
    char ts[24]; isoTimestamp(ts, sizeof(ts));
    printf(DIM "%.8s " RESET BOLD RED "[ALERT] " RESET
           BOLD "%-26s" RESET "  src=%-16s  if=%-8s  %s\n",
           ts + 11, type, srcIp, iface, detail);
    fflush(stdout);
    totalAlerts++;
    writeLogEntry(ts, type, srcIp, iface, detail);
    runAlertScript(type, srcIp, detail, ts, iface);
}

static void logInfo(const char *fmt, ...) {
    if (!cfg.verbose) return;
    va_list ap; va_start(ap, fmt);
    printf(CYAN "[info]  " RESET); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}

/* ════════════════════════════════════════════════════════════════════════
 *  Protocol handlers  (called with gLock held)
 * ════════════════════════════════════════════════════════════════════════ */

/* ── IP-level checks (called before dispatching to TCP/UDP/ICMP) ──────── */
/*
 * suppressBogon is 1 when either --no-bogon is set globally OR the packet
 * arrived on an interface marked with --internal-iface.  In that case the
 * bogon, martian, and smurf checks are skipped; the land-attack check still
 * runs because a src==dst packet is suspicious even on an internal network.
 */
static void checkIpAnomalies(const struct ip *iph, const char *srcIp,
                              const char *iface, int suppressBogon) {
    uint32_t src = ntohl(iph->ip_src.s_addr);
    uint32_t dst = ntohl(iph->ip_dst.s_addr);

    /* Land attack: src == dst — always checked */
    if (iph->ip_src.s_addr == iph->ip_dst.s_addr) {
        char d[80];
        snprintf(d, sizeof(d), "src IP == dst IP (%s)", srcIp);
        fireAlert("LAND ATTACK", srcIp, d, iface);
    }

    if (suppressBogon) return;

    /* Bogon source IP */
    if (isBogon(src)) {
        char d[80];
        snprintf(d, sizeof(d), "RFC-1918/loopback/APIPA source %s on wire", srcIp);
        fireAlert("BOGON SOURCE", srcIp, d, iface);
    }

    /* Martian source IP */
    if (isMartian(src)) {
        char d[80];
        snprintf(d, sizeof(d), "reserved/unallocated source %s", srcIp);
        fireAlert("MARTIAN PACKET", srcIp, d, iface);
    }

    /* Smurf indicator: ICMP echo to broadcast/multicast destination */
    if (iph->ip_p == IPPROTO_ICMP && isBroadcastOrMulticast(dst)) {
        char d[80];
        snprintf(d, sizeof(d), "ICMP echo to broadcast/multicast dst %s",
                 ipToStr(iph->ip_dst.s_addr));
        fireAlert("SMURF INDICATOR", srcIp, d, iface);
    }
}

/* ── IP fragmentation flood ──────────────────────────────────────────── */
static void checkFragFlood(IpStats *s, const struct ip *iph,
                           const char *srcIp, const char *iface) {
    uint16_t fragOff = ntohs(iph->ip_off);
    int isFrag = (fragOff & IP_MF) || (fragOff & IP_OFFMASK);
    if (!isFrag) return;

    s->fragCount++;
    logInfo("IP fragment from %s on %s  (count=%u)", srcIp, iface, s->fragCount);
    if (s->fragCount >= (uint32_t)cfg.fragFloodThreshold && !s->alertedFragFlood) {
        char d[80];
        snprintf(d, sizeof(d), "%u fragmented packets in %ds window",
                 s->fragCount, cfg.windowSeconds);
        fireAlert("FRAGMENT FLOOD", srcIp, d, iface);
        s->alertedFragFlood = 1;
    }
}

/* ── TCP handler ─────────────────────────────────────────────────────── */
static void handleTcp(IpStats *s, const struct tcphdr *tcp,
                      const u_char *payload, size_t payloadLen,
                      const char *srcIp, const char *iface,
                      const IfaceCtx *ctx) {
    uint16_t dport = ntohs(tcp->dest);
    uint8_t  flags = tcp->th_flags;

    /* ── Stealth scan family ─────────────────────────────────────────── */

    /* Null scan: no flags */
    if (flags == 0) {
        char d[64]; snprintf(d,sizeof(d),"TCP NULL scan -> port %u",dport);
        fireAlert("TCP NULL SCAN", srcIp, d, iface); return;
    }

    /* Xmas scan: FIN+PSH+URG */
    if ((flags & (TH_FIN|TH_PUSH|TH_URG)) == (TH_FIN|TH_PUSH|TH_URG)) {
        char d[64]; snprintf(d,sizeof(d),"TCP Xmas scan -> port %u",dport);
        fireAlert("TCP XMAS SCAN", srcIp, d, iface); return;
    }

    /* FIN scan: only FIN */
    if (flags == TH_FIN && !cfg.noFinScan && !ctx->noFinScan) {
        char d[64]; snprintf(d,sizeof(d),"TCP FIN scan -> port %u",dport);
        fireAlert("TCP FIN SCAN", srcIp, d, iface); return;
    }

    /* ACK scan: only ACK */
    if (flags == TH_ACK && !cfg.noAckScan && !ctx->noAckScan) {
        char d[64]; snprintf(d,sizeof(d),"TCP ACK scan -> port %u",dport);
        fireAlert("TCP ACK SCAN", srcIp, d, iface); return;
    }

    /* Maimon scan: FIN+ACK */
    if (flags == (TH_FIN|TH_ACK) && !cfg.noMaimonScan && !ctx->noMaimonScan) {
        char d[64]; snprintf(d,sizeof(d),"TCP Maimon scan -> port %u",dport);
        fireAlert("TCP MAIMON SCAN", srcIp, d, iface); return;
    }

    int isSyn = (flags & TH_SYN) && !(flags & TH_ACK);
    int isRst = (flags & TH_RST) && !isSyn;
    int isFin = (flags & TH_FIN) && !(flags & TH_SYN) && !(flags & TH_ACK);

    /* ── OS fingerprint probe: SYN with zero window size ─────────────── */
    if (isSyn && ntohs(tcp->th_win) == 0
            && !cfg.noOsFingerprint && !ctx->noOsFingerprint) {
        char d[80];
        snprintf(d, sizeof(d), "TCP SYN with zero window -> port %u (nmap -O probe)", dport);
        fireAlert("OS FINGERPRINT PROBE", srcIp, d, iface);
    }

    /* ── SMB exploit probe: SYN burst to port 445 ────────────────────── */
    if (isSyn && dport == 445) {
        s->synCount++;   /* piggy-back on synCount for SMB threshold */
        if (s->synCount >= (uint32_t)cfg.synFloodThreshold && !s->alertedSynFlood) {
            char d[80];
            snprintf(d, sizeof(d), "%u SYN packets to SMB port 445 in %ds window",
                     s->synCount, cfg.windowSeconds);
            fireAlert("SMB EXPLOIT PROBE", srcIp, d, iface);
            s->alertedSynFlood = 1;
        }
    }

    /* ── Brute-force detection ───────────────────────────────────────── */
    if (isSyn) {
        for (int i = 0; i < cfg.watchCount; i++) {
            if (dport == cfg.watchPorts[i].port) {
                s->bruteAttempts[i]++;
                logInfo("%s attempt from %s on %s (count=%u)",
                        cfg.watchPorts[i].name, srcIp, iface, s->bruteAttempts[i]);
                if (s->bruteAttempts[i] >= (uint32_t)cfg.watchPorts[i].threshold
                        && !s->alertedBrute[i]) {
                    char at[48], d[96];
                    snprintf(at, sizeof(at), "%s BRUTE-FORCE", cfg.watchPorts[i].name);
                    snprintf(d, sizeof(d), "%u attempts to %s (port %u) in %ds window",
                             s->bruteAttempts[i], cfg.watchPorts[i].name,
                             cfg.watchPorts[i].port, cfg.windowSeconds);
                    fireAlert(at, srcIp, d, iface);
                    s->alertedBrute[i] = 1;
                }
                break;
            }
        }
    }

    /* ── SYN flood ───────────────────────────────────────────────────── */
    if (isSyn && dport != 445) {   /* 445 handled above as SMB */
        s->synCount++;
        logInfo("SYN from %s -> port %u on %s (count=%u)", srcIp, dport, iface, s->synCount);
        if (s->synCount >= (uint32_t)cfg.synFloodThreshold && !s->alertedSynFlood) {
            char d[80];
            snprintf(d, sizeof(d), "%u SYN packets in %ds window",
                     s->synCount, cfg.windowSeconds);
            fireAlert("SYN FLOOD", srcIp, d, iface);
            s->alertedSynFlood = 1;
        }
    }

    /* ── RST flood ───────────────────────────────────────────────────── */
    if (isRst) {
        s->rstCount++;
        logInfo("RST from %s on %s (count=%u)", srcIp, iface, s->rstCount);
        if (s->rstCount >= (uint32_t)cfg.rstFloodThreshold && !s->alertedRstFlood) {
            char d[80];
            snprintf(d, sizeof(d), "%u RST packets in %ds window",
                     s->rstCount, cfg.windowSeconds);
            fireAlert("TCP RST FLOOD", srcIp, d, iface);
            s->alertedRstFlood = 1;
        }
    }

    /* ── FIN flood ───────────────────────────────────────────────────── */
    if (isFin) {
        s->finCount++;
        logInfo("FIN from %s on %s (count=%u)", srcIp, iface, s->finCount);
        if (s->finCount >= (uint32_t)cfg.finFloodThreshold && !s->alertedFinFlood) {
            char d[80];
            snprintf(d, sizeof(d), "%u FIN packets in %ds window",
                     s->finCount, cfg.windowSeconds);
            fireAlert("TCP FIN FLOOD", srcIp, d, iface);
            s->alertedFinFlood = 1;
        }
    }

    /* ── TCP port scan ───────────────────────────────────────────────── */
    if (markPort(s->tcpPorts, dport)) {
        s->tcpPortCount++;
        logInfo("new TCP port %u from %s on %s (distinct=%u)",
                dport, srcIp, iface, s->tcpPortCount);
        if (s->tcpPortCount >= (uint32_t)cfg.portScanThreshold && !s->alertedPortScan) {
            char d[80];
            snprintf(d, sizeof(d), "%u distinct TCP ports in %ds window",
                     s->tcpPortCount, cfg.windowSeconds);
            fireAlert("TCP PORT SCAN", srcIp, d, iface);
            s->alertedPortScan = 1;
        }
    }

    /* ── Application-layer payload inspection ────────────────────────── */
    if (payloadLen >= 4 &&
        (dport == 80 || dport == 443 || dport == 8080 ||
         ntohs(tcp->source) == 80 || ntohs(tcp->source) == 443)) {

        /* HTTP directory traversal: look for ../ in payload */
        const char *p = (const char *)payload;
        size_t      pLen = payloadLen > 512 ? 512 : payloadLen;
        if (memmem(p, pLen, "../", 3) || memmem(p, pLen, "..\\", 3)) {
            fireAlert("HTTP DIR TRAVERSAL", srcIp,
                      "path traversal sequence '../' in HTTP payload", iface);
        }

        /* HTTP scanner User-Agent strings */
        static const char * const scanners[] = {
            "Nikto", "sqlmap", "Masscan", "ZGrab", "Nmap",
            "dirbuster", "gobuster", "nuclei", "zgrab", NULL
        };
        for (int i = 0; scanners[i]; i++) {
            if (memmem(p, pLen, scanners[i], strlen(scanners[i]))) {
                char d[80];
                snprintf(d, sizeof(d), "scanner User-Agent '%s' in HTTP payload",
                         scanners[i]);
                fireAlert("HTTP SCANNER", srcIp, d, iface);
                break;  /* one alert per packet */
            }
        }
    }
}

/* ── UDP handler ─────────────────────────────────────────────────────── */
static void handleUdp(IpStats *s, const struct udphdr *udp,
                      uint32_t dstIp,
                      const char *srcIp, const char *iface) {
    uint16_t dport = ntohs(udp->uh_dport);

    /* ── Amplification: DNS (53) ─────────────────────────────────────── */
    if (dport == 53) {
        s->dnsCount++;
        logInfo("UDP DNS from %s on %s (count=%u)", srcIp, iface, s->dnsCount);
        if (s->dnsCount >= (uint32_t)cfg.dnsAmpThreshold && !s->alertedDnsAmp) {
            char d[80];
            snprintf(d, sizeof(d), "%u UDP packets to port 53 in %ds window",
                     s->dnsCount, cfg.windowSeconds);
            fireAlert("DNS AMPLIFICATION", srcIp, d, iface);
            s->alertedDnsAmp = 1;
        }
        return;
    }

    /* ── Amplification: NTP (123) ────────────────────────────────────── */
    if (dport == 123) {
        s->ntpCount++;
        if (s->ntpCount >= (uint32_t)cfg.ntpAmpThreshold && !s->alertedNtpAmp) {
            char d[80];
            snprintf(d, sizeof(d), "%u UDP packets to port 123 in %ds window",
                     s->ntpCount, cfg.windowSeconds);
            fireAlert("NTP AMPLIFICATION", srcIp, d, iface);
            s->alertedNtpAmp = 1;
        }
        return;
    }

    /* ── Amplification: SSDP (1900) ──────────────────────────────────── */
    if (dport == 1900) {
        s->ssdpCount++;
        if (s->ssdpCount >= (uint32_t)cfg.ssdpAmpThreshold && !s->alertedSsdpAmp) {
            char d[80];
            snprintf(d, sizeof(d), "%u UDP packets to port 1900 in %ds window",
                     s->ssdpCount, cfg.windowSeconds);
            fireAlert("SSDP AMPLIFICATION", srcIp, d, iface);
            s->alertedSsdpAmp = 1;
        }
        return;
    }

    /* ── UDP flood (high rate to one dst IP) ─────────────────────────── */
    (void)dstIp;   /* tracked by per-source counter as a proxy */
    s->udpFloodCount++;
    logInfo("UDP flood from %s on %s (count=%u)", srcIp, iface, s->udpFloodCount);
    if (s->udpFloodCount >= (uint32_t)cfg.udpFloodThreshold && !s->alertedUdpFlood) {
        char d[80];
        snprintf(d, sizeof(d), "%u UDP packets in %ds window",
                 s->udpFloodCount, cfg.windowSeconds);
        fireAlert("UDP FLOOD", srcIp, d, iface);
        s->alertedUdpFlood = 1;
    }

    /* ── UDP port scan (distinct ports) ──────────────────────────────── */
    if (markPort(s->udpPorts, dport)) {
        s->udpPortCount++;
        logInfo("new UDP port %u from %s on %s (distinct=%u)",
                dport, srcIp, iface, s->udpPortCount);
        if (s->udpPortCount >= (uint32_t)cfg.udpScanThreshold && !s->alertedUdpScan) {
            char d[80];
            snprintf(d, sizeof(d), "%u distinct UDP ports in %ds window",
                     s->udpPortCount, cfg.windowSeconds);
            fireAlert("UDP PORT SCAN", srcIp, d, iface);
            s->alertedUdpScan = 1;
        }
    }
}

/* ── ICMP handler ────────────────────────────────────────────────────── */
static void handleIcmp(IpStats *s, const struct icmphdr *icmp,
                       uint32_t dstIp, const struct ip *iph,
                       const char *srcIp, const char *iface) {
    /* ICMP fragment flood: More Fragments bit set on ICMP */
    uint16_t fragOff = ntohs(iph->ip_off);
    if (fragOff & IP_MF) {
        char d[80];
        snprintf(d, sizeof(d), "ICMP fragment (MF bit set) from %s", srcIp);
        fireAlert("ICMP FRAGMENT FLOOD", srcIp, d, iface);
    }

    /* Ping sweep: many different destination IPs */
    if (icmp->type == ICMP_ECHO) {
        if (markSweepDst(s, dstIp)) {
            s->sweepCount++;
            logInfo("ping sweep from %s on %s (distinct dsts=%u)",
                    srcIp, iface, s->sweepCount);
            if (s->sweepCount >= (uint32_t)cfg.pingSweepThreshold
                    && !s->alertedPingSweep) {
                char d[80];
                snprintf(d, sizeof(d),
                         "%u distinct destination IPs pinged in %ds window",
                         s->sweepCount, cfg.windowSeconds);
                fireAlert("PING SWEEP", srcIp, d, iface);
                s->alertedPingSweep = 1;
            }
        }
    }

    /* ICMP flood: high rate from one source */
    s->icmpCount++;
    logInfo("ICMP from %s on %s (count=%u)", srcIp, iface, s->icmpCount);
    if (s->icmpCount >= (uint32_t)cfg.icmpFloodThreshold && !s->alertedIcmpFlood) {
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

    uint32_t      srcIp    = iph->ip_src.s_addr;
    uint32_t      dstIp    = iph->ip_dst.s_addr;
    int           ipHdrLen = iph->ip_hl * 4;
    const u_char *transport = (const u_char *)iph + ipHdrLen;
    size_t        remaining = header->caplen
                              - sizeof(struct ether_header)
                              - (size_t)ipHdrLen;

    pthread_mutex_lock(&gLock);

    const char *srcStr = ipToStr(srcIp);
    IpStats    *s      = getStats(srcIp);
    maybeResetWindow(s);
    totalPackets++;

    /* IP-level anomaly checks (land, bogon, martian, smurf) */
    int suppressBogon = cfg.noBogon || ctx->isInternal;
    checkIpAnomalies(iph, srcStr, ctx->name, suppressBogon);

    /* IP fragmentation flood */
    checkFragFlood(s, iph, srcStr, ctx->name);

    switch (iph->ip_p) {
    case IPPROTO_TCP:
        if (remaining >= sizeof(struct tcphdr)) {
            const struct tcphdr *tcp = (const struct tcphdr *)transport;
            size_t tcpHdrLen = tcp->th_off * 4;
            const u_char *payload = transport + tcpHdrLen;
            size_t payloadLen = remaining > tcpHdrLen
                                ? remaining - tcpHdrLen : 0;
            handleTcp(s, tcp, payload, payloadLen, srcStr, ctx->name, ctx);
        }
        break;
    case IPPROTO_UDP:
        if (remaining >= sizeof(struct udphdr))
            handleUdp(s, (const struct udphdr *)transport,
                      dstIp, srcStr, ctx->name);
        break;
    case IPPROTO_ICMP:
        if (remaining >= sizeof(struct icmphdr))
            handleIcmp(s, (const struct icmphdr *)transport,
                       dstIp, iph, srcStr, ctx->name);
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
        "  -i, --interface    <dev>         Interface to monitor (repeatable)\n"
        "  -w, --window       <sec>         Time window in seconds      (default: %d)\n"
        "  -p, --port-scan    <n>           TCP port-scan threshold     (default: %d)\n"
        "  -s, --syn-flood    <n>           SYN flood threshold         (default: %d)\n"
        "  -c, --icmp-flood   <n>           ICMP flood threshold        (default: %d)\n"
        "  -u, --udp-scan     <n>           UDP port-scan threshold     (default: %d)\n"
        "      --udp-flood    <n>           UDP flood threshold         (default: %d)\n"
        "      --rst-flood    <n>           TCP RST flood threshold     (default: %d)\n"
        "      --fin-flood    <n>           TCP FIN flood threshold     (default: %d)\n"
        "      --ping-sweep   <n>           Ping sweep threshold        (default: %d)\n"
        "      --dns-amp      <n>           DNS amplification threshold (default: %d)\n"
        "      --ntp-amp      <n>           NTP amplification threshold (default: %d)\n"
        "      --ssdp-amp     <n>           SSDP amplification threshold(default: %d)\n"
        "      --frag-flood   <n>           Fragment flood threshold    (default: %d)\n"
        "      --no-bogon                   Disable bogon/martian/smurf checks globally\n"
        "      --internal-iface <dev>       Suppress bogon checks on one interface (repeatable)\n"
        "      --no-ack-scan                Disable TCP ACK scan detection globally\n"
        "      --no-fin-scan                Disable TCP FIN scan detection globally\n"
        "      --no-maimon-scan             Disable TCP Maimon scan detection globally\n"
        "      --no-os-fingerprint          Disable OS fingerprint probe detection globally\n"
        "      --iface-no-ack-scan <dev>    Suppress ACK scan on one interface (repeatable)\n"
        "      --iface-no-fin-scan <dev>    Suppress FIN scan on one interface (repeatable)\n"
        "      --iface-no-maimon <dev>      Suppress Maimon scan on one interface (repeatable)\n"
        "      --iface-no-os-fp <dev>       Suppress OS fingerprint on one interface (repeatable)\n"
        "      --watch        <p:name:thr>  Watch port for brute-force (repeatable)\n"
        "      --alert-script <path>        Script to run on every alert\n"
        "      --log-dir      <dir>         Directory for YYYYMMDD.log files\n"
        "      --log-max-mb   <n>           Rotate log when it exceeds N MB (default: 0=off)\n"
        "                                     (default: /var/log/tigernet)\n"
        "  -v, --verbose                    Print every packet event\n"
        "  -h, --help                       Show this help\n\n"
        "Config file: ~/.tigernet/tigernet.conf\n"
        "  Keys: interface, window, portScan, synFlood, icmpFlood, udpScan,\n"
        "        udpFlood, rstFlood, finFlood, pingSweep, dnsAmp, ntpAmp,\n"
        "        ssdpAmp, fragFlood, alertScript, logDir, verbose,\n"
        "        noBogon, noAckScan, noFinScan, noMaimonScan, noOsFingerprint,\n"
        "        internalIface, ifaceNoAckScan, ifaceNoFinScan,\n"
        "        ifaceNoMaimon, ifaceNoOsFp (all repeatable per-iface),\n"
        "        watch (repeatable: port:name:threshold)\n",
        prog,
        defWindowSeconds, defPortScanThreshold, defSynFloodThreshold,
        defIcmpFloodThreshold, defUdpScanThreshold, defUdpFloodThreshold,
        defRstFloodThreshold, defFinFloodThreshold, defPingSweepThreshold,
        defDnsAmpThreshold, defNtpAmpThreshold, defSsdpAmpThreshold,
        defFragFloodThreshold);
}

/* ════════════════════════════════════════════════════════════════════════
 *  main
 * ════════════════════════════════════════════════════════════════════════ */

enum {
    optWatch = 1000, optAlertScript, optLogDir,
    optUdpFlood, optRstFlood, optFinFlood, optPingSweep,
    optDnsAmp, optNtpAmp, optSsdpAmp, optFragFlood,
    optLogMaxMb,
    optNoBogon, optInternalIface,
    optNoAckScan, optNoFinScan, optNoMaimonScan, optNoOsFp,
    optIfaceNoAckScan, optIfaceNoFinScan, optIfaceNoMaimon, optIfaceNoOsFp
};

int main(int argc, char *argv[]) {

    /* 1. defaults */
    memset(&cfg, 0, sizeof(cfg));
    cfg.windowSeconds       = defWindowSeconds;
    cfg.portScanThreshold   = defPortScanThreshold;
    cfg.synFloodThreshold   = defSynFloodThreshold;
    cfg.icmpFloodThreshold  = defIcmpFloodThreshold;
    cfg.udpScanThreshold    = defUdpScanThreshold;
    cfg.udpFloodThreshold   = defUdpFloodThreshold;
    cfg.rstFloodThreshold   = defRstFloodThreshold;
    cfg.finFloodThreshold   = defFinFloodThreshold;
    cfg.pingSweepThreshold  = defPingSweepThreshold;
    cfg.dnsAmpThreshold     = defDnsAmpThreshold;
    cfg.ntpAmpThreshold     = defNtpAmpThreshold;
    cfg.ssdpAmpThreshold    = defSsdpAmpThreshold;
    cfg.fragFloodThreshold  = defFragFloodThreshold;
    snprintf(cfg.logDir, sizeof(cfg.logDir), "%s", defLogDir);
    cfg.logMaxMb = defLogMaxMb;

    /* 2. config file path */
    const char *home = getenv("HOME");
    if (home) snprintf(cfg.confFilePath, sizeof(cfg.confFilePath), "%s%s", home, confPath);
    else      snprintf(cfg.confFilePath, sizeof(cfg.confFilePath), ".tigernet/tigernet.conf");

    /* 3. load config file */
    cfg.confLoaded = loadConfig(&cfg);
    if (!cfg.confLoaded && home) writeDefaultConfig(cfg.confFilePath);

    /* 4. default watched ports */
    if (cfg.watchCount == 0) {
        addWatchPort(&cfg,   22, "SSH", defBruteThreshold);
        addWatchPort(&cfg, 3389, "RDP", defBruteThreshold);
    }

    /* 5. CLI flags */
    static const struct option longOpts[] = {
        { "interface",    required_argument, NULL, 'i'           },
        { "window",       required_argument, NULL, 'w'           },
        { "port-scan",    required_argument, NULL, 'p'           },
        { "syn-flood",    required_argument, NULL, 's'           },
        { "icmp-flood",   required_argument, NULL, 'c'           },
        { "udp-scan",     required_argument, NULL, 'u'           },
        { "udp-flood",    required_argument, NULL, optUdpFlood   },
        { "rst-flood",    required_argument, NULL, optRstFlood   },
        { "fin-flood",    required_argument, NULL, optFinFlood   },
        { "ping-sweep",   required_argument, NULL, optPingSweep  },
        { "dns-amp",      required_argument, NULL, optDnsAmp     },
        { "ntp-amp",      required_argument, NULL, optNtpAmp     },
        { "ssdp-amp",     required_argument, NULL, optSsdpAmp    },
        { "frag-flood",   required_argument, NULL, optFragFlood  },
        { "no-bogon",           no_argument,       NULL, optNoBogon        },
        { "internal-iface",     required_argument, NULL, optInternalIface  },
        { "no-ack-scan",        no_argument,       NULL, optNoAckScan      },
        { "no-fin-scan",        no_argument,       NULL, optNoFinScan      },
        { "no-maimon-scan",     no_argument,       NULL, optNoMaimonScan   },
        { "no-os-fingerprint",  no_argument,       NULL, optNoOsFp         },
        { "iface-no-ack-scan",  required_argument, NULL, optIfaceNoAckScan },
        { "iface-no-fin-scan",  required_argument, NULL, optIfaceNoFinScan },
        { "iface-no-maimon",    required_argument, NULL, optIfaceNoMaimon  },
        { "iface-no-os-fp",     required_argument, NULL, optIfaceNoOsFp    },
        { "watch",          required_argument, NULL, optWatch        },
        { "alert-script",   required_argument, NULL, optAlertScript  },
        { "log-dir",      required_argument, NULL, optLogDir     },
        { "log-max-mb",   required_argument, NULL, optLogMaxMb   },
        { "verbose",      no_argument,       NULL, 'v'           },
        { "help",         no_argument,       NULL, 'h'           },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:w:p:s:c:u:vh", longOpts, NULL)) != -1) {
        switch (opt) {
        case 'i': addInterface(&cfg, optarg); break;
        case 'w': cfg.windowSeconds      = atoi(optarg); break;
        case 'p': cfg.portScanThreshold  = atoi(optarg); break;
        case 's': cfg.synFloodThreshold  = atoi(optarg); break;
        case 'c': cfg.icmpFloodThreshold = atoi(optarg); break;
        case 'u': cfg.udpScanThreshold   = atoi(optarg); break;
        case optUdpFlood:   cfg.udpFloodThreshold  = atoi(optarg); break;
        case optRstFlood:   cfg.rstFloodThreshold  = atoi(optarg); break;
        case optFinFlood:   cfg.finFloodThreshold  = atoi(optarg); break;
        case optPingSweep:  cfg.pingSweepThreshold = atoi(optarg); break;
        case optDnsAmp:     cfg.dnsAmpThreshold    = atoi(optarg); break;
        case optNtpAmp:     cfg.ntpAmpThreshold    = atoi(optarg); break;
        case optSsdpAmp:    cfg.ssdpAmpThreshold   = atoi(optarg); break;
        case optFragFlood:  cfg.fragFloodThreshold = atoi(optarg); break;
        case optNoBogon:         cfg.noBogon = 1; break;
        case optInternalIface:   markInternalIface(&cfg, optarg); break;
        case optNoAckScan:       cfg.noAckScan = 1; break;
        case optNoFinScan:       cfg.noFinScan = 1; break;
        case optNoMaimonScan:    cfg.noMaimonScan = 1; break;
        case optNoOsFp:          cfg.noOsFingerprint = 1; break;
        case optIfaceNoAckScan:  markIfaceScan(&cfg, optarg, cfg.ifaceNoAckScan); break;
        case optIfaceNoFinScan:  markIfaceScan(&cfg, optarg, cfg.ifaceNoFinScan); break;
        case optIfaceNoMaimon:   markIfaceScan(&cfg, optarg, cfg.ifaceNoMaimon); break;
        case optIfaceNoOsFp:     markIfaceScan(&cfg, optarg, cfg.ifaceNoOsFp); break;
        case optWatch:
            parseWatchSpec(&cfg, optarg); break;
        case optAlertScript:
            snprintf(cfg.alertScript, sizeof(cfg.alertScript), "%s", optarg); break;
        case optLogDir:
            snprintf(cfg.logDir, sizeof(cfg.logDir), "%s", optarg); break;
        case optLogMaxMb:  cfg.logMaxMb = atol(optarg); break;
        case 'v': cfg.verbose = 1; break;
        case 'h': printUsage(argv[0]); return EXIT_SUCCESS;
        default:  printUsage(argv[0]); return EXIT_FAILURE;
        }
    }

    /* 6. sanity-check all threshold values */
#define CLAMP1(x) if ((x) < 1) (x) = 1
    CLAMP1(cfg.windowSeconds);    CLAMP1(cfg.portScanThreshold);
    CLAMP1(cfg.synFloodThreshold); CLAMP1(cfg.icmpFloodThreshold);
    CLAMP1(cfg.udpScanThreshold);  CLAMP1(cfg.udpFloodThreshold);
    CLAMP1(cfg.rstFloodThreshold); CLAMP1(cfg.finFloodThreshold);
    CLAMP1(cfg.pingSweepThreshold); CLAMP1(cfg.dnsAmpThreshold);
    CLAMP1(cfg.ntpAmpThreshold);   CLAMP1(cfg.ssdpAmpThreshold);
    CLAMP1(cfg.fragFloodThreshold);
#undef CLAMP1

    /* 7. validate alert script */
    if (cfg.alertScript[0] != '\0' && access(cfg.alertScript, X_OK) != 0)
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "warning: alert script '%s' not executable: %s\n",
                cfg.alertScript, strerror(errno));

    /* 8. create log directory */
    if (cfg.logDir[0] != '\0' && !ensureLogDir(cfg.logDir)) {
        fprintf(stderr, YELLOW "[tigernet] " RESET
                "warning: log directory unavailable, file logging disabled\n");
        cfg.logDir[0] = '\0';
    }

    /* 9. auto-detect interface if none specified */
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

    /* 10. open pcap handles */
    static IfaceCtx  ctxArr[maxInterfaces];
    static pthread_t threads[maxInterfaces];

    for (int i = 0; i < cfg.ifaceCount; i++) {
        snprintf(ctxArr[i].name, sizeof(ctxArr[i].name), "%s", cfg.ifaceNames[i]);
        ctxArr[i].isInternal      = cfg.internalIface[i];
        ctxArr[i].noAckScan       = cfg.ifaceNoAckScan[i];
        ctxArr[i].noFinScan       = cfg.ifaceNoFinScan[i];
        ctxArr[i].noMaimonScan    = cfg.ifaceNoMaimon[i];
        ctxArr[i].noOsFingerprint = cfg.ifaceNoOsFp[i];
        ctxArr[i].handle = pcap_open_live(ctxArr[i].name, 65535, 1, 100, errbuf);
        if (!ctxArr[i].handle) {
            fprintf(stderr, "pcap_open_live(%s): %s\n", ctxArr[i].name, errbuf);
            return EXIT_FAILURE;
        }
        struct bpf_program fp;
        if (pcap_compile(ctxArr[i].handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
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

    /* 11. banner */
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
    printf("Window       : %d s\n",             cfg.windowSeconds);
    printf("Port scan    : %d ports/window\n",  cfg.portScanThreshold);
    printf("SYN flood    : %d SYNs/window\n",   cfg.synFloodThreshold);
    printf("ICMP flood   : %d pkts/window\n",   cfg.icmpFloodThreshold);
    printf("UDP scan     : %d ports/window\n",  cfg.udpScanThreshold);
    printf("UDP flood    : %d pkts/window\n",   cfg.udpFloodThreshold);
    printf("RST flood    : %d RSTs/window\n",   cfg.rstFloodThreshold);
    printf("FIN flood    : %d FINs/window\n",   cfg.finFloodThreshold);
    printf("Ping sweep   : %d dst IPs/window\n",cfg.pingSweepThreshold);
    printf("DNS amp      : %d pkts/window\n",   cfg.dnsAmpThreshold);
    printf("NTP amp      : %d pkts/window\n",   cfg.ntpAmpThreshold);
    printf("SSDP amp     : %d pkts/window\n",   cfg.ssdpAmpThreshold);
    printf("Frag flood   : %d frags/window\n",  cfg.fragFloodThreshold);
    /* bogon suppression status */
    if (cfg.noBogon) {
        printf("Bogon checks : " DIM "disabled globally (--no-bogon)" RESET "\n");
    } else {
        int anyInternal = 0;
        for (int i = 0; i < cfg.ifaceCount; i++)
            if (cfg.internalIface[i]) { anyInternal = 1; break; }
        if (anyInternal) {
            printf("Bogon checks : enabled globally; suppressed on internal interfaces:\n");
            for (int i = 0; i < cfg.ifaceCount; i++)
                if (cfg.internalIface[i])
                    printf("  [internal] %s\n", cfg.ifaceNames[i]);
        } else {
            printf("Bogon checks : enabled on all interfaces\n");
        }
    }
    printf("Alert script : %s\n",
           cfg.alertScript[0] ? cfg.alertScript : DIM "(none)" RESET);
    printf("Log dir      : %s\n",
           cfg.logDir[0] ? cfg.logDir : DIM "(disabled)" RESET);
    if (cfg.logDir[0] != '\0') {
        char tp[maxLogDirPath + 20]; todayLogPath(tp, sizeof(tp));
        printf("Today's log  : %s\n", tp);
        if (cfg.logMaxMb > 0)
            printf("Log max size : %ld MB (rotate on exceed)\n", cfg.logMaxMb);
        else
            printf("Log max size : " DIM "unlimited" RESET "\n");
    }
    /* scan-check suppression status */
    {
        const char *checks[4]   = {"ACK scan","FIN scan","Maimon","OS fingerprint"};
        int         global[4]   = {cfg.noAckScan, cfg.noFinScan,
                                   cfg.noMaimonScan, cfg.noOsFingerprint};
        int        *perIface[4] = {cfg.ifaceNoAckScan, cfg.ifaceNoFinScan,
                                   cfg.ifaceNoMaimon, cfg.ifaceNoOsFp};
        for (int c = 0; c < 4; c++) {
            if (global[c]) {
                printf("%-13s: " DIM "disabled globally" RESET "\n", checks[c]);
            } else {
                /* list any per-interface suppressions */
                int printed = 0;
                for (int i = 0; i < cfg.ifaceCount; i++) {
                    if (perIface[c][i]) {
                        if (!printed)
                            printf("%-13s: disabled on: %s",
                                   checks[c], cfg.ifaceNames[i]);
                        else
                            printf(", %s", cfg.ifaceNames[i]);
                        printed = 1;
                    }
                }
                if (printed) printf("\n");
            }
        }
    }
    printf("Verbose      : %s\n", cfg.verbose ? "yes" : "no");
    printf("Watched ports: %d\n", cfg.watchCount);
    for (int i = 0; i < cfg.watchCount; i++)
        printf("  [%d] port %-5u  name %-16s  threshold %d/window\n",
               i+1, cfg.watchPorts[i].port, cfg.watchPorts[i].name,
               cfg.watchPorts[i].threshold);
    printf("\n");
    printf(YELLOW "Listening on %d interface%s… press Ctrl+C to stop.\n\n" RESET,
           cfg.ifaceCount, cfg.ifaceCount == 1 ? "" : "s");

    /* 12. launch threads */
    for (int i = 0; i < cfg.ifaceCount; i++) {
        if (pthread_create(&threads[i], NULL, captureThread, &ctxArr[i]) != 0) {
            perror("pthread_create"); return EXIT_FAILURE;
        }
    }

    /* 13. wait */
    for (int i = 0; i < cfg.ifaceCount; i++)
        pthread_join(threads[i], NULL);

    /* 14. close */
    for (int i = 0; i < cfg.ifaceCount; i++)
        pcap_close(ctxArr[i].handle);

    /* 15. summary */
    printf("\n" BOLD "── Summary ──────────────────────────────────────\n" RESET);
    printf("Interfaces monitored   : %d\n", cfg.ifaceCount);
    printf("Total packets captured : %ld\n", totalPackets);
    printf("Total alerts raised    : %ld\n", totalAlerts);
    if (cfg.logDir[0]) printf("Log directory          : %s\n", cfg.logDir);
    printf(BOLD GREEN "Done.\n" RESET);

    /* 16. cleanup */
    for (int i = 0; i < maxTrackedIps; i++) {
        IpStats *s = ipTable[i];
        while (s) { IpStats *n = s->next; free(s); s = n; }
    }
    pthread_mutex_destroy(&gLock);
    return EXIT_SUCCESS;
}
