#!/usr/bin/env bash
# =============================================================================
# alert_udp.sh — tigernet alert script: sends a JSON UDP packet on every alert
#
# tigernet calls this script for every alert and passes data via environment
# variables:
#
#   TIGERNET_TYPE        alert category, e.g. "SSH BRUTE-FORCE"
#   TIGERNET_SRC_IP      attacker IP address, e.g. "203.0.113.7"
#   TIGERNET_DETAIL      human-readable detail string
#   TIGERNET_TIMESTAMP   ISO-8601 UTC time, e.g. "2025-04-22T14:03:44Z"
#   TIGERNET_HOSTNAME    hostname of the machine running tigernet
#   TIGERNET_IFACE       network interface that saw the traffic, e.g. "eth0"
#
# Configuration — edit the variables below or export them before starting
# tigernet so your values take precedence:
#
#   TIGERNET_UDP_HOST    destination host (default: 127.0.0.1)
#   TIGERNET_UDP_PORT    destination UDP port (default: 5140)
#   TIGERNET_UDP_TOOL    "nc" or "socat" (auto-detected if not set)
#
# Usage:
#   chmod +x alert_udp.sh
#   sudo ./tigernet --alert-script ./alert_udp.sh
#   # or in tigernet.conf:
#   # alertScript = /etc/tigernet/alert_udp.sh
#
# Receiving the alerts:
#   nc -u -l 5140                          # one-shot listener
#   socat UDP-RECV:5140 STDOUT             # continuous listener
#   tcpdump -i lo udp port 5140 -A         # packet view
# =============================================================================

set -euo pipefail

# ── destination ─────────────────────────────────────────────────────────────
UDP_HOST="${TIGERNET_UDP_HOST:-127.0.0.1}"
UDP_PORT="${TIGERNET_UDP_PORT:-5140}"

# ── required env vars from tigernet ─────────────────────────────────────────
ALERT_TYPE="${TIGERNET_TYPE:-UNKNOWN}"
SRC_IP="${TIGERNET_SRC_IP:-0.0.0.0}"
DETAIL="${TIGERNET_DETAIL:-}"
TIMESTAMP="${TIGERNET_TIMESTAMP:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
HOSTNAME_VAL="${TIGERNET_HOSTNAME:-$(hostname -s 2>/dev/null || echo unknown)}"
IFACE="${TIGERNET_IFACE:-unknown}"

# ── escape a string for safe inclusion in a JSON value ──────────────────────
json_escape() {
    # Replace backslash, double-quote, and control characters
    printf '%s' "$1" \
        | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g'
}

# ── build JSON payload ───────────────────────────────────────────────────────
PAYLOAD=$(printf '{"sensor":"%s","timestamp":"%s","iface":"%s","type":"%s","src_ip":"%s","detail":"%s"}' \
    "$(json_escape "$HOSTNAME_VAL")" \
    "$(json_escape "$TIMESTAMP")" \
    "$(json_escape "$IFACE")" \
    "$(json_escape "$ALERT_TYPE")" \
    "$(json_escape "$SRC_IP")" \
    "$(json_escape "$DETAIL")")

# ── detect or select UDP sending tool ───────────────────────────────────────
send_udp() {
    local payload="$1"
    local host="$2"
    local port="$3"
    local tool="${TIGERNET_UDP_TOOL:-}"

    if [[ -z "$tool" ]]; then
        if command -v socat &>/dev/null; then
            tool="socat"
        elif command -v nc &>/dev/null; then
            tool="nc"
        else
            echo "[alert_udp.sh] ERROR: neither socat nor nc found; cannot send UDP" >&2
            return 1
        fi
    fi

    case "$tool" in
        socat)
            printf '%s' "$payload" \
                | socat - "UDP-SENDTO:${host}:${port}"
            ;;
        nc)
            # -u UDP, -q0 / -w1 close after sending, -N signals EOF
            # Different nc variants need different flags; try them in order.
            if printf '%s' "$payload" | nc -u -w1 "$host" "$port" 2>/dev/null; then
                :
            else
                printf '%s' "$payload" | nc -u -q0 "$host" "$port" 2>/dev/null || true
            fi
            ;;
        *)
            echo "[alert_udp.sh] ERROR: unknown tool '${tool}'; set TIGERNET_UDP_TOOL to 'nc' or 'socat'" >&2
            return 1
            ;;
    esac
}

send_udp "$PAYLOAD" "$UDP_HOST" "$UDP_PORT"
