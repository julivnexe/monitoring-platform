#!/usr/bin/env python3
"""
netmon-alert — Halo CE server observability bot.

Same behavior as the original halo_ddos_monitor.py (per-port iptables
counters → PPS/BPS/flood alerts to Discord, players.log tail → join/leave
embeds, systemctl service watchdog disabled inside a container), PLUS a
Prometheus /metrics endpoint so the data is now scrape-able by a real
TSDB.

Why both Discord and Prometheus?
  - Discord is the *event* channel: join/leave, DDoS alerts. Push-style,
    human-readable, one message per event.
  - Prometheus is the *time-series* channel: continuous PPS/BPS/player-
    count history, queryable in Grafana over arbitrary time ranges,
    suitable for trend analysis and SLO dashboards.

The two channels see the same underlying data but answer different
questions ("is something broken right now?" vs "how has it been doing?").
"""
import os
import time
import socket
import subprocess
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests
from prometheus_client import (
    Counter, Gauge, start_http_server, REGISTRY, CollectorRegistry
)

# ============ CONFIG ============
WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK", "")
HALO_SERVERS_RAW = os.environ.get("HALO_SERVERS", "2302:Server 1:16")
IFACE = os.environ.get("IFACE", "")
PLAYER_LOG = os.environ.get("PLAYER_LOG", "/opt/halo-monitor/players.log")
LOG_POS_FILE = os.environ.get("LOG_POS_FILE", "/opt/halo-monitor/players.log.pos")
PROXYCHECK_KEY = os.environ.get("PROXYCHECK_KEY", "").strip()
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))

PPS_THRESHOLD = int(os.environ.get("PPS_THRESHOLD", "3000"))
BPS_THRESHOLD = int(os.environ.get("BPS_THRESHOLD", str(8 * 1024 * 1024)))
UNIQUE_IPS_WINDOW_SEC = int(os.environ.get("UNIQUE_IPS_WINDOW_SEC", "10"))
UNIQUE_IPS_THRESHOLD = int(os.environ.get("UNIQUE_IPS_THRESHOLD", "40"))
ALERT_COOLDOWN_SEC = int(os.environ.get("ALERT_COOLDOWN_SEC", "60"))
POLL_SEC = int(os.environ.get("POLL_SEC", "2"))
# If a player's IP hasn't appeared in `ss -uan` output for this many seconds,
# we treat them as ghost-disconnected (SAPP didn't fire EVENT_LEAVE) and
# synthesize a leave event. Halo client heartbeats are sub-second, so 90s
# is comfortably above any natural network blip.
GHOST_TIMEOUT_SEC = int(os.environ.get("GHOST_TIMEOUT_SEC", "90"))
# ================================

HOSTNAME = socket.gethostname()

# ---------- Prometheus metrics ----------
# Labels: server="Pelea de Gallos @LA", port="2310". Cardinality stays
# bounded because the set of servers is small and static per-deployment.
M_PPS = Gauge("netmon_pps", "Inbound packets/sec to halo UDP port",
              ["server", "port"])
M_BPS = Gauge("netmon_bps", "Inbound bytes/sec to halo UDP port",
              ["server", "port"])
M_PLAYERS = Gauge("netmon_players_online", "Current connected players",
                  ["server"])
M_UNIQUE_IPS = Gauge("netmon_unique_src_ips_window",
                     "Unique source IPs seen in the flood-detection window",
                     ["server", "port"])
M_JOINS = Counter("netmon_player_joins_total", "Total player joins",
                  ["server"])
M_LEAVES = Counter("netmon_player_leaves_total", "Total player leaves",
                   ["server"])
M_VPN = Counter("netmon_vpn_detections_total",
                "Players whose IP flagged as VPN/proxy/datacenter",
                ["server"])
M_ALERTS = Counter("netmon_alerts_fired_total",
                   "Discord alerts emitted by category",
                   ["server", "kind"])
M_WEBHOOK_ERRORS = Counter("netmon_webhook_errors_total",
                           "Failed Discord webhook POSTs")
M_IP_LOOKUPS = Counter("netmon_ip_lookups_total",
                       "proxycheck.io lookups by status",
                       ["status"])
# ----------------------------------------

_ip_info_cache = {}
# Map (server, name, hsh) -> {"ip": "1.2.3.4[:port]", "last_seen": float epoch}.
# Used both for dedupe (key membership) and for the ghost-prune reconciliation
# pass (last_seen freshness vs ss output).
_active_players = {}
_seen_ips = set()

# In-memory cache: ip -> "🇽🇽 Country" string


def parse_servers(raw):
    out = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        bits = entry.split(":")
        if len(bits) < 2:
            continue
        try:
            port = int(bits[0].strip())
        except ValueError:
            continue
        max_players = 16
        name_parts = bits[1:]
        if len(name_parts) >= 2:
            try:
                max_players = int(name_parts[-1].strip())
                name_parts = name_parts[:-1]
            except ValueError:
                pass
        name = ":".join(s.strip() for s in name_parts)
        out[port] = {"name": name, "max": max_players}
    return out


SERVERS = parse_servers(HALO_SERVERS_RAW)
SERVER_MAX = {info["name"]: info["max"] for info in SERVERS.values()}
SERVER_PORT = {info["name"]: port for port, info in SERVERS.items()}

SERVER_PASSWORDS_RAW = os.environ.get("SERVER_PASSWORDS", "")
SERVER_PASSWORDS = {}
for entry in SERVER_PASSWORDS_RAW.split(","):
    entry = entry.strip()
    if not entry or ":" not in entry:
        continue
    p, pw = entry.split(":", 1)
    try:
        SERVER_PASSWORDS[int(p.strip())] = pw.strip()
    except ValueError:
        pass

PUBLIC_IP = os.environ.get("PUBLIC_IP", "").strip()
SERVER_IPS_RAW = os.environ.get("SERVER_IPS", "")
SERVER_IPS = {}
for entry in SERVER_IPS_RAW.split(","):
    entry = entry.strip()
    if not entry or ":" not in entry:
        continue
    p, ip = entry.split(":", 1)
    try:
        SERVER_IPS[int(p.strip())] = ip.strip()
    except ValueError:
        pass


def get_public_ip():
    global PUBLIC_IP
    if PUBLIC_IP:
        return PUBLIC_IP
    for url in ("https://icanhazip.com", "https://api.ipify.org",
                "https://ifconfig.me/ip"):
        try:
            r = requests.get(url, timeout=4)
            ip = (r.text or "").strip().split("\n")[0]
            if ip and ip.count(".") == 3:
                PUBLIC_IP = ip
                return PUBLIC_IP
        except Exception:
            continue
    return None


def detect_iface() -> str:
    if IFACE:
        return IFACE
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True)
        parts = out.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def post(payload):
    if not WEBHOOK_URL:
        return
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"webhook error: {e}")
        M_WEBHOOK_ERRORS.inc()


def post_alert(server_name, title, desc, color, kind="generic", fields=None):
    post({
        "username": "SoplonBOT",
        "embeds": [{
            "title": f"[{server_name}] {title}",
            "description": desc,
            "color": color,
            "fields": fields or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }],
    })
    M_ALERTS.labels(server=server_name, kind=kind).inc()


def lookup_ip_info(ip_with_port):
    empty = {"country_label": None, "org": None, "vpn_type": None,
             "is_suspicious": False}
    if not ip_with_port:
        return empty
    ip = ip_with_port.split(":", 1)[0]
    if not ip:
        return empty
    if ip in _ip_info_cache:
        return _ip_info_cache[ip]
    info = dict(empty)
    try:
        params = {"vpn": "1", "asn": "1", "risk": "1"}
        if PROXYCHECK_KEY:
            params["key"] = PROXYCHECK_KEY
        r = requests.get(f"https://proxycheck.io/v2/{ip}",
                         params=params, timeout=4)
        data = r.json()
        if data.get("status") in ("ok", "warning"):
            entry = data.get(ip, {}) or {}
            cc = (entry.get("isocode") or "").upper()
            country = entry.get("country") or ""
            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A"))
                           for c in cc if "A" <= c <= "Z")
            info["country_label"] = (
                f"{flag} {country}".strip() if (flag or country) else None)
            info["org"] = (entry.get("provider") or
                           entry.get("organisation") or entry.get("asn"))
            if (entry.get("proxy") or "").lower() == "yes":
                info["is_suspicious"] = True
                info["vpn_type"] = entry.get("type") or "Proxy"
            M_IP_LOOKUPS.labels(status="ok").inc()
        else:
            print(f"proxycheck non-ok status for {ip}: {data}")
            M_IP_LOOKUPS.labels(status="non_ok").inc()
    except Exception as e:
        print(f"proxycheck lookup failed for {ip}: {e}")
        M_IP_LOOKUPS.labels(status="error").inc()
    _ip_info_cache[ip] = info
    return info


def current_players_from_log(server_filter=None):
    if not os.path.exists(PLAYER_LOG):
        return [], set()
    active = {}
    try:
        with open(PLAYER_LOG, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(",", 5)
                if len(parts) == 6:
                    ts, server, action, name, ip, hsh = parts
                elif len(parts) == 5:
                    ts, action, name, ip, hsh = parts
                    server = ""
                else:
                    continue
                if server_filter and server != server_filter:
                    continue
                if action == "startup":
                    for k in list(active.keys()):
                        if k[0] == server:
                            del active[k]
                    continue
                key = (server, name, hsh)
                if action == "join":
                    active[key] = {"name": name, "ip": ip}
                elif action == "leave":
                    active.pop(key, None)
    except Exception as e:
        print(f"log read error: {e}")
    names = [p["name"] for p in active.values()]
    ips = {p["ip"] for p in active.values() if p["ip"]}
    return names, ips


def conntrack_unique_ips(port: int) -> set:
    ips = set()
    try:
        out = subprocess.check_output(["ss", "-uan"], text=True, timeout=3)
        for line in out.splitlines():
            if f":{port} " in line or line.endswith(f":{port}"):
                cols = line.split()
                if len(cols) >= 5:
                    peer = cols[4]
                    ip = peer.rsplit(":", 1)[0].strip("[]")
                    if ip and ip != "*":
                        ips.add(ip)
    except Exception:
        pass
    return ips


def ensure_iptables_counter(port: int):
    chain_check = subprocess.run(
        ["iptables", "-C", "INPUT", "-p", "udp", "--dport", str(port),
         "-j", "ACCEPT"], capture_output=True)
    if chain_check.returncode != 0:
        subprocess.run(
            ["iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(port),
             "-j", "ACCEPT"], check=False)


def read_port_counter(port: int):
    try:
        out = subprocess.check_output(
            ["iptables", "-L", "INPUT", "-v", "-n", "-x"], text=True)
        for line in out.splitlines():
            if f"udp dpt:{port}" in line:
                cols = line.split()
                return int(cols[0]), int(cols[1])
    except Exception:
        pass
    return 0, 0


def safe_player_field(server_name) -> dict:
    names, _ = current_players_from_log(server_filter=server_name)
    if not names:
        return {"name": "Connected players", "value": "_none_",
                "inline": False}
    shown = names[:20]
    extra = f" _+ {len(names)-20} more_" if len(names) > 20 else ""
    return {"name": f"Connected players ({len(names)})",
            "value": ", ".join(f"`{n}`" for n in shown) + extra,
            "inline": False}


def attack_source_ips(seen_ips, player_ips):
    return sorted(ip for ip in seen_ips if ip not in player_ips)


def get_log_pos() -> int:
    try:
        with open(LOG_POS_FILE) as f:
            return int((f.read() or "0").strip())
    except Exception:
        return 0


def set_log_pos(pos: int):
    try:
        with open(LOG_POS_FILE, "w") as f:
            f.write(str(pos))
    except Exception as e:
        print(f"could not save log pos: {e}")


def post_join_leave(server, action, name, ip_with_port=None, returning=False):
    names, _ = current_players_from_log(server_filter=server)
    count = len(names)
    M_PLAYERS.labels(server=server).set(count)
    if action == "join":
        title, color = "🟢 Player joined", 3066993
        M_JOINS.labels(server=server).inc()
    else:
        title, color = "🔴 Player left", 15158332
        M_LEAVES.labels(server=server).inc()
    info = lookup_ip_info(ip_with_port)
    ip_clean = (ip_with_port or "").split(":", 1)[0] or "?"
    display_name = f"🔄 {name}" if returning else name
    fields = [
        {"name": "Server", "value": server, "inline": False},
        {"name": "Player", "value": display_name, "inline": True},
        {"name": "IP",     "value": f"`{ip_clean}`", "inline": True},
    ]
    if info.get("country_label"):
        fields.append({"name": "Country",
                       "value": info["country_label"], "inline": True})
    if info.get("is_suspicious"):
        fields.append({"name": f"⚠️ {info.get('vpn_type') or 'Proxy'} detected",
                       "value": info.get("org") or "unknown", "inline": False})
        if action == "join":
            M_VPN.labels(server=server).inc()
    max_players = SERVER_MAX.get(server, 16)
    fields.append({"name": "Players online",
                   "value": f"{count}/{max_players}", "inline": True})
    if action == "join":
        port = SERVER_PORT.get(server)
        if port:
            host = SERVER_IPS.get(port) or get_public_ip()
            if host:
                pw = SERVER_PASSWORDS.get(port, "")
                cmd = f'connect {host}:{port} "{pw}"'
                fields.append({"name": "Connect",
                               "value": f"```\n{cmd}\n```", "inline": False})
    post({"username": "SoplonBOT",
          "embeds": [{"title": title, "color": color, "fields": fields,
                      "timestamp": datetime.now(timezone.utc).isoformat()}]})


def reconcile_active_players(seen_ips_per_server, now):
    """For each active player, refresh last_seen if their IP currently appears
    in ss output for their server. Prune anyone whose last_seen is older than
    GHOST_TIMEOUT_SEC and synthesize a leave so Discord + the gauge stay in
    sync. This is the safety net for SAPP's unreliable EVENT_LEAVE: timeouts
    and hard disconnects don't trigger Lua, leaving stale 'active' entries
    forever otherwise."""
    # Refresh last_seen
    for key, meta in _active_players.items():
        server = key[0]
        player_ip = (meta.get("ip") or "").split(":", 1)[0]
        if not player_ip:
            continue
        if player_ip in seen_ips_per_server.get(server, set()):
            meta["last_seen"] = now
    # Prune
    for key in list(_active_players.keys()):
        meta = _active_players[key]
        age = now - meta.get("last_seen", now)
        if age > GHOST_TIMEOUT_SEC:
            server, name, hsh = key
            ip = meta.get("ip", "")
            print(f"[ghost-prune] {server}/{name} (ip={ip}) silent for "
                  f"{age:.0f}s — synthesizing leave")
            _active_players.pop(key, None)
            post_join_leave(server, "leave", name, ip, returning=False)


def rebuild_active_players():
    _active_players.clear()
    _seen_ips.clear()
    if not os.path.exists(PLAYER_LOG):
        return
    now = time.time()
    try:
        with open(PLAYER_LOG, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(",", 5)
                if len(parts) == 6:
                    _ts, server, action, name, ip, hsh = parts
                elif len(parts) == 5:
                    _ts, action, name, ip, hsh = parts
                    server = ""
                else:
                    continue
                if action == "startup":
                    for k in list(_active_players):
                        if k[0] == server:
                            _active_players.pop(k, None)
                    continue
                ip_clean = (ip or "").split(":", 1)[0]
                if action == "join" and ip_clean:
                    _seen_ips.add(ip_clean)
                key = (server, name, hsh)
                if action == "join":
                    # Seed last_seen with `now` so ghosts from the log get one
                    # full GHOST_TIMEOUT_SEC window to prove they're still real
                    # via ss output before we prune them.
                    _active_players[key] = {"ip": ip or "", "last_seen": now}
                elif action == "leave":
                    _active_players.pop(key, None)
    except Exception as e:
        print(f"rebuild_active_players error: {e}")


def process_new_log_entries():
    if not os.path.exists(PLAYER_LOG):
        return
    size = os.path.getsize(PLAYER_LOG)
    pos = get_log_pos()
    if pos > size:
        pos = 0
    if pos >= size:
        return
    try:
        with open(PLAYER_LOG, encoding="utf-8", errors="replace") as f:
            f.seek(pos)
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split(",", 5)
                if len(parts) != 6:
                    continue
                _ts, server, action, name, ip, hsh = parts
                if action == "startup":
                    for k in list(_active_players):
                        if k[0] == server:
                            _active_players.pop(k, None)
                    M_PLAYERS.labels(server=server).set(0)
                    continue
                if action not in ("join", "leave"):
                    continue
                key = (server, name, hsh)
                ip_clean = (ip or "").split(":", 1)[0]
                if action == "join":
                    if key in _active_players:
                        continue
                    returning = bool(ip_clean) and ip_clean in _seen_ips
                    if ip_clean:
                        _seen_ips.add(ip_clean)
                    _active_players[key] = {"ip": ip or "", "last_seen": time.time()}
                    post_join_leave(server, "join", name, ip,
                                    returning=returning)
                else:
                    if key not in _active_players:
                        continue
                    _active_players.pop(key, None)
                    post_join_leave(server, "leave", name, ip,
                                    returning=False)
            set_log_pos(f.tell())
    except Exception as e:
        print(f"log tail error: {e}")


def main():
    if not SERVERS:
        print("[!] HALO_SERVERS env var is empty or invalid; exiting")
        return

    # Start /metrics HTTP server in a background thread.
    start_http_server(METRICS_PORT)
    print(f"[+] /metrics listening on :{METRICS_PORT}")

    iface = detect_iface()
    print(f"[+] monitoring iface={iface} servers={SERVERS}")

    states = {}
    for port, info in SERVERS.items():
        ensure_iptables_counter(port)
        pkts, bts = read_port_counter(port)
        states[port] = {
            "name": info["name"],
            "last_pkts": pkts,
            "last_bytes": bts,
            "ip_window": deque(),
            "last_alert": defaultdict(lambda: 0.0),
        }

    if not os.path.exists(LOG_POS_FILE) and os.path.exists(PLAYER_LOG):
        sz = os.path.getsize(PLAYER_LOG)
        set_log_pos(sz)
        print(f"[+] log tail starts at byte {sz}")

    rebuild_active_players()
    print(f"[+] _active_players seeded with {len(_active_players)} entries")

    # Initial player-count gauge sync
    for port, info in SERVERS.items():
        names, _ = current_players_from_log(server_filter=info["name"])
        M_PLAYERS.labels(server=info["name"]).set(len(names))

    server_list = "\n".join(
        f"`{info['name']}` → UDP/{p} (max {info['max']})"
        for p, info in SERVERS.items())
    post({"username": "SoplonBOT", "embeds": [{
        "title": "🟢 Halo monitor online",
        "description": server_list,
        "color": 3066993,
        "fields": [
            {"name": "PPS threshold", "value": str(PPS_THRESHOLD),
             "inline": True},
            {"name": "BPS threshold",
             "value": f"{BPS_THRESHOLD // 1024 // 1024} Mbps",
             "inline": True},
            {"name": "/metrics", "value": f"port {METRICS_PORT}",
             "inline": True},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }]})

    while True:
        time.sleep(POLL_SEC)
        now = time.time()
        process_new_log_entries()

        # IPs currently visible on each server's UDP port — used by the
        # ghost-pruner below to validate that every "active" player is
        # actually still talking to the server.
        seen_ips_per_server = {}

        for port, s in states.items():
            name = s["name"]
            pkts, bytes_ = read_port_counter(port)
            dp = pkts - s["last_pkts"]
            db = bytes_ - s["last_bytes"]
            s["last_pkts"], s["last_bytes"] = pkts, bytes_

            pps = dp / POLL_SEC
            bps = (db * 8) / POLL_SEC

            M_PPS.labels(server=name, port=str(port)).set(pps)
            M_BPS.labels(server=name, port=str(port)).set(bps)

            if pps >= PPS_THRESHOLD and \
                    now - s["last_alert"]["pps"] > ALERT_COOLDOWN_SEC:
                s["last_alert"]["pps"] = now
                post_alert(name, "⚠️ PPS spike",
                           f"Inbound packets to UDP/{port} spiked",
                           15105570, kind="pps", fields=[
                               {"name": "PPS", "value": f"{int(pps)}",
                                "inline": True},
                               {"name": "Bandwidth",
                                "value": f"{bps/1_000_000:.2f} Mbps",
                                "inline": True},
                               safe_player_field(name),
                           ])

            if bps >= BPS_THRESHOLD and \
                    now - s["last_alert"]["bps"] > ALERT_COOLDOWN_SEC:
                s["last_alert"]["bps"] = now
                post_alert(name, "⚠️ Bandwidth spike",
                           f"Inbound bandwidth to UDP/{port} exceeded threshold",
                           15105570, kind="bps", fields=[
                               {"name": "PPS", "value": f"{int(pps)}",
                                "inline": True},
                               {"name": "Bandwidth",
                                "value": f"{bps/1_000_000:.2f} Mbps",
                                "inline": True},
                               safe_player_field(name),
                           ])

            cur = conntrack_unique_ips(port)
            seen_ips_per_server.setdefault(name, set()).update(cur)
            for ip in cur:
                s["ip_window"].append((now, ip))
            cutoff = now - UNIQUE_IPS_WINDOW_SEC
            while s["ip_window"] and s["ip_window"][0][0] < cutoff:
                s["ip_window"].popleft()
            unique_recent = {ip for _, ip in s["ip_window"]}
            M_UNIQUE_IPS.labels(server=name, port=str(port)).set(
                len(unique_recent))

            if len(unique_recent) >= UNIQUE_IPS_THRESHOLD and \
                    now - s["last_alert"]["flood"] > ALERT_COOLDOWN_SEC:
                s["last_alert"]["flood"] = now
                _, player_ips = current_players_from_log(server_filter=name)
                attackers = attack_source_ips(unique_recent, player_ips)
                sample = (", ".join(attackers[:10]) if attackers else
                          "_(all source IPs match known players)_")
                post_alert(name, "🚨 Connection flood detected",
                           f"{len(unique_recent)} unique src IPs in "
                           f"{UNIQUE_IPS_WINDOW_SEC}s",
                           15158332, kind="flood", fields=[
                               {"name": f"Attack source IPs ({len(attackers)})",
                                "value": f"`{sample}`", "inline": False},
                               safe_player_field(name),
                           ])


if __name__ == "__main__":
    main()
