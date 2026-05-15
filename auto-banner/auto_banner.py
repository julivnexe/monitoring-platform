#!/usr/bin/env python3
"""
auto-banner — automatic botnet / DDoS subnet banning for Halo CE.

Runs alongside netmon-alert in the monitoring stack. Watches Prometheus
for sustained PPS spikes on Halo UDP ports; when one fires, captures
~15 seconds of traffic via tcpdump, identifies offending source IPs,
groups them by /24 subnet, and adds them to an ipset that an iptables
rule drops.

Key design choices:
  * ipset (not raw iptables rules) — O(1) set lookup vs O(N) chain
    scan; one iptables rule references the set regardless of how many
    entries get added.
  * Subnet-level bans (/24) when 3+ distinct IPs from the same /24
    appear in a single attack — that's a botnet pattern, individual
    IP bans wouldn't keep up.
  * 24-hour TTL on every entry — false-positives self-correct without
    manual intervention. Configurable via BAN_TTL_SEC.
  * Whitelist from players.log — any IP that has ever joined a real
    Halo game is exempt. Protects laggy legit players from being
    mis-identified as flooders.
  * Discord alert on every ban so the operator sees what happened.

Required capabilities: NET_ADMIN, NET_RAW (for ipset / iptables / tcpdump).
"""
import os
import time
import signal
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone

import requests

# --- CONFIG ---
PROMETHEUS_URL    = os.environ.get("PROMETHEUS_URL", "http://127.0.0.1:9090")
HALO_PORTS        = [int(p) for p in os.environ.get("HALO_PORTS", "2310,2312").split(",")]
PPS_TRIGGER       = int(os.environ.get("PPS_TRIGGER", "1500"))           # total inbound pps that triggers investigation
CHECK_INTERVAL    = int(os.environ.get("CHECK_INTERVAL_SEC", "30"))
CAPTURE_DURATION  = int(os.environ.get("CAPTURE_DURATION_SEC", "15"))
MIN_IPS_PER_SUBNET = int(os.environ.get("MIN_IPS_PER_SUBNET", "3"))      # /24 must have at least N distinct attacker IPs
SINGLE_IP_PPS     = int(os.environ.get("SINGLE_IP_PPS", "300"))          # individual ban threshold
BAN_TTL_SEC       = int(os.environ.get("BAN_TTL_SEC", str(24 * 3600)))   # 24h default
IPSET_NAME        = os.environ.get("IPSET_NAME", "halo-banlist")
PLAYER_LOG        = os.environ.get("PLAYER_LOG", "/opt/halo-monitor/players.log")
DISCORD_WEBHOOK   = os.environ.get("DISCORD_WEBHOOK", "").strip()
# Whitelist subnets / IPs that should never be banned regardless of behaviour.
# Format: comma-separated CIDRs.
PERMANENT_WHITELIST = [
    s.strip() for s in os.environ.get("PERMANENT_WHITELIST", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if s.strip()
]


def log(msg):
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}", flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def setup_ipset():
    """Idempotently create the ipset and the single iptables DROP rule that
    references it. Subsequent bans are just `ipset add` calls — no iptables
    churn."""
    r = run(["ipset", "create", "-exist", IPSET_NAME,
             "hash:net", "timeout", str(BAN_TTL_SEC), "maxelem", "65536"])
    if r.returncode != 0:
        log(f"ipset create failed: {r.stderr}")
    chain_check = run(["iptables", "-C", "INPUT", "-m", "set",
                       "--match-set", IPSET_NAME, "src", "-j", "DROP"])
    if chain_check.returncode != 0:
        r = run(["iptables", "-I", "INPUT", "1", "-m", "set",
                 "--match-set", IPSET_NAME, "src", "-j", "DROP"])
        if r.returncode == 0:
            log(f"inserted iptables DROP rule referencing ipset {IPSET_NAME}")
        else:
            log(f"failed to insert iptables rule: {r.stderr}")


def load_player_ip_whitelist():
    """Build a set of IPs that have ever appeared as legit players. Used to
    veto auto-bans against laggy real players."""
    ips = set()
    if not os.path.isfile(PLAYER_LOG):
        return ips
    try:
        with open(PLAYER_LOG, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(",", 5)
                if len(parts) != 6:
                    continue
                _ts, _server, action, _name, ip, _hsh = parts
                if action != "join":
                    continue
                ip_clean = (ip or "").split(":", 1)[0]
                if ip_clean:
                    ips.add(ip_clean)
    except Exception as e:
        log(f"could not read player log: {e}")
    return ips


def get_current_total_pps():
    """Query Prometheus for total inbound PPS across all halo ports."""
    try:
        r = requests.get(f"{PROMETHEUS_URL}/api/v1/query",
                         params={"query": "sum(netmon_pps)"}, timeout=5)
        data = r.json()
        if data.get("status") == "success":
            result = data.get("data", {}).get("result", [])
            if result:
                return float(result[0]["value"][1])
    except Exception as e:
        log(f"prometheus query error: {e}")
    return 0.0


def capture_attackers(duration):
    """Run tcpdump for `duration` seconds, return Counter of source IPs to packet count."""
    port_expr = " or ".join(f"dst port {p}" for p in HALO_PORTS)
    cmd = ["timeout", str(duration), "tcpdump", "-i", "any", "-nn",
           f"udp and ({port_expr})"]
    r = run(cmd)
    counter = Counter()
    for line in r.stdout.splitlines():
        # tcpdump -i any -nn line:
        #   HH:MM:SS.MMMM enp1s0 In  IP a.b.c.d.PORT > x.y.z.w.PORT: UDP, length N
        parts = line.split()
        if len(parts) < 5 or parts[2] != "In":
            continue
        src = parts[4]
        ip = ".".join(src.split(".")[:4])
        # Sanity check: dotted-quad
        if ip.count(".") == 3 and all(p.isdigit() for p in ip.split(".")):
            counter[ip] += 1
    return counter


def is_whitelisted_subnet(ip):
    """True if `ip` is in any PERMANENT_WHITELIST CIDR."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in PERMANENT_WHITELIST:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def group_by_subnet(ips):
    subnets = defaultdict(set)
    for ip in ips:
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        subnets[subnet].add(ip)
    return subnets


def ban(entry, reason=""):
    r = run(["ipset", "add", "-exist", IPSET_NAME, entry,
             "timeout", str(BAN_TTL_SEC)])
    if r.returncode != 0:
        log(f"ipset add {entry} failed: {r.stderr}")
        return False
    log(f"banned {entry} ({reason})")
    return True


def discord_alert(title, fields):
    if not DISCORD_WEBHOOK:
        return
    try:
        requests.post(DISCORD_WEBHOOK, json={
            "username": "SoplonBOT",
            "embeds": [{
                "title": title,
                "color": 16711680,  # red
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }],
        }, timeout=5)
    except Exception as e:
        log(f"discord post error: {e}")


def evaluate_and_ban(player_whitelist):
    pps = get_current_total_pps()
    log(f"total halo pps={pps:.0f}  trigger>{PPS_TRIGGER}")
    if pps < PPS_TRIGGER:
        return

    log(f"PPS spike — capturing {CAPTURE_DURATION}s of traffic")
    counter = capture_attackers(CAPTURE_DURATION)
    if not counter:
        log("capture empty — nothing to ban")
        return

    bans = []      # list of (entry, reason, pps)
    skipped = []   # reasons we skipped a candidate

    # Subnet-level: any /24 with >= MIN_IPS_PER_SUBNET attackers
    subnets = group_by_subnet(counter.keys())
    for subnet, ips in subnets.items():
        if len(ips) < MIN_IPS_PER_SUBNET:
            continue
        if any(ip in player_whitelist for ip in ips):
            skipped.append(f"{subnet} (contains a known player)")
            continue
        if is_whitelisted_subnet(next(iter(ips))):
            skipped.append(f"{subnet} (RFC1918 / loopback)")
            continue
        total_pkts = sum(counter[i] for i in ips)
        if ban(subnet, f"{len(ips)} attackers, {total_pkts/CAPTURE_DURATION:.0f} pps"):
            bans.append((subnet, f"{len(ips)} unique src IPs",
                         total_pkts / CAPTURE_DURATION))

    # Individual heavy hitters: > SINGLE_IP_PPS pps, not in a banned subnet
    banned_subnet_prefixes = {b[0].rsplit(".0/", 1)[0] for b in bans}
    for ip, pkts in counter.items():
        pps_ip = pkts / CAPTURE_DURATION
        if pps_ip < SINGLE_IP_PPS:
            continue
        if ip in player_whitelist:
            skipped.append(f"{ip} ({pps_ip:.0f} pps, known player)")
            continue
        if is_whitelisted_subnet(ip):
            skipped.append(f"{ip} (RFC1918)")
            continue
        prefix = ".".join(ip.split(".")[:3])
        if prefix in banned_subnet_prefixes:
            continue  # already covered by subnet ban
        if ban(f"{ip}/32", f"{pps_ip:.0f} pps"):
            bans.append((f"{ip}/32", "single high-volume source", pps_ip))

    if bans:
        fields = [
            {"name": "Trigger PPS", "value": f"{pps:.0f}", "inline": True},
            {"name": "New entries", "value": str(len(bans)), "inline": True},
            {"name": "TTL", "value": f"{BAN_TTL_SEC//3600}h", "inline": True},
            {"name": "Banned",
             "value": "\n".join(f"`{e}` — {r} ({p:.0f} pps)" for e, r, p in bans[:10]),
             "inline": False},
        ]
        if skipped:
            fields.append({
                "name": f"Skipped ({len(skipped)})",
                "value": "\n".join(f"`{s}`" for s in skipped[:5]),
                "inline": False,
            })
        discord_alert("🛡️ Auto-ban fired", fields)


def shutdown(signum, _frame):
    log(f"signal {signum} — exiting (ipset & iptables rule left in place)")
    raise SystemExit(0)


def main():
    log(f"auto-banner starting  ports={HALO_PORTS}  pps_trigger={PPS_TRIGGER}  "
        f"cap={CAPTURE_DURATION}s  min_ips_per_subnet={MIN_IPS_PER_SUBNET}  "
        f"ttl={BAN_TTL_SEC}s")
    setup_ipset()
    while True:
        try:
            player_whitelist = load_player_ip_whitelist()
            evaluate_and_ban(player_whitelist)
        except Exception as e:
            log(f"loop error: {e}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    main()
