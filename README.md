# monitoring-platform

**Production-grade observability stack for game server infrastructure.** Containerized Prometheus + Grafana + a custom Python exporter that watches UDP traffic, detects DDoS patterns in real time, and pushes events to Discord — all behind a single `docker compose up`.

> Built around a fleet of Halo CE dedicated servers, but the architecture (host-network exporter + bridge-network observability) generalizes to any UDP service that needs combined event-style alerting and continuous metric collection.

---

## Architecture

```
                              ┌───────────────────────────────────────────────┐
                              │                  VPS  host                    │
                              │   (Ubuntu 22.04, Docker engine, UFW, root)    │
                              │                                               │
   Player UDP traffic ─────►──┼──► Game server processes  (outside Docker)    │
                              │       └── writes  /opt/halo-monitor/          │
                              │             players.log  (CSV, append-only)   │
                              │                                               │
                              │   ┌─────────────────────────────────────────┐ │
                              │   │ Docker (compose-managed)                │ │
                              │   │                                         │ │
                              │   │  ┌────────────────────────┐             │ │
                              │   │  │ netmon-alert  (host)   │             │ │
                              │   │  │ • iptables counters    │             │ │
                              │   │  │ • ss -uan flood detect │             │ │
                              │   │  │ • players.log tail     │             │ │
                              │   │  │ • Discord push         │─────────────┼─┼──► Discord webhook
                              │   │  │ • /metrics  :9100      │             │ │
                              │   │  └───────────▲────────────┘             │ │
                              │   │              │ scrape                   │ │
                              │   │  ┌───────────┴────────────┐             │ │
                              │   │  │ node-exporter (host)   │             │ │
                              │   │  │ • CPU / mem / disk     │             │ │
                              │   │  │ • host network throughput│           │ │
                              │   │  │ • /metrics  :9101      │             │ │
                              │   │  └───────────▲────────────┘             │ │
                              │   │              │ scrape                   │ │
                              │   │  ┌───────────┴────────────┐             │ │
                              │   │  │ prometheus  (bridge)   │             │ │
                              │   │  │ • 30d TSDB             │             │ │
                              │   │  │ • :9090 localhost-only │             │ │
                              │   │  └───────────▲────────────┘             │ │
                              │   │              │ query                    │ │
                              │   │  ┌───────────┴────────────┐             │ │
                              │   │  │ grafana     (bridge)   │─────────────┼─┼──► http://vps:3000
                              │   │  │ • provisioned DS       │             │ │
                              │   │  │ • netmon-alert dashboard│            │ │
                              │   │  └────────────────────────┘             │ │
                              │   └─────────────────────────────────────────┘ │
                              └───────────────────────────────────────────────┘
```

**Two channels, two jobs:**
- **Discord** = push-style. Single events you want a human to see immediately (player joins, DDoS spike, service crash).
- **Prometheus** = pull-style. Continuous time-series for trend analysis, capacity planning, and historical incident review.

Trying to use either channel for the other job is the wrong tool. The platform deliberately runs both.

---

## Key features

- **Per-port DDoS detection** — packet rate, bandwidth rate, and unique-source-IP flood thresholds, each with independent alert cooldowns to prevent storming the channel during sustained attacks.
- **Real-time Discord embeds** — player joins / leaves enriched with country (via proxycheck.io), VPN/proxy detection, returning-visitor markers, and a click-to-copy `connect` command per server.
- **Privacy-aware data flow** — CD-key hashes and full forensics CSV stay on disk, never in Discord. Player IPs are filtered out of attack-source lists to avoid doxxing legit lagging players as attackers.
- **Production observability** — a `/metrics` endpoint exposing PPS, BPS, players online, alert counters, lookup error rates, and webhook delivery health. Scraped by Prometheus and visualized in a pre-provisioned Grafana dashboard.
- **Host system metrics** — node-exporter sidecar surfaces CPU, memory, disk, load, uptime, and host network throughput so the dashboard tells you whether a problem is the game server, the bot, or the box itself.
- **Self-healing** — every service has a Docker healthcheck. `restart: unless-stopped` survives reboots without flapping on a deliberate `docker compose stop`.
- **Declarative provisioning** — Grafana datasource and dashboard are configured via YAML files on first boot. Zero manual click-through.
- **Persistent state** — named volumes for the Prometheus TSDB and Grafana database. `docker compose down && up` doesn't lose history.

---

## Tech stack

| Layer | Tool | Version |
|---|---|---|
| Runtime | Docker Engine + Compose plugin | 27+ |
| Exporter | Python 3.12 + `prometheus-client` + `requests` | latest |
| Time-series DB | Prometheus | v2.55.1 |
| Visualization | Grafana | 11.3.0 |
| Host metrics | node-exporter | v1.8.2 |
| Geolocation / VPN detection | proxycheck.io API | free tier (no key) |
| Host firewall | UFW + iptables | distro-provided |
| Push channel | Discord webhooks | — |

All upstream images are **pinned to specific versions** — `latest` is a moving target and breaks reproducibility.

---

## Design decisions, with reasoning

### Why containerize at all?

The original deployment was a hand-managed systemd unit on the host. Containerization gives us:

- **Reproducible deploys** — one image, same binary everywhere.
- **Dependency isolation** — Python and its libs ship with the image; the host stays clean.
- **One-command upgrades** — `docker compose pull && docker compose up -d` is the entire rollout procedure.
- **Easy rollback** — pinned image tags mean the previous version is one `docker tag` swap away.

### Why does `netmon-alert` need `network_mode: host`?

Because the bot reads **the host's** packet counters (`iptables -L INPUT -v -n`) and **the host's** open UDP sockets (`ss -uan`). A bridge-networked container has its own network namespace and would see *its own* iptables table and *its own* sockets — both empty. Host networking is the only correct way to see real host UDP traffic.

The trade-off is loss of network isolation for that one container, which is justified because the bot's job *is* to inspect host networking. NET_ADMIN capability is also required so the bot can `iptables -I INPUT` to insert the counter rules at startup.

### Why bridge networking for Prometheus and Grafana?

They don't need host-level visibility — they communicate by name on a private Docker bridge (`prometheus:9090`, `grafana:3000`). Benefits:

- **DNS-based service discovery** — Grafana's datasource URL is `http://prometheus:9090`, no IP hardcoding.
- **Reduced attack surface** — Prometheus's port 9090 is bound to `127.0.0.1` on the host, not exposed publicly. Only Grafana (port 3000) is reachable from outside, and only because that's the intentional dashboard endpoint.

### Why `host.docker.internal` from Prometheus → netmon-alert?

Bridge-networked Prometheus can't address host-networked netmon-alert by Docker DNS — they're in different network namespaces. `extra_hosts: host.docker.internal:host-gateway` is the canonical Linux workaround that gives the bridge container a routable name for the host. Docker Desktop adds this automatically on macOS/Windows; we set it explicitly for Linux parity.

### Why both Discord *and* Prometheus?

They answer different questions:
- **Discord** is push-style, event-driven: "this happened right now, look." One message per event, human-readable, mobile-pingable.
- **Prometheus** is pull-style, continuous: "what's the shape of traffic over the last 24 hours?" Time-series, queryable, dashboard-able.

Trying to put trend analysis into Discord (or alerts into Grafana without a paged operator) is the wrong tool in both directions.

### Why `unless-stopped` over `always`?

`always` overrides a deliberate `docker compose stop` and restarts anyway. `unless-stopped` respects operator intent: Docker restarts on host reboot or container crash, but a manual stop stays stopped.

### Why pinned image tags?

`prom/prometheus:v2.55.1`, `grafana/grafana:11.3.0`, `prom/node-exporter:v1.8.2`. `latest` is a moving target — a rebuild months later could pull a different version with breaking changes. Dependabot or Renovate can bump these via PR for auditable, opt-in upgrades.

### Why 30-day Prometheus retention?

`--storage.tsdb.retention.time=30d` is a default that fits comfortably under 1GB for this metric volume. Long enough to spot weekly patterns, short enough not to bloat the VPS disk.

### Why a CSV log on disk and not a database?

The game server's Lua side has to write to *something* that the Python container can read. A bind-mounted CSV is the simplest contract: append-only, human-readable, no schema migrations, no other moving parts. The bot tails it with a `players.log.pos` bookmark file so restarts pick up where they left off without re-posting old events.

---

## Screenshots

> Drop screenshots into `docs/screenshots/` and reference them here.

- `docs/screenshots/grafana-overview.png` — full Grafana dashboard at a glance.
- `docs/screenshots/discord-join.png` — example player-join embed with country flag, VPN flag, and connect command.
- `docs/screenshots/discord-flood-alert.png` — example DDoS flood alert.
- `docs/screenshots/prometheus-targets.png` — Prometheus `/targets` view showing all three jobs healthy.

---

## Repository layout

```
monitoring-platform/
├── docker-compose.yml                              # the entire stack
├── .env.example                                    # config template (commit)
├── .env                                            # real secrets (gitignored)
├── .gitignore
├── README.md
├── netmon-alert/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── netmon_alert.py
├── prometheus/
│   └── prometheus.yml
└── grafana/
    ├── provisioning/
    │   ├── datasources/prometheus.yml
    │   └── dashboards/dashboards.yml
    └── dashboards/
        └── netmon-alert.json
```

---

## Setup

### Prerequisites

- Linux host with Docker Engine 27+ and the Compose plugin.
- A Discord webhook URL.
- Optional: a [proxycheck.io](https://proxycheck.io/dashboard) free API key for 1000 VPN lookups/day instead of the keyless 100/day.

Install Docker on a fresh Ubuntu host:

```bash
curl -fsSL https://get.docker.com | sh
sudo apt install -y docker-compose-plugin
```

### Local clone

```bash
git clone https://github.com/julivnexe/monitoring-platform.git
cd monitoring-platform
cp .env.example .env
$EDITOR .env        # set DISCORD_WEBHOOK, HALO_SERVERS, GRAFANA_ADMIN_PASSWORD
```

### Bring it up

```bash
docker compose build
docker compose up -d
docker compose ps                                # all services Up (healthy)
docker compose logs -f netmon-alert              # tail the bot
```

Then visit:

| URL | What |
|---|---|
| `http://localhost:3000` | Grafana (login from `.env`) → dashboard "netmon-alert overview" |
| `http://127.0.0.1:9090` | Prometheus UI (localhost-bound) |
| `http://127.0.0.1:9100/metrics` | Raw bot metrics |
| `http://127.0.0.1:9101/metrics` | Host system metrics (node-exporter) |

### Production deploy on a VPS

```bash
ssh root@your-vps
git clone https://github.com/julivnexe/monitoring-platform.git /opt/monitoring-platform
cd /opt/monitoring-platform
cp .env.example .env && $EDITOR .env

docker compose up -d --build
```

**UFW recommendations:**

```bash
sudo ufw allow 22/tcp                                 # SSH
sudo ufw allow 3000/tcp                               # Grafana (lock down by source IP for real production)
sudo ufw allow in on docker0 to any port 9100 proto tcp   # Prometheus → netmon-alert
sudo ufw allow in on docker0 to any port 9101 proto tcp   # Prometheus → node-exporter
sudo ufw deny 9090/tcp                                # Prometheus stays internal
sudo ufw enable
```

For real production, also put Grafana behind a reverse proxy with TLS (Caddy or nginx + Let's Encrypt) and bind it to `127.0.0.1:3000` rather than `0.0.0.0:3000`.

### Day-2 ops

```bash
# Tail one service
docker compose logs -f netmon-alert

# Restart after .env edit
docker compose up -d

# Pull updated upstream images
docker compose pull && docker compose up -d

# Full teardown (keeps volumes)
docker compose down

# Wipe everything including TSDB
docker compose down -v
```

---

## What's exposed

Bot metrics (job `netmon-alert`):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `netmon_pps` | Gauge | `server`, `port` | Inbound packets/sec |
| `netmon_bps` | Gauge | `server`, `port` | Inbound bytes/sec |
| `netmon_unique_src_ips_window` | Gauge | `server`, `port` | Distinct source IPs in flood-detection window |
| `netmon_players_online` | Gauge | `server` | Active players, derived from `players.log` replay |
| `netmon_player_joins_total` | Counter | `server` | Cumulative joins |
| `netmon_player_leaves_total` | Counter | `server` | Cumulative leaves |
| `netmon_vpn_detections_total` | Counter | `server` | Joins flagged as VPN/proxy |
| `netmon_alerts_fired_total` | Counter | `server`, `kind` | Discord alerts emitted (pps/bps/flood) |
| `netmon_webhook_errors_total` | Counter | — | Failed Discord POSTs |
| `netmon_ip_lookups_total` | Counter | `status` | proxycheck.io call outcomes |

Plus the full standard node-exporter metric set: `node_cpu_seconds_total`, `node_memory_MemAvailable_bytes`, `node_filesystem_*`, `node_network_*`, `node_load1/5/15`, `node_boot_time_seconds`, etc.

Useful PromQL one-liners:

```promql
# Sustained high-PPS server (5m rolling avg)
avg_over_time(netmon_pps[5m]) > 500

# Joins per minute, per server
rate(netmon_player_joins_total[5m]) * 60

# Any alert in the last hour?
increase(netmon_alerts_fired_total[1h]) > 0

# VPN-join ratio (last hour)
increase(netmon_vpn_detections_total[1h])
  / clamp_min(increase(netmon_player_joins_total[1h]), 1)

# Host CPU usage %
100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)
```

---

## Future improvements

- **Alertmanager** for paging — move threshold logic out of the bot and into Prometheus rules + an Alertmanager Discord/PagerDuty receiver. Decouples *what to alert on* from *how to detect it*. The push-style join/leave events stay in the bot regardless.
- **Loki + Promtail** for centralized log aggregation. Container stdout is currently JSON-file-rotated; Loki would make logs queryable alongside metrics in Grafana.
- **TLS + reverse proxy** in front of Grafana (Caddy is the simplest path — automatic Let's Encrypt).
- **Backups** for the Prometheus TSDB and Grafana SQLite. A nightly `docker run --rm -v ... busybox tar` cron job into off-host storage covers it.
- **CI** on the repo — GitHub Actions to lint Python, validate compose with `docker compose config`, and build the netmon-alert image on every PR.
- **Multi-host** — if the game servers ever split across VPSes, replace `host.docker.internal` with the explicit host IP per scrape target and shift Prometheus into a federation topology.
- **AlertManager → Discord** with deduplication and grouping, so a sustained DDoS doesn't fire 60 embeds in 60 seconds.

---

## License

MIT
