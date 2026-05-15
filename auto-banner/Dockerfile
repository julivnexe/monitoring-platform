# =====================================================================
# auto-banner — automatic botnet / DDoS subnet ban service
#
# Same base as netmon-alert (python:3.12-slim). Needs three host-level
# tools beyond Python: ipset (kernel set datastore), iptables (insert
# the single DROP rule referencing the set), and tcpdump (sample
# traffic to identify attacker IPs).
#
# Runs as root for ipset/iptables manipulation; the compose unit
# restricts capabilities to NET_ADMIN + NET_RAW.
# =====================================================================

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ipset \
        iptables \
        tcpdump \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY auto_banner.py .

# Sanity healthcheck — process is alive and ipset binary works.
HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
  CMD pgrep -f auto_banner.py > /dev/null && ipset list -n > /dev/null || exit 1

CMD ["python", "/app/auto_banner.py"]
