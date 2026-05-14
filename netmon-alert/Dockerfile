# =====================================================================
# netmon-alert — Halo CE monitoring exporter + Discord notifier
#
# Base image: python:3.12-slim (~50MB) — small surface, security-patched,
# no apt cache, no compilers. Multi-stage isn't worth it for pure Python.
#
# Runtime tools we shell out to:
#   iptables  — read host packet/byte counters per UDP port
#   iproute2  — provides `ss -uan` for socket inspection
#   wget      — used by the Docker HEALTHCHECK only
# We run as root because iptables manipulation requires it. NET_ADMIN
# cap on the container constrains what root can actually do on the host.
# =====================================================================

FROM python:3.12-slim

# Don't write .pyc files inside the container (writable layer pollution),
# and force stdout/stderr to be unbuffered so `docker logs` is live.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System dependencies. apt cache pruned in the same RUN to keep the
# image small.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        wget \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps in a separate layer so they're cached across rebuilds
# when only the script changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY netmon_alert.py .

# Default port for /metrics. Override with METRICS_PORT env if needed.
EXPOSE 9100

# Container-level healthcheck — Docker restarts the container if this
# fails. The docker-compose healthcheck is the same logic; either layer
# alone would suffice but having both means `docker run` (no compose)
# also gets the safety net.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9100/metrics > /dev/null || exit 1

CMD ["python", "/app/netmon_alert.py"]
