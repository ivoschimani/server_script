#!/usr/bin/env bash

# Docker host + QEMU agent + hardened public SSH — Debian 13 Trixie / Hetzner Cloud
# Usage:
#   sudo ./server.sh
#
# Env vars:
#   ALLOW_HTTP           yes|no (default yes)
#   ALLOW_HTTPS          yes|no (default yes)
#   SSH_PORT             SSH port (default 22)
#   INSTALL_TAILSCALE    yes|no (default no)
#                        Installs and enables tailscaled.
#   TAILSCALE_AUTH_KEY   (optional) Tailscale auth key — if set, the node is authenticated
#                        automatically during the script via 'tailscale up --authkey=...'.
#                        Generate one at https://login.tailscale.com/admin/settings/keys
#                        Reusable / ephemeral keys both work; prefer ephemeral for servers.
#                        If unset, run 'tailscale up' manually after the script completes.
#   SSH_VIA_TAILSCALE    yes|no (default no)  — requires INSTALL_TAILSCALE=yes
#                        Removes SSH from the public UFW rules and allows it only
#                        on the tailscale0 interface. SSH becomes unreachable via the
#                        public IP. Strongly recommended to set TAILSCALE_AUTH_KEY as
#                        well — without it the node won't join the tailnet until you
#                        run 'tailscale up' manually (Hetzner VNC is your only fallback).
#   TAILSCALE_EXIT_NODE  yes|no (default no)  — requires INSTALL_TAILSCALE=yes
#                        Advertises this server as a Tailscale exit node so that other
#                        devices on your tailnet can route all internet traffic through it.
#                        Enables net.ipv4.ip_forward and net.ipv6.conf.all.forwarding.
#                        After joining the tailnet you must approve the exit node once in
#                        the Tailscale admin console (Machines → Edit route settings) unless
#                        you use an auth key with auto-approval enabled.
#
# SSH model:
#   Default: Port is open to the public internet (rate-limited by UFW, hardened by fail2ban)
#   With SSH_VIA_TAILSCALE=yes: SSH is restricted to the tailscale0 interface only.
#     UFW blocks public SSH; only peers on your tailnet can connect.
#     IMPORTANT: do NOT close this session until tailscale is authenticated and
#     you have verified SSH access via your Tailscale IP.
#   Authentication: public key only — all password auth disabled
#   Ensure your SSH public key is in ~/.ssh/authorized_keys BEFORE running this script,
#     or add it via the Hetzner Cloud console / rescue system afterwards.
#
# Docker / UFW note:
#   Docker bypasses UFW by manipulating iptables directly. Mitigated by:
#   - "ip": "127.0.0.1" in daemon.json (localhost-only default binding)
#   - DOCKER-USER iptables chain rules (persisted via systemd, see below)

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

########################
# Preconditions
########################

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this script as root (sudo)." >&2
  exit 1
fi

if ! grep -qi "debian" /etc/os-release; then
  echo "This script is intended for Debian only." >&2
  exit 1
fi

ALLOW_HTTP="${ALLOW_HTTP:-yes}"
ALLOW_HTTPS="${ALLOW_HTTPS:-yes}"
SSH_PORT="${SSH_PORT:-22}"
INSTALL_TAILSCALE="${INSTALL_TAILSCALE:-no}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
SSH_VIA_TAILSCALE="${SSH_VIA_TAILSCALE:-no}"
TAILSCALE_EXIT_NODE="${TAILSCALE_EXIT_NODE:-no}"

if [ "${SSH_VIA_TAILSCALE}" = "yes" ] && [ "${INSTALL_TAILSCALE}" != "yes" ]; then
  echo "ERROR: SSH_VIA_TAILSCALE=yes requires INSTALL_TAILSCALE=yes" >&2
  exit 1
fi

if [ "${TAILSCALE_EXIT_NODE}" = "yes" ] && [ "${INSTALL_TAILSCALE}" != "yes" ]; then
  echo "ERROR: TAILSCALE_EXIT_NODE=yes requires INSTALL_TAILSCALE=yes" >&2
  exit 1
fi

if [ "${SSH_VIA_TAILSCALE}" = "yes" ] && [ -z "${TAILSCALE_AUTH_KEY}" ]; then
  echo "WARNING: SSH_VIA_TAILSCALE=yes but TAILSCALE_AUTH_KEY is not set." >&2
  echo "         The node will NOT join the tailnet automatically. Public SSH will be" >&2
  echo "         blocked and the Hetzner VNC console will be your only access until" >&2
  echo "         you run 'tailscale up' manually. Continuing in 10 seconds..." >&2
  sleep 10
fi

# Resolve the actual home directory of the invoking user (works under sudo)
REAL_HOME="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)"
MGMT_DIR="${REAL_HOME}/management"

########################
# System update
########################

echo "[*] Updating system packages..."
apt-get update -y
apt-get upgrade -y

########################
# Install base tools
########################

echo "[*] Installing base utilities..."
apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  ufw \
  fail2ban \
  jq \
  apt-transport-https \
  htop \
  qemu-guest-agent \
  nano

# Note: iptables-persistent / netfilter-persistent are intentionally NOT installed.
# In Debian 13 Trixie, ufw (0.36.2-9) has a hard Breaks: on iptables-persistent (1.0.23)
# and they cannot coexist. DOCKER-USER rules are persisted via a systemd service instead.

########################
# Block iptables-persistent (apt pinning)
########################

echo "[*] Blocking iptables-persistent via apt pinning..."

# iptables-persistent snapshots the ENTIRE iptables state (including dynamic Docker
# chains, UFW rules, Tailscale chains) and replays them on every boot. Docker then
# adds its own chains on top → duplicated/corrupted rules → containers unreachable.
# DOCKER-USER rules are persisted via a dedicated systemd service instead.
cat >/etc/apt/preferences.d/no-iptables-persistent <<'EOF'
Package: iptables-persistent
Pin: release *
Pin-Priority: -1

Package: netfilter-persistent
Pin: release *
Pin-Priority: -1
EOF

########################
# QEMU Guest Agent
########################

echo "[*] Enabling QEMU Guest Agent..."
systemctl enable qemu-guest-agent
systemctl start qemu-guest-agent

########################
# Bridge netfilter module — load before sysctl
########################

# br_netfilter must be loaded before systemd-sysctl applies settings, otherwise
# the bridge-nf-call sysctls in 99-hardening.conf fail with "No such file or
# directory" (the /proc/sys/net/bridge/* sysfs files only exist when the module
# is loaded). Docker would later load br_netfilter on demand, but by then the
# sysctl values would already have been silently skipped.
echo 'br_netfilter' > /etc/modules-load.d/br_netfilter.conf
modprobe br_netfilter

########################
# Kernel / sysctl hardening
########################

echo "[*] Applying kernel sysctl hardening..."

cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
# TCP SYN flood protection
net.ipv4.tcp_syncookies = 1

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects (prevent routing table manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast pings and bogus ICMP errors
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Kernel pointer and dmesg restrictions
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 1

# Disable core dumps for setuid binaries
fs.suid_dumpable = 0

# Container-to-container Bridge traffic must NOT traverse iptables FORWARD.
# Without this, the DOCKER-USER chain's final DROP rule kills inter-container
# ICMP/TCP between containers on the same bridge (e.g. Traefik -> socket-proxy).
# Bridge isolation is enforced by Docker's network topology (separate user-defined
# networks per stack), not by iptables on the bridge itself.
# NOTE: This is belt-and-suspenders — Docker 29.x re-sets bridge-nf-call-iptables=1
# on every daemon start, so the actual fix lives in a docker.service drop-in
# (see 'Disable bridge netfilter on Docker startup' block below).
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-ip6tables = 0

# NOTE: net.ipv4.ip_forward is intentionally left at its default (1) — required by Docker
EOF

sysctl --system

# Exit node requires IP forwarding (Docker already benefits from ipv4, but ipv6 is not set above).
if [ "${TAILSCALE_EXIT_NODE}" = "yes" ]; then
  echo "[*] Enabling IP forwarding for Tailscale exit node..."
  cat >/etc/sysctl.d/99-tailscale-exit-node.conf <<'EOF'
# Required for Tailscale exit node functionality
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Relax reverse-path filter for exit node traffic.
# Strict mode (1, set in 99-hardening.conf) drops return packets that arrive on
# tailscale0 but were routed in via a different interface — this breaks exit node NAT.
# Loose mode (2) checks that a route to the source exists on ANY interface, which
# is sufficient to detect spoofing while allowing asymmetric exit node flows.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
  sysctl -p /etc/sysctl.d/99-tailscale-exit-node.conf

  # Fix UDP GRO forwarding on the main interface — Tailscale exit node throughput
  # drops significantly without this. See https://tailscale.com/s/ethtool-config-udp-gro
  MAIN_IF="$(ip -o -4 route show default | awk '{print $5; exit}')"
  if [ -n "${MAIN_IF}" ]; then
    echo "[*] Configuring UDP GRO forwarding on ${MAIN_IF} for Tailscale exit node..."
    apt-get install -y ethtool
    ethtool -K "${MAIN_IF}" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || \
      echo "WARNING: ethtool GRO config failed on ${MAIN_IF} — may not be supported by this NIC driver" >&2

    # Persist via a systemd service — ethtool settings reset on reboot
    cat >/etc/systemd/system/tailscale-gro.service <<EOF2
[Unit]
Description=Tailscale exit node UDP GRO forwarding
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ethtool -K ${MAIN_IF} rx-udp-gro-forwarding on rx-gro-list off

[Install]
WantedBy=multi-user.target
EOF2
    systemctl daemon-reload
    systemctl enable tailscale-gro.service
    echo "[*] tailscale-gro.service enabled (persists GRO config across reboots)"
  fi
fi

########################
# Install Docker CE (Debian repo)
########################

echo "[*] Setting up Docker repository (Debian Trixie)..."

install -m 0755 -d /etc/apt/keyrings

# Download GPG key and verify fingerprint before trusting it.
# Fingerprint source: https://docs.docker.com/engine/install/debian/
DOCKER_GPG_TMP="$(mktemp)"
curl -fsSL https://download.docker.com/linux/debian/gpg -o "${DOCKER_GPG_TMP}"

DOCKER_KEYRING_TMP="$(mktemp --suffix=.gpg)"
gpg --no-default-keyring --keyring "${DOCKER_KEYRING_TMP}" \
    --import "${DOCKER_GPG_TMP}" 2>/dev/null

DOCKER_GPG_EXPECTED="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
# Use --with-colons for structured output: the 'fpr' record contains the fingerprint
# in field 10. 'exit' after the first match ensures we get the PRIMARY key only,
# not a subkey (which caused false mismatches with grep-based extraction).
DOCKER_GPG_ACTUAL=$(gpg --no-default-keyring --keyring "${DOCKER_KEYRING_TMP}" \
    --with-colons --fingerprint 2>/dev/null \
    | awk -F: '/^fpr:/{print $10; exit}')

rm -f "${DOCKER_KEYRING_TMP}"

if [ "${DOCKER_GPG_ACTUAL}" != "${DOCKER_GPG_EXPECTED}" ]; then
  echo "Docker GPG key fingerprint mismatch!" >&2
  echo "  Expected: ${DOCKER_GPG_EXPECTED}" >&2
  echo "  Got:      ${DOCKER_GPG_ACTUAL}" >&2
  echo "Aborting — do NOT trust this key." >&2
  rm -f "${DOCKER_GPG_TMP}"
  exit 1
fi

echo "[*] Docker GPG key fingerprint verified."
gpg --dearmor < "${DOCKER_GPG_TMP}" > /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
rm -f "${DOCKER_GPG_TMP}"

CODENAME="$(lsb_release -cs)"

cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${CODENAME} stable
EOF

echo "[*] Installing Docker Engine..."
apt-get update -y
apt-get install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

systemctl enable docker
systemctl enable containerd
systemctl start docker
systemctl start containerd

# Add the invoking user to the docker group so they can run docker without sudo.
# This takes effect on next login; 'newgrp docker' activates it in the current session.
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  usermod -aG docker "${SUDO_USER}"
  echo "[*] Added ${SUDO_USER} to docker group (re-login or run: newgrp docker)"
fi

########################
# Docker daemon hardening
########################

echo "[*] Configuring Docker daemon hardening..."

mkdir -p /etc/docker

cat >/etc/docker/daemon.json <<'EOF'
{
  "icc": true,
  "no-new-privileges": true,
  "ip": "127.0.0.1",
  "log-driver": "json-file",
  "log-level": "info",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "iptables": true,
  "userland-proxy": false
}
EOF

# "icc": true        — allows inter-container communication on all networks.
#                     Isolation is achieved by network topology instead: each stack gets
#                     its own user-defined network, and containers are only attached to
#                     the networks they need. icc:false causes iptables DOCKER-ISOLATION
#                     rules that interfere with legitimate container-to-container traffic
#                     (e.g. Traefik → socket-proxy) and provides no real security benefit
#                     when user-defined networks are used correctly.
#
# "ip": "127.0.0.1"  — published ports bind to localhost by default (UFW/iptables bypass mitigation).
#                     Traefik MUST use explicit 0.0.0.0 binding:
#                       ports: ["0.0.0.0:80:80", "0.0.0.0:443:443"]
#                     Internal services (Arcane, DBs) must NOT use 0.0.0.0 — keep them on
#                     user-defined networks and route through Traefik.
#
# "userland-proxy": false — disables Docker's userland TCP proxy (docker-proxy process)
#                     and uses pure iptables DNAT for port forwarding instead.
#                     CRITICAL for Traefik ipAllowList middleware: docker-proxy replaces
#                     the real client source IP with the Docker bridge gateway IP (e.g.
#                     172.19.0.1), making IP-based access control impossible. With
#                     userland-proxy=false, the original client IP (including Tailscale
#                     100.64.x.x addresses) is preserved through to the container.

# Docker 29.x sets net.bridge.bridge-nf-call-iptables=1 on daemon startup, overriding
# anything in /etc/sysctl.d/. This is intentional Docker behaviour to support
# host-IP:mapped-port access between containers when userland-proxy=false (see PR
# https://github.com/moby/moby/pull/48685). Side effect: inter-container Bridge
# traffic gets routed through iptables FORWARD, where the DOCKER-USER chain's final
# DROP rule kills it (e.g. Traefik -> socket-proxy ping fails 100% after reboot).
#
# Trade-off accepted: we lose the ability for container A on bridge X to reach
# container B (also on bridge X) via the host's mapped port. We don't use that
# pattern — inter-container traffic goes via internal Docker networks by service
# name; external traffic comes through Traefik. userland-proxy=false stays enabled
# so Traefik IP allowlists keep seeing real client IPs (e.g. Tailscale 100.64/10).
#
# The drop-in below resets the values *after* dockerd's own bridge setup runs,
# which is the only reliable place to win this race.

mkdir -p /etc/systemd/system/docker.service.d

cat >/etc/systemd/system/docker.service.d/disable-bridge-netfilter.conf <<'EOF'
[Service]
ExecStartPost=/sbin/sysctl -w net.bridge.bridge-nf-call-iptables=0
ExecStartPost=/sbin/sysctl -w net.bridge.bridge-nf-call-ip6tables=0
EOF

systemctl daemon-reload
systemctl restart docker

########################
# Docker / UFW iptables hardening (DOCKER-USER chain)
########################

echo "[*] Hardening Docker iptables via DOCKER-USER chain..."

# Persist as a standalone script — only DOCKER-USER chain, never all chains.
# Earlier approach (iptables-save/restore) snapshotted UFW + Tailscale + Docker
# rules together and replayed them on boot. Then all those tools re-inserted
# their own rules on top → exponential accumulation across reboots.
#
# IMPORTANT: this script is fully static (single-quoted heredoc). Conditional
# rules based on shell vars at install time were unreliable — an earlier version
# silently dropped the 172.16/12 RETURN rules due to nested expansion inside the
# heredoc, breaking all container outbound traffic after every reboot.
# If you need to disable HTTP/HTTPS, edit /usr/local/sbin/apply-docker-user-rules.sh
# directly after the bootstrap (ALLOW_HTTP/ALLOW_HTTPS env vars only gate UFW
# now, not the DOCKER-USER chain).
cat >/usr/local/sbin/apply-docker-user-rules.sh <<'RULES_EOF'
#!/bin/bash
set -euo pipefail

# Wait for DOCKER-USER chain to exist (Docker creates it on startup)
for i in {1..30}; do
  iptables -L DOCKER-USER -n >/dev/null 2>&1 && break
  sleep 1
done

iptables -F DOCKER-USER

# Allow loopback and established connections
iptables -A DOCKER-USER -i lo -j RETURN
iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

# Allow Tailscale source range (Exit Node clients reaching containers)
iptables -A DOCKER-USER -s 100.64.0.0/10 -j RETURN

# Allow all container outbound traffic (covers container-to-container AND
# container-to-external; Docker uses the 172.16.0.0/12 range for bridges).
iptables -A DOCKER-USER -s 172.16.0.0/12 -j RETURN

# Allow inbound HTTP/HTTPS to containers
iptables -A DOCKER-USER -p tcp --dport 80 -j RETURN
iptables -A DOCKER-USER -p tcp --dport 443 -j RETURN

# Drop everything else
iptables -A DOCKER-USER -j DROP

# Tailscale Exit Node MASQUERADE — only takes effect when this server is an
# exit node, otherwise the rule is harmless (no Tailscale traffic to NAT).
# Idempotent: -C checks for the rule before -A appends.
MAIN_IF="$(ip -o -4 route show default | awk '{print $5; exit}')"
if [ -n "${MAIN_IF}" ]; then
  iptables -t nat -C POSTROUTING -o "${MAIN_IF}" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "${MAIN_IF}" -j MASQUERADE
fi

logger -t docker-user-rules "DOCKER-USER rules applied"
RULES_EOF

chmod 700 /usr/local/sbin/apply-docker-user-rules.sh

# Apply the rules now (single source of truth — the same script that runs on every reboot)
/usr/local/sbin/apply-docker-user-rules.sh

cat >/etc/systemd/system/docker-iptables-restore.service <<'EOF'
[Unit]
Description=Apply DOCKER-USER iptables rules
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/apply-docker-user-rules.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable docker-iptables-restore.service

########################
# Restart socket-proxies after Docker daemon restarts
########################

echo "[*] Configuring socket-proxy auto-restart after Docker daemon restarts..."

# When the Docker daemon restarts (e.g. after an unattended-upgrade of docker-ce),
# /var/run/docker.sock is recreated with a new inode. The socket-proxy bind mount
# still points to the old (now deleted) inode — HAProxy inside returns 503 on every
# request, even though the container shows as "Up" (live-restore=true keeps it
# running). This drop-in restarts both proxies after every dockerd start so they
# pick up the fresh socket.
#
# `-` prefix on ExecStartPost tells systemd to ignore failures: on first boot (before
# `docker compose up` has ever run) neither container exists, and we don't want
# docker.service to be marked failed for that. The autoheal container provides a
# secondary safety net via healthchecks.

mkdir -p /etc/systemd/system/docker.service.d

cat >/etc/systemd/system/docker.service.d/restart-socket-proxy.conf <<'EOF'
[Service]
ExecStartPost=-/usr/bin/docker restart socket-proxy-traefik socket-proxy-mgmt
EOF

systemctl daemon-reload

# Note: Docker networks (traefik-public, socket-proxy-traefik, socket-proxy-mgmt)
# are created by the compose files themselves on first `docker compose up`.

########################
# Docker socket proxy + Traefik + Arcane compose files
########################

echo "[*] Writing Traefik / Arcane compose templates..."

# WHY A SOCKET PROXY?
# Mounting /var/run/docker.sock into a container gives that container unrestricted
# root-equivalent access to the Docker daemon — it can start/stop/delete any container,
# pull images, escape to the host, etc. The socket proxy (tecnativa/docker-socket-proxy)
# exposes only the specific API endpoints each service actually needs, over a private
# network. The real socket never leaves the proxy container.

mkdir -p "${MGMT_DIR}/traefik/dynamic" "${MGMT_DIR}/arcane" "${MGMT_DIR}/socket-proxy"

# ── Socket proxies (split: read-only for Traefik, full for management UIs) ────
#
# Two socket-proxy instances:
#  - socket-proxy-traefik: minimal API surface (read-only). Traefik talks to this.
#                          Traefik is exposed to the public internet — limiting its
#                          Docker API access reduces blast radius if it gets compromised.
#  - socket-proxy-mgmt:    full API surface (POST/DELETE/EXEC/BUILD/SYSTEM/...).
#                          Used by Arcane and Code Server, which need to manage
#                          containers, exec into them, and build images. Both are
#                          accessible only via Tailscale (Traefik IPAllowList) so the
#                          attack surface is restricted to the tailnet.
#
# Even with the split, socket-proxy-mgmt is effectively root-equivalent on the host —
# the security boundary for Arcane/Code-Server is the Tailscale-only access policy,
# not the proxy itself.

cat >"${MGMT_DIR}/socket-proxy/docker-compose.yml" <<'EOF'
# Socket proxies — start this stack before Traefik / Arcane / Code Server.
# Creates the two private networks (socket-proxy-traefik, socket-proxy-mgmt)
# that the consumer stacks reference as external.

services:
  socket-proxy-traefik:
    image: tecnativa/docker-socket-proxy:latest
    container_name: socket-proxy-traefik
    restart: unless-stopped
    # Healthcheck: detects stale socket connections (e.g. after Docker engine updates
    # via unattended-upgrades). With live-restore=true the container stays "Up" but
    # HAProxy inside loses its connection to docker.sock — _ping returns 503.
    # autoheal below detects unhealthy and restarts automatically; a systemd drop-in
    # on docker.service additionally restarts both proxies on every dockerd start.
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:2375/_ping"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      # Strictly read-only API surface — only what Traefik's docker provider needs.
      # NO POST, DELETE, EXEC, BUILD — Traefik must NEVER be able to mutate Docker.
      CONTAINERS: 1
      NETWORKS:   1
      SERVICES:   1
      TASKS:      1
      INFO:       1
      VERSION:    1
      PING:       1
    networks:
      - socket-proxy-traefik
    security_opt:
      - no-new-privileges:true
    labels:
      - "autoheal=true"

  socket-proxy-mgmt:
    image: tecnativa/docker-socket-proxy:latest
    container_name: socket-proxy-mgmt
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:2375/_ping"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      # Full API surface — required by Arcane (container management UI) and Code
      # Server (in-IDE Docker workflows: exec, build, restart). Effectively
      # root-equivalent. Mitigated by Tailscale-only access at the Traefik layer.
      CONTAINERS: 1
      NETWORKS:   1
      SERVICES:   1
      TASKS:      1
      IMAGES:     1
      VOLUMES:    1
      INFO:       1
      VERSION:    1
      PING:       1
      POST:       1
      DELETE:     1
      EXEC:       1
      BUILD:      1
      SYSTEM:     1
      NODES:      1
    networks:
      - socket-proxy-mgmt
    security_opt:
      - no-new-privileges:true
    labels:
      - "autoheal=true"

  autoheal:
    image: willfarrell/autoheal:latest
    container_name: autoheal
    restart: unless-stopped
    # Monitors containers labelled autoheal=true and restarts them when unhealthy.
    # Needs docker.sock to call the Docker API — direct mount is acceptable here
    # because autoheal runs no user-facing services and its attack surface is minimal.
    # network_mode: none — autoheal only needs docker.sock, no network connectivity.
    # Without this Docker Compose creates a spurious default bridge which may get a
    # subnet outside 172.16.0.0/12 and trigger the DOCKER-USER DROP rule.
    network_mode: none
    environment:
      AUTOHEAL_CONTAINER_LABEL: autoheal
      AUTOHEAL_INTERVAL: 30        # check every 30 s
      AUTOHEAL_START_PERIOD: 60    # ignore unhealthy during first 60 s after daemon start
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    security_opt:
      - no-new-privileges:true

networks:
  # Networks owned by this stack. Other stacks reference them as external.
  socket-proxy-traefik:
    name: socket-proxy-traefik
  socket-proxy-mgmt:
    name: socket-proxy-mgmt
EOF

# ── Traefik ───────────────────────────────────────────────────────────────────
# Unquoted heredoc — ${MGMT_DIR} is substituted at script-write time so the
# resulting compose file has absolute paths and is self-contained (no env vars
# required at `docker compose up` time).
cat >"${MGMT_DIR}/traefik/docker-compose.yml" <<EOF
# Traefik reverse proxy
# Prerequisites:
#   1. socket-proxy stack running (cd ~/management/socket-proxy && docker compose up -d)
#   2. Set TRAEFIK_ACME_EMAIL below
#   3. Replace YOURDOMAIN with your actual domain
#   4. cd ~/management/traefik && docker compose up -d
#
# Networks: this stack owns the traefik-public network and creates it on first up.

services:
  traefik:
    image: traefik:v3
    container_name: traefik
    restart: unless-stopped
    command:
      - "--api.dashboard=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      # Point to read-only socket proxy — never mount docker.sock directly.
      # socket-proxy-traefik exposes only GET endpoints (CONTAINERS, NETWORKS, ...);
      # if Traefik is compromised it cannot start/stop/exec into containers.
      - "--providers.docker.endpoint=tcp://socket-proxy-traefik:2375"
      - "--providers.docker.network=traefik-public"
      # File provider for shared middlewares (e.g. tailscale-only) — referenced
      # from any container's labels as <name>@file. Watching means edits take
      # effect without a Traefik restart.
      - "--providers.file.directory=/dynamic"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.http.tls.certresolver=letsencrypt"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=TRAEFIK_ACME_EMAIL"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--log.level=INFO"
      - "--accesslog=true"
    ports:
      # MUST be 0.0.0.0 — daemon.json defaults to 127.0.0.1
      - "0.0.0.0:80:80"
      - "0.0.0.0:443:443"
    volumes:
      - ${MGMT_DIR}/traefik/letsencrypt:/letsencrypt
      - ${MGMT_DIR}/traefik/dynamic:/dynamic:ro
    networks:
      traefik-public:
        ipv4_address: 172.18.0.254
      socket-proxy-traefik:
    security_opt:
      - no-new-privileges:true

networks:
  # Owned by this stack: created on first compose up if it doesn't exist.
  traefik-public:
    name: traefik-public
    ipam:
      config:
        - subnet: 172.18.0.0/16
  # Owned by the socket-proxy stack — must be up first.
  socket-proxy-traefik:
    name: socket-proxy-traefik
    external: true
EOF

# ── Traefik dynamic config: shared middlewares ───────────────────────────────
# File-provider config — picked up automatically because Traefik watches /dynamic.
# Add new shared middlewares here and reference them from any container as
# <name>@file (e.g. tailscale-only@file).
cat >"${MGMT_DIR}/traefik/dynamic/middlewares.yml" <<'EOF'
http:
  middlewares:
    # Tailscale-only access gate.
    # 100.64.0.0/10        → Tailscale CGNAT range (IPv4)
    # fd7a:115c:a1e0::/48  → Tailscale ULA prefix  (IPv6)
    # Public clients hitting a router with this middleware get HTTP 403.
    # Relies on userland-proxy=false in daemon.json so the real client IP
    # makes it to Traefik.
    tailscale-only:
      ipAllowList:
        sourceRange:
          - "100.64.0.0/10"
          - "fd7a:115c:a1e0::/48"
EOF

# ── Arcane ────────────────────────────────────────────────────────────────────

# Arcane requires two secrets (ENCRYPTION_KEY and JWT_SECRET) that must be
# stable across restarts — regenerating them invalidates all sessions and
# encrypted data. We generate them now and bake them into the compose file
# so they are ready to use without any manual steps.
echo "[*] Generating Arcane secrets..."
ARCANE_SECRETS_RAW="$(docker run --rm ghcr.io/getarcaneapp/arcane:latest /app/arcane generate secret 2>/dev/null)"
ARCANE_ENCRYPTION_KEY="$(echo "${ARCANE_SECRETS_RAW}" | awk -F'=' '/ENCRYPTION_KEY/{print $2}' | tr -d '[:space:]')"
ARCANE_JWT_SECRET="$(echo "${ARCANE_SECRETS_RAW}" | awk -F'=' '/JWT_SECRET/{print $2}' | tr -d '[:space:]')"

if [ -z "${ARCANE_ENCRYPTION_KEY}" ] || [ -z "${ARCANE_JWT_SECRET}" ]; then
  echo "ERROR: Failed to generate Arcane secrets. Is Docker running?" >&2
  exit 1
fi

mkdir -p "${MGMT_DIR}/arcane/stacks"

# NOTE: unquoted heredoc (<<EOF not <<'EOF') so that shell variables are expanded.
# Dollar signs that must appear literally in the YAML are escaped as \$. None here.
cat >"${MGMT_DIR}/arcane/docker-compose.yml" <<EOF
# Arcane — Docker management UI
# Prerequisites:
#   1. socket-proxy stack running
#   2. Traefik stack running
#   3. Replace YOURDOMAIN below (in APP_URL and the Traefik label)
#   4. cd ~/management/arcane && docker compose up -d
#
# Access (Tailscale-only):
#   Arcane is exposed via Traefik with an IPAllowList middleware that restricts
#   access to the Tailscale CGNAT range (100.64.0.0/10) and Tailscale ULA range
#   (fd7a:115c:a1e0::/48). Public clients get HTTP 403.
#   This relies on userland-proxy=false in daemon.json so the real client IP
#   reaches Traefik intact.
#
#   Set arcane.YOURDOMAIN in DNS → Traefik routes it. Connect via Tailscale.
#
# Fallback access (no DNS / Tailscale not yet up): SSH tunnel
#   ssh -L 3552:localhost:3552 user@YOUR_SERVER_IP
#   Then open: http://localhost:3552
#
# Default login: arcane / arcane-admin  ← CHANGE IMMEDIATELY after first login.
#
# SECRETS: ENCRYPTION_KEY and JWT_SECRET were generated during server setup.
# Keep them safe — regenerating them invalidates all sessions and encrypted data.

services:
  arcane:
    image: ghcr.io/getarcaneapp/arcane:latest
    container_name: arcane
    restart: unless-stopped
    environment:
      APP_URL: "https://arcane.YOURDOMAIN"
      # Talks to the FULL-API socket proxy (POST/DELETE/EXEC/BUILD enabled).
      # Public exposure is gated by the tailscale-only middleware on Traefik.
      DOCKER_HOST: "tcp://socket-proxy-mgmt:2375"
      # Secrets generated at server setup time — do not regenerate
      ENCRYPTION_KEY: "${ARCANE_ENCRYPTION_KEY}"
      JWT_SECRET: "${ARCANE_JWT_SECRET}"
      # Match the UID/GID of the invoking user so file permissions are correct
      PUID: "$(id -u "${SUDO_USER:-root}")"
      PGID: "$(id -g "${SUDO_USER:-root}")"
    volumes:
      - ${MGMT_DIR}/arcane/data:/app/data
      # Stacks volume: inside path MUST match outside path so that compose files
      # with relative volume references resolve correctly at deploy time.
      - ${MGMT_DIR}/arcane/stacks:${MGMT_DIR}/arcane/stacks
    networks:
      - traefik-public
      - socket-proxy-mgmt
    # Internal port 3552 — bound to 127.0.0.1 only (SSH tunnel fallback).
    # NOT publicly exposed.
    ports:
      - "127.0.0.1:3552:3552"
    security_opt:
      - no-new-privileges:true
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.arcane.rule=Host(\`arcane.YOURDOMAIN\`)"
      - "traefik.http.routers.arcane.entrypoints=websecure"
      # Tailscale-only gate — middleware defined in traefik/dynamic/middlewares.yml.
      - "traefik.http.routers.arcane.middlewares=tailscale-only@file"
      - "traefik.http.services.arcane.loadbalancer.server.port=3552"

networks:
  traefik-public:
    name: traefik-public
    external: true
  socket-proxy-mgmt:
    name: socket-proxy-mgmt
    external: true
EOF

# ── Example app stack (app + db pattern) ──────────────────────────────────────
cat >"${MGMT_DIR}/traefik/example-app-stack.yml" <<'EOF'
# Example: app container + database — correct network wiring
#
# - app and db share a private backend network (they can talk freely)
# - app also joins traefik-public so Traefik can route HTTP(S) to it
# - db is NOT on traefik-public (never exposed via Traefik or publicly)
# - network isolation is enforced by attaching each container only to the networks it needs

services:
  app:
    image: your-app-image
    restart: unless-stopped
    environment:
      DB_HOST: db        # resolves via Docker DNS on the backend network
      DB_PORT: 5432
    networks:
      - traefik-public   # Traefik routes inbound requests here
      - backend          # talks to db
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.myapp.rule=Host(`app.YOURDOMAIN`)"
      - "traefik.http.routers.myapp.entrypoints=websecure"
      - "traefik.http.services.myapp.loadbalancer.server.port=3000"

  db:
    image: postgres:16
    restart: unless-stopped
    volumes:
      - db-data:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    networks:
      - backend          # isolated — no Traefik, no public access

volumes:
  db-data:

networks:
  traefik-public:
    external: true
  backend:               # private to this stack
    driver: bridge
EOF

chmod 644 "${MGMT_DIR}/socket-proxy/docker-compose.yml"
chmod 644 "${MGMT_DIR}/traefik/docker-compose.yml"   # only contains placeholders / ACME email
chmod 644 "${MGMT_DIR}/traefik/dynamic/middlewares.yml"
chmod 600 "${MGMT_DIR}/arcane/docker-compose.yml"    # contains generated secrets
chmod 644 "${MGMT_DIR}/traefik/example-app-stack.yml"

# Fix ownership — script runs as root but files should belong to the invoking user
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  chown -R "${SUDO_USER}:$(id -gn "${SUDO_USER}")" "${MGMT_DIR}"
  echo "[*] Ownership of ${MGMT_DIR} set to ${SUDO_USER}"
fi

echo "[*] Compose templates written to ${MGMT_DIR}/{socket-proxy,traefik,arcane}/"

########################
# UFW firewall
########################

echo "[*] Configuring UFW firewall..."

ufw --force reset

# Default policy: deny incoming, allow outbound
ufw default deny incoming
ufw default allow outgoing

# Allow packet forwarding — required for Docker container outbound traffic.
# UFW sets DEFAULT_FORWARD_POLICY=DROP by default, which blocks all forwarded packets
# including containers reaching the internet (e.g. Traefik → Let's Encrypt).
# Docker container isolation is enforced by the DOCKER-USER iptables chain instead.
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
if ! grep -q 'DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw; then
  echo "WARNING: UFW forward policy was not updated — check /etc/default/ufw manually" >&2
fi

if [ "${ALLOW_HTTP}" = "yes" ]; then
  ufw allow 80/tcp
fi

if [ "${ALLOW_HTTPS}" = "yes" ]; then
  ufw allow 443/tcp
fi

# SSH: either public (rate-limited) or Tailscale-only depending on SSH_VIA_TAILSCALE.
if [ "${SSH_VIA_TAILSCALE}" = "yes" ]; then
  # Restrict SSH to the tailscale0 interface only — public SSH is blocked.
  # tailscale0 may not exist yet (tailscaled just installed, not authenticated).
  # UFW can reference interface names before the interface appears; the rule activates
  # automatically once tailscale0 comes up.
  ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp comment "SSH via Tailscale only"
  # Allow Tailscale's WireGuard UDP port so the node can join the tailnet.
  ufw allow 41641/udp comment "Tailscale WireGuard"
  echo "[!] SSH_VIA_TAILSCALE=yes — public SSH is BLOCKED."
  echo "    Run 'tailscale up' to join your tailnet, then verify SSH access before"
  echo "    closing this session or you will be locked out."
else
  # Key-only auth + fail2ban provide the real protection — this is a first-line filter.
  ufw limit "${SSH_PORT}"/tcp comment "SSH rate-limited"
fi

if [ "${INSTALL_TAILSCALE}" = "yes" ] && [ "${SSH_VIA_TAILSCALE}" != "yes" ]; then
  # Tailscale installed but SSH stays public — still allow the WireGuard port.
  ufw allow 41641/udp comment "Tailscale WireGuard"
fi

ufw logging medium

echo "y" | ufw enable

########################
# Fail2Ban for SSH
########################

echo "[*] Configuring Fail2Ban for SSH..."

mkdir -p /etc/fail2ban/jail.d

# Debian 13 uses systemd-journald; /var/log/auth.log may not exist.
# Use backend=systemd so fail2ban reads directly from the journal.
cat >/etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
backend  = systemd
maxretry = 3
bantime  = 3600
findtime = 600
EOF

systemctl restart fail2ban

########################
# Tailscale (optional)
########################

if [ "${INSTALL_TAILSCALE}" = "yes" ]; then
  echo "[*] Installing Tailscale..."

  # Use the official Tailscale apt repository for Debian Trixie.
  # The .noarmor.gpg key is the raw binary keyring format required by apt.
  curl -fsSL "https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg" \
    -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list" \
    -o /etc/apt/sources.list.d/tailscale.list

  apt-get update -y
  apt-get install -y tailscale

  systemctl enable tailscaled
  systemctl start tailscaled

  if [ -n "${TAILSCALE_AUTH_KEY}" ]; then
    echo "[*] Authenticating Tailscale with provided auth key..."
    # Auth key passed via a temp file (--auth-key=file:...) so the secret never
    # appears in 'ps' / process accounting / shell history. File is mode 0600
    # and removed via trap regardless of how this section exits.
    TS_KEYFILE="$(mktemp)"
    chmod 600 "${TS_KEYFILE}"
    printf '%s' "${TAILSCALE_AUTH_KEY}" > "${TS_KEYFILE}"
    # shellcheck disable=SC2064  # intentionally expand TS_KEYFILE now
    trap "rm -f '${TS_KEYFILE}'" EXIT

    # --timeout: abort rather than hang indefinitely if the control plane is unreachable.
    TS_UP_ARGS="--auth-key=file:${TS_KEYFILE} --timeout=60s"
    [ "${TAILSCALE_EXIT_NODE}" = "yes" ] && TS_UP_ARGS="${TS_UP_ARGS} --advertise-exit-node"
    # shellcheck disable=SC2086  # intentional word splitting on TS_UP_ARGS
    tailscale up ${TS_UP_ARGS}

    rm -f "${TS_KEYFILE}"
    trap - EXIT

    # Wait up to 30 s for the node to receive a Tailscale IP.
    TS_IP=""
    for _ in $(seq 1 30); do
      TS_IP="$(tailscale ip -4 2>/dev/null || true)"
      [ -n "${TS_IP}" ] && break
      sleep 1
    done

    if [ -n "${TS_IP}" ]; then
      echo "[*] Tailscale authenticated. Tailscale IP: ${TS_IP}"
    else
      echo "WARNING: Tailscale authenticated but could not retrieve IP within 30 s." >&2
      echo "         Run 'tailscale ip -4' once the node has fully connected." >&2
    fi
  else
    echo "[*] tailscaled installed and running."
    echo "    No auth key provided — run the following to join your tailnet:"
    if [ "${TAILSCALE_EXIT_NODE}" = "yes" ]; then
      echo "      tailscale up --advertise-exit-node"
    else
      echo "      tailscale up"
    fi
    echo "    Use 'tailscale status' to check connectivity."
  fi
fi

########################
# SSH hardening (drop-in config)
########################

echo "[*] Hardening SSH via sshd_config.d drop-in..."

# Write all hardening settings to a drop-in file rather than patching sshd_config with sed.
# - sshd_config and other drop-ins are left untouched (easier auditing/upgrades)
# - 99- prefix ensures this file wins over other drop-ins (last-wins ordering)
# - No risk of sed leaving conflicting commented/uncommented directives

SSHD_DROPIN="/etc/ssh/sshd_config.d/99-hardening.conf"

cat >"${SSHD_DROPIN}" <<'EOF'
# SSH hardening — managed by bootstrap script
# Public internet access: key-only, rate-limited by UFW, brute-force blocked by fail2ban.

# Disable all password-based auth
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no   # OpenSSH 8.7+ rename of ChallengeResponseAuthentication

# Require public key auth
PubkeyAuthentication yes

# Keep PAM for account/session processing on Debian
UsePAM yes

# No direct root login — connect as a regular user, then sudo
PermitRootLogin no

# Limit brute-force exposure
MaxAuthTries 3
LoginGraceTime 30

# Disable unnecessary / risky features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local   # Required for SSH tunnels to Arcane; set 'no' if not needed
PrintMotd no
EOF

# Validate config syntax before reloading — avoids locking yourself out
sshd -t || {
  echo "sshd config test FAILED — check ${SSHD_DROPIN}" >&2
  exit 1
}

systemctl reload ssh || systemctl restart ssh

########################
# Unattended upgrades (non-interactive)
########################

echo "[*] Enabling unattended security upgrades..."
apt-get install -y unattended-upgrades

# Write explicit config instead of relying on Debian defaults.
# Defaults only cover Debian-Security and never reboot — insufficient for production.
cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
    // Debian security updates
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    // Debian stable updates (bug fixes with security implications)
    "origin=Debian,codename=${distro_codename}-updates";
};

// Docker CE packages are excluded from unattended-upgrades (see Package-Blacklist below).
// Docker daemon restarts triggered by package updates corrupt iptables chains — Docker
// rebuilds its NAT/filter/raw rules on restart, but stale rules from the previous daemon
// instance accumulate, causing duplicated DOCKER-USER, FORWARD, and PREROUTING chains.
// This makes containers unreachable from the public internet. Update Docker manually:
//   apt update && apt upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin
//   systemctl restart docker

Unattended-Upgrade::Package-Blacklist {
    "docker-ce";
    "docker-ce-cli";
    "docker-ce-rootless-extras";
    "containerd.io";
    "docker-compose-plugin";
    "docker-buildx-plugin";
};

// Remove unused automatically-installed packages after upgrades
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Reboot automatically if a package requires it (e.g. kernel, libc, openssl).
// Reboots happen at 03:00 if needed. Set to "false" to reboot manually.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

// Send email on errors (optional — remove if not configured)
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "on-change";

// Write upgrade activity to syslog
Unattended-Upgrade::SyslogEnable "true";
EOF

# Enable the daily apt timers: update lists, download, install, clean
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Verify the config is valid and unattended-upgrades can read it
unattended-upgrade --dry-run 2>&1 | grep -E "Packages|No packages|ERROR" || true

########################
# Info / next steps
########################

SERVER_IP="$(hostname -I | awk '{print $1}')"

cat <<EOF

========================================
Setup complete on Debian 13 Trixie (Hetzner Cloud).

SUMMARY:
  System        Updated with DEBIAN_FRONTEND=noninteractive
  sysctl        /etc/sysctl.d/99-hardening.conf (SYN cookies, rp_filter, redirect blocks, etc.)
  Docker CE     icc=true, no-new-privileges, ip=127.0.0.1, userland-proxy=false
  iptables      DOCKER-USER: HTTP(${ALLOW_HTTP})/HTTPS(${ALLOW_HTTPS}) public; else DROP
                Persisted via systemd (docker-iptables-restore.service)
  Networks      Created on demand by compose:
                  socket-proxy stack → socket-proxy-traefik, socket-proxy-mgmt
                  traefik stack      → traefik-public (172.18.0.0/16, traefik @ .254)
  Templates     ${MGMT_DIR}/socket-proxy/docker-compose.yml   ← start this first
                ${MGMT_DIR}/traefik/docker-compose.yml        ← Traefik v3 (read-only sock)
                ${MGMT_DIR}/traefik/dynamic/middlewares.yml   ← shared middlewares (file provider)
                ${MGMT_DIR}/arcane/docker-compose.yml         ← Arcane (Tailscale-only)
                ${MGMT_DIR}/traefik/example-app-stack.yml     ← app+db wiring example
  QEMU agent    Enabled (Hetzner clean shutdown + IP reporting)
  UFW           deny inbound; HTTP/HTTPS open; SSH rate-limited (6/30s); logging=medium
  Fail2Ban      SSH via systemd backend; maxretry=3, bantime=1h
  SSH           Drop-in: ${SSHD_DROPIN}
                Public internet; key-only; PermitRootLogin=no; MaxAuthTries=3
  Tailscale     $(
    if [ "${INSTALL_TAILSCALE}" != "yes" ]; then
      echo "Not installed"
    elif [ -n "${TAILSCALE_AUTH_KEY}" ]; then
      TS_IP="$(tailscale ip -4 2>/dev/null || true)"
      [ -n "${TS_IP}" ] && echo "Authenticated — Tailscale IP: ${TS_IP}" \
                        || echo "Authenticated — IP pending (run: tailscale ip -4)"
    else
      echo "Installed — NOT yet authenticated. Run: tailscale up"
    fi
  )
$([ "${TAILSCALE_EXIT_NODE}" = "yes" ] && echo "  Exit node     Advertised — approve in Tailscale admin console (Machines → Edit route settings)")
$([ "${TAILSCALE_EXIT_NODE}" = "yes" ] && echo "  NAT/MASQ      POSTROUTING MASQUERADE active on WAN interface (persisted via systemd)")
$([ "${SSH_VIA_TAILSCALE}" = "yes" ] && echo "  SSH access    Tailscale-only (tailscale0) — public SSH is BLOCKED by UFW")
$([ "${SSH_VIA_TAILSCALE}" != "yes" ] && echo "  SSH access    Public internet (rate-limited)")
  Auto-updates  Security + stable (Docker excluded — update manually)
  Blocked pkgs  iptables-persistent, netfilter-persistent (apt pin -1)

SSH ACCESS:
$(if [ "${SSH_VIA_TAILSCALE}" = "yes" ]; then
  TS_IP="$(tailscale ip -4 2>/dev/null || true)"
  echo "  SSH is restricted to the Tailscale network."
  if [ -n "${TS_IP}" ]; then
    echo "  Connect: ssh <user>@${TS_IP} -p ${SSH_PORT}"
  else
    echo "  1. Run: tailscale up"
    echo "  2. Get your Tailscale IP: tailscale ip -4"
    echo "  3. Connect: ssh <user>@<tailscale-ip> -p ${SSH_PORT}"
    echo "  WARNING: public SSH is blocked. Verify access before closing this session!"
  fi
else
  echo "  ssh <user>@${SERVER_IP} -p ${SSH_PORT}"
fi)

ARCANE ACCESS (Tailscale-only via Traefik):
  Router carries tailscale-only@file middleware (sourceRange 100.64.0.0/10 +
  fd7a:115c:a1e0::/48). Public clients receive HTTP 403.
    arcane: https://arcane.YOURDOMAIN  (default login arcane / arcane-admin)

  Fallback (no DNS yet): SSH tunnel
    ssh -L 3552:localhost:3552 <user>@${SERVER_IP}
    Open: http://localhost:3552

  Code Server / further internal tools: deploy as additional stacks via Arcane.
  Apply Tailscale gate by adding this label to any router:
    - "traefik.http.routers.<name>.middlewares=tailscale-only@file"

DEPLOY ORDER:
  1. cd ${MGMT_DIR}/socket-proxy && docker compose up -d
     (creates networks: socket-proxy-traefik, socket-proxy-mgmt)

  2. Edit ${MGMT_DIR}/traefik/docker-compose.yml — set TRAEFIK_ACME_EMAIL + YOURDOMAIN
     cd ${MGMT_DIR}/traefik && docker compose up -d
     (creates network: traefik-public; loads dynamic config from /dynamic)

  3. Edit ${MGMT_DIR}/arcane/docker-compose.yml — set YOURDOMAIN
     cd ${MGMT_DIR}/arcane && docker compose up -d

  4. For each app stack: attach app to traefik-public + a private backend network;
     attach db ONLY to the private backend network. See example-app-stack.yml.

ADDING SHARED MIDDLEWARES:
  Edit ${MGMT_DIR}/traefik/dynamic/middlewares.yml — Traefik watches the file
  and reloads automatically (no restart needed). Reference from any router as
  <name>@file in compose labels.

KEY RULES:
  • Traefik ports MUST be "0.0.0.0:80:80" / "0.0.0.0:443:443" (daemon defaults to 127.0.0.1)
  • Never mount /var/run/docker.sock anywhere except into socket-proxy-* / autoheal
  • Traefik talks to socket-proxy-traefik (read-only API only — no POST/EXEC/BUILD)
  • Arcane talks to socket-proxy-mgmt (full API) but is Tailscale-gated at Traefik
  • DB containers: backend network only — never traefik-public, never a published port
  • Network isolation is enforced by attaching each container only to the networks it needs

DOCKER UPDATES:
  Docker CE is excluded from unattended-upgrades to prevent iptables corruption.
  Update manually when ready:
    apt update && apt upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin
    systemctl restart docker

NEXT STEPS:
  1. Verify your SSH public key is in authorized_keys — test login NOW.
     If locked out: Hetzner Cloud VNC console → rescue system.
  2. PermitRootLogin=no — connect as a regular user with sudo.
  3. AllowTcpForwarding=local in ${SSHD_DROPIN} — required for Arcane SSH tunnel.
     Set to 'no' if you don't need it.
$(
  if [ "${INSTALL_TAILSCALE}" = "yes" ] && [ -z "${TAILSCALE_AUTH_KEY}" ]; then
    echo "  4. Run 'tailscale up$([ "${TAILSCALE_EXIT_NODE}" = "yes" ] && echo " --advertise-exit-node")' to authenticate and join your tailnet."
    [ "${SSH_VIA_TAILSCALE}" = "yes" ] && \
      echo "     CRITICAL: Until tailscale up succeeds, the only fallback is the Hetzner VNC console."
  fi
)
$(
  if [ "${TAILSCALE_EXIT_NODE}" = "yes" ] && [ -n "${TAILSCALE_AUTH_KEY}" ]; then
    echo "  4. Approve exit node in Tailscale admin console: Machines → Edit route settings → Allow as exit node."
  elif [ "${TAILSCALE_EXIT_NODE}" = "yes" ]; then
    echo "     Then approve the exit node in Tailscale admin console: Machines → Edit route settings → Allow as exit node."
  fi
)

  Test: docker run hello-world
========================================
EOF