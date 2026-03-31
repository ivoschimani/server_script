# server.sh

Bootstrap script for a hardened Debian 13 (Trixie) server on Hetzner Cloud. Sets up Docker CE, Traefik, Arcane, UFW, fail2ban, SSH hardening, and optionally Tailscale — ready to deploy containerised apps.

## What it does

- **System**: Updates packages, installs base utilities, enables QEMU guest agent
- **Kernel hardening**: sysctl rules (SYN cookies, rp_filter, redirect/spoofing protection, etc.)
- **Docker CE**: Installs from the official Docker repo (GPG fingerprint verified), configures daemon with `ip=127.0.0.1` and `no-new-privileges`
- **iptables**: Hardens the `DOCKER-USER` chain to block unsolicited inbound traffic; persists rules via a systemd service (avoids `iptables-persistent` which conflicts with `ufw` on Debian 13)
- **Docker networks**: Creates `traefik-public` and `socket-proxy` networks
- **Compose templates**: Writes ready-to-use compose files for socket-proxy, Traefik v3, and Arcane (with secrets pre-generated) to `~/management/`
- **UFW**: Denies all inbound by default; opens HTTP/HTTPS and rate-limits SSH
- **fail2ban**: Configured for SSH via systemd journal backend
- **SSH hardening**: Drop-in config disabling password auth, root login, X11, agent forwarding
- **Unattended upgrades**: Auto-applies Debian security + stable + Docker updates; auto-reboots at 03:00 if needed
- **Tailscale** *(optional)*: Installs, authenticates, and optionally advertises as an exit node

## Requirements

- Debian 13 Trixie
- Run as root (`sudo ./server.sh`)
- SSH public key already in `~/.ssh/authorized_keys` before running

## Usage

```bash
sudo ./server.sh
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ALLOW_HTTP` | `yes` | Open port 80 in UFW and DOCKER-USER |
| `ALLOW_HTTPS` | `yes` | Open port 443 in UFW and DOCKER-USER |
| `SSH_PORT` | `22` | SSH port for UFW and fail2ban |
| `INSTALL_TAILSCALE` | `no` | Install and enable Tailscale |
| `TAILSCALE_AUTH_KEY` | *(unset)* | Auth key for automatic Tailscale authentication. Generate at [login.tailscale.com/admin/settings/keys](https://login.tailscale.com/admin/settings/keys). Ephemeral keys recommended for servers. |
| `SSH_VIA_TAILSCALE` | `no` | Restrict SSH to the `tailscale0` interface only — blocks public SSH. Requires `INSTALL_TAILSCALE=yes`. |
| `TAILSCALE_EXIT_NODE` | `no` | Advertise this server as a Tailscale exit node. Requires `INSTALL_TAILSCALE=yes`. Must be approved in the Tailscale admin console after joining. |

### Examples

Minimal (HTTP + HTTPS + public SSH):
```bash
sudo ./server.sh
```

With Tailscale, SSH restricted to tailnet:
```bash
sudo INSTALL_TAILSCALE=yes \
     TAILSCALE_AUTH_KEY=tskey-auth-... \
     SSH_VIA_TAILSCALE=yes \
     ./server.sh
```

With Tailscale exit node:
```bash
sudo INSTALL_TAILSCALE=yes \
     TAILSCALE_AUTH_KEY=tskey-auth-... \
     TAILSCALE_EXIT_NODE=yes \
     ./server.sh
```

## After running

Compose files are written to `~/management/`. Deploy in this order:

```bash
# 1. Socket proxy (must be first)
cd ~/management/socket-proxy && docker compose up -d

# 2. Traefik — edit first: set TRAEFIK_ACME_EMAIL, YOURDOMAIN, and generate a dashboard password
#    docker run --rm httpd:2.4-alpine htpasswd -nbB admin yourpassword | sed -e 's/\$/\$\$/g'
cd ~/management/traefik && docker compose up -d

# 3. Arcane — edit first: set YOURDOMAIN in APP_URL and the Traefik label
cd ~/management/arcane && docker compose up -d
```

**Arcane** is not publicly exposed. Access it via SSH tunnel:
```bash
ssh -L 3552:localhost:3552 user@YOUR_SERVER_IP
# Open: http://localhost:3552
# Default login: arcane / arcane-admin  ← change immediately
```

## Key rules for app stacks

- Traefik ports **must** be `"0.0.0.0:80:80"` / `"0.0.0.0:443:443"` — the Docker daemon defaults to `127.0.0.1`
- **Never** mount `/var/run/docker.sock` directly into Traefik or Arcane — only into the socket proxy
- Database containers: attach to a private backend network only — never to `traefik-public`, never with a published port
- See `~/management/traefik/example-app-stack.yml` for a wiring reference

## SSH access

| Mode | How to connect |
|---|---|
| Default (public) | `ssh user@SERVER_IP -p SSH_PORT` |
| `SSH_VIA_TAILSCALE=yes` | `ssh user@TAILSCALE_IP -p SSH_PORT` |

> **Warning**: With `SSH_VIA_TAILSCALE=yes`, public SSH is blocked immediately. Do not close your session until Tailscale is authenticated and you have verified access via the Tailscale IP. The Hetzner VNC console is your fallback if locked out.
