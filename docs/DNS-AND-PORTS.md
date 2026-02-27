# DNS and ports

Use this checklist so all services are reachable. Replace `example.com` with your actual domain.

## DNS records (A or AAAA)

Point these hostnames at your server’s public IP:

| Hostname | Purpose |
|----------|---------|
| `example.com` | Bare domain (optional; used with `www`) |
| `www.example.com` | Landing page + Matrix well-known |
| `auth.example.com` | Authentik (SSO) |
| `mail.example.com` | Stalwart mail web UI |
| `matrix.example.com` | Matrix Synapse |
| `element.example.com` | Element Web client |
| `cloud.example.com` | Nextcloud |
| `logs.example.com` | Dozzle (Docker logs) |
| `admin.example.com` | Admin panel |
| `meet.example.com` | Jitsi Meet |
| `turn.example.com` | TURN server (Jitsi/coturn) |
| `vaultwarden.example.com` | Vaultwarden (passwords) |
| `immich.example.com` | Immich (photos/videos) |

## Ports

### Open on host / firewall

| Port | Protocol | Service |
|------|----------|---------|
| 80 | TCP | HTTP (Caddy; redirect to HTTPS) |
| 443 | TCP | HTTPS (Caddy; all web apps) |
| 25 | TCP | SMTP (Stalwart) |
| 465 | TCP | SMTPS (Stalwart) |
| 993 | TCP | IMAPS (Stalwart) |
| 3478 | TCP, UDP | TURN (coturn) |
| 5349 | TCP, UDP | TURNS (coturn) |
| 10000 | UDP | Jitsi JVB (video bridge) |

`01-server-installation.sh` configures UFW to allow these. If you use another firewall or a cloud security group, open the same ports.

### Not exposed (internal only)

Postgres, Redis, Authentik internal, Synapse, Nextcloud, etc. are only reachable inside Docker networks. Do **not** expose 5432, 6379, or 9000 to the internet.

## After DNS changes

- Wait for TTL to expire or use low TTL when preparing.
- Reload Caddy is not required for DNS; Caddy uses the hostname at request time.
- For new hostnames (e.g. after adding a service), ensure the A record exists before first HTTPS request so Let’s Encrypt can issue the certificate.
