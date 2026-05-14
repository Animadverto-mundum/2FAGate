# 2FAGate — TOTP 2FA for any Caddy site

A ~15MB Docker image that adds TOTP two-factor authentication to any Caddy reverse-proxied site via `forward_auth`.

## How it works

```
Browser → Caddy → forward_auth → CaddyGate(/auth)
                   ↓ 200               ↑ 302 redirect
               backend            /_auth/login ← user enters TOTP → sets cookie
```

1. User visits protected domain — Caddy calls `/auth` to check cookie
2. No cookie → 302 redirect to login page
3. User enters 6-digit TOTP code → cookie issued → redirected back
4. Subsequent requests with cookie pass through

## Quick start

### 1. Start

```bash
docker compose up -d
```

All keys auto-generated on first run. Zero manual config.

### 2. Scan QR

```bash
docker compose logs auth
```

ASCII QR code printed in terminal — scan with Google Authenticator, Authy, etc.

### 3. Add to Caddy

In `/etc/caddy/Caddyfile`:

```
your.domain.com {
    handle /_auth/* {
        uri strip_prefix /_auth
        reverse_proxy 127.0.0.1:18080
    }
    handle {
        forward_auth 127.0.0.1:18080 {
            uri /auth
        }
        reverse_proxy your-backend:port
    }
}
```

Reload:

```bash
systemctl reload caddy
```

### 4. Done

Visit `https://your.domain.com/` → login form → enter TOTP → in.

## Configuration

Set in `docker-compose.yml` `environment`:

| Variable | Description | Default |
|---|---|---|
| `TOTP_SKEW` | Tolerate ±N time periods (30s each) | `1` |
| `TOTP_ANTI_REPLAY` | Reject reused codes, `false` to disable | `true` |
| `COOKIE_MAX_AGE` | Cookie TTL in seconds, `0` = never expire | `2592000` (30d) |
| `ISSUER` | Name shown in authenticator app | host hostname |
| `LISTEN` | Listen address | `:8080` |

`COOKIE_SECRET` and `TOTP_SECRET` are auto-generated and stored inside `/data/`. Persist across `stop`/`start`/`restart`, cleared on `rm`.

## Key lifecycle

```
docker stop     → keys kept
docker start    → keys kept
docker restart  → keys kept
docker rm       → keys wiped
docker compose down → keys wiped
docker compose up -d → new keys generated
```

After `rm`, TOTP secret changes — rescan required.

## Use with existing backend

If your backend already runs (e.g. `localhost:3006`), just point Caddy's `reverse_proxy` to it. No other containers needed.
