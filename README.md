# scancore-web

A small sync server for [SCANCORE](https://github.com/medium-gh/scancore):
accounts and device sync on your own computer, NAS or server, instead of
scancore.onl. Every SCANCORE app signed in to the same account keeps the same
library, reading and watching progress, removals and activity.

It is one file (`server.mjs`) with no dependencies: Node's own HTTP server,
SQLite and scrypt. Each app keeps one snapshot of itself here and merges the
others' itself; the server only stores them.

## Run it

### Docker (simplest)

```sh
docker run -d --name scancore-sync --restart unless-stopped \
  -p 8787:8787 -v scancore-data:/data ghcr.io/medium-gh/scancore-web:latest
```

Then in SCANCORE: Settings → Sync → **Your server**, enter
`http://<this computer's address>:8787` (for example
`http://192.168.1.20:8787`), choose **Use this website** and create an
account. Sign in with the same account on your other devices.

### With HTTPS, for use over the internet

You need a domain pointing at the server and ports 80 and 443 open.

```sh
git clone https://github.com/medium-gh/scancore-web.git
cd scancore-web
cp .env.example .env      # set SCANCORE_DOMAIN, and TRUST_PROXY=true
docker compose --profile https up -d
```

Caddy gets a certificate for your domain; use `https://<your domain>` in the
app. Without the profile (`docker compose up -d`), only the plain server on
port 8787 runs.

### Without Docker

Node 22.13 or later:

```sh
git clone https://github.com/medium-gh/scancore-web.git
cd scancore-web
npm start
```

## Settings

Environment variables:

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8787` | Port to listen on. |
| `HOST` | `0.0.0.0` | Address to listen on. |
| `DATA_DIR` | `./data` (`/data` in Docker) | Where the database lives. |
| `ALLOW_SIGNUP` | `true` | Set to `false` once your accounts exist, so nobody else can make one. |
| `TRUST_PROXY` | `false` | `true` behind Caddy, nginx or another proxy (uses its forwarded address and HTTPS headers). |
| `MAX_DEVICES` | `20` | Devices per account. |
| `MAX_SNAPSHOT_MB` | `16` | Largest snapshot a device may store. |

## Looking after it

- **Backups:** everything is in `scancore-sync.db` in the data folder (the
  `scancore-data` volume in Docker). Copy it while the server is stopped, or
  use `sqlite3 scancore-sync.db ".backup backup.db"` while it runs.
- **Forgotten password:**
  `docker exec scancore-sync node server.mjs passwd <username> <new password>`
  (or `node server.mjs passwd …` without Docker). The account's devices sign
  in again with the new password.
- **Remove an account:** `node server.mjs delete <username>`.
- **Update:** `docker pull ghcr.io/medium-gh/scancore-web:latest` and
  recreate the container (or `git pull` and restart).

## Security notes

- Passwords are stored as scrypt hashes; sessions are random tokens in an
  HttpOnly cookie, stored hashed.
- Plain `http://` is fine on a home network you trust. Over the internet,
  use the HTTPS setup: without it, passwords and your library travel
  unencrypted.
- Sign-in and sign-up are limited to 10 attempts per 15 minutes per address.

## API

What the app uses, for anyone writing their own client:

- `GET /api/capabilities` → `{appSync: {devices: true, devicesOnly: true, live: true}}`
- `POST /api/auth/signup` `{email, username, password}`,
  `POST /api/auth/login` `{email (or username), password}`,
  `POST /api/auth/logout`, `GET /api/auth/session` → `{user | null}`
- `GET /api/app/devices?since=<ms>` →
  `{devices: [{deviceId, name, platform, updatedAt, data}]}`
- `PUT /api/app/devices/<deviceId>` `{name, platform, data}` → `{updatedAt}`
- `DELETE /api/app/devices/<deviceId>`
- `GET /api/app/live?device=<id>&name=<name>&platform=<platform>`: a
  stream of server-sent events while the app is open: `presence`
  `{device, online}` for the account's other open apps, and `progress` or
  `handoff` `{from, data}` as they send them. It ends after 15 minutes;
  the app reconnects.
- `POST /api/app/live` `{from: {id, name, platform}, type: "progress" |
  "handoff", to?, data}` passes `data` on to the account's other open apps
  (or only to `to`). Nothing is stored.

## Licence

MIT. Copyright 2026 Medium Dev.
