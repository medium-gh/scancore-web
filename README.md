# scancore-web

A small sync server for [SCANCORE](https://github.com/medium-gh/scancore):
accounts and device sync on your own computer, NAS or server, instead of
scancore.onl. Every SCANCORE app signed in to the same account keeps the same
library, reading and watching progress, removals and activity. The people
on your server can also be friends (and see what each other read, if they
choose to share it), share lists by link, react to comic pages and watch
anime together in watch parties.

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
| `ATTEMPT_LIMIT` | `10` | Sign-in and sign-up attempts per address in 15 minutes. |

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

- `GET /api/capabilities` → `{appSync: {devices: true, devicesOnly: true, live: true},
  party: true, friends: true, lists: true, reactions: true}`
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
- Watch parties: `POST /api/app/party` → `{code}` (six letters and digits);
  `GET /api/app/party/<code>` is the party's stream of server-sent events
  (`hello` `{you, host}`, then `state` `{state: {anime, episode, playing,
  position, age}}`, `members`, `chat` and `ended`); `POST
  /api/app/party/<code>` `{type: "state", state}` (the host),
  `{type: "chat", text}` or `{type: "end"}` (the host). Nothing is stored;
  a party ends when its host leaves or after six hours.
- Friends: `GET /api/app/friends` → `{shareActivity, friends, sent,
  received}` (people as `{id, username}`); `POST` `{username}` follows
  someone (following each other makes friends); `PATCH`
  `{shareActivity}`; `DELETE ?user=<id>` stops following.
- `GET /api/app/activity?before=<ISO date>` → `{events: [{user, type
  ("read", "watched", "shared"), payload {media, title, unit, cover,
  sourceUrl}, at}]}`: what friends who share it read lately, taken from
  their devices' snapshots (one line per series an hour).
- Shared lists: `POST /api/app/lists` `{title, items: [{title, media,
  source, sourceUrl, cover, anilistId}]}` → `{code}`; `GET
  /api/app/lists/<code>` (anyone) and the page `/lists/<code>`; `GET
  /api/app/lists` (mine), `DELETE /api/app/lists?code=<code>`.
- Reactions on a comic's pages: `GET /api/app/reactions?thread=<thread>`
  → `{pages: [{page, total, counts}], mine}`; `POST {thread, page,
  type}` (`LIKE`, `LOVE`, `LAUGH`, `WOW`, `SAD`, `ANGRY`, or `null` to
  take it back). A thread is `c:<series title>|<chapter number>`.

## Licence

MIT. Copyright 2026 Medium Dev.
