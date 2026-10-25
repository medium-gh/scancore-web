<div align="center">

<img src="https://raw.githubusercontent.com/medium-gh/scancore/main/resources/branding/scancore.svg" width="96" alt="SCANCORE">

# scancore-web

### Your own server for SCANCORE
Sync, friends and watch parties on your own computer, NAS or server, instead of scancore.onl.

[![Discord](https://img.shields.io/badge/discord-join-5865F2?logo=discord&logoColor=white&labelColor=27303D)](https://scancore.onl/discord)
[![Image](https://img.shields.io/badge/image-ghcr.io-0D1117?logo=docker&logoColor=white&labelColor=27303D)](https://github.com/medium-gh/scancore-web/pkgs/container/scancore-web)
[![Build](https://img.shields.io/github/actions/workflow/status/medium-gh/scancore-web/docker.yml?branch=main&label=build&labelColor=27303D)](https://github.com/medium-gh/scancore-web/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-0877d2?labelColor=27303D)](LICENSE)

**One file · no dependencies · Docker on amd64 and arm64 · Node 22.13+**

</div>

## What it does

Every [SCANCORE](https://github.com/medium-gh/scancore) app signed in to the same account on your server keeps:

* **The same library**, with reading and watching progress, removals and activity, on every device.
* **Live progress**: a chapter you leave on your phone opens where you stopped on your computer.
* **Friends**: follow each other to see what you read and watch, but only if each of you chooses to share it.
* **Shared lists** that anyone with the link can open and add to their library.
* **Reactions** on a comic's pages.
* **Watch parties**: anime played together, steered by the host, with chat.
* **Where the anime leaves off**: which chapter or volume to read after a season. It starts with the same list of over 200 as scancore.onl, and your users can suggest and vote on more.

All of it is `server.mjs`, plus that list in `story-seeds.json`. It uses Node's own HTTP server, SQLite and scrypt. Each app stores one snapshot of itself here and merges the others' itself, so the server only keeps them.

## Quick start

```sh
docker run -d --name scancore-sync --restart unless-stopped \
  -p 8787:8787 -v scancore-data:/data ghcr.io/medium-gh/scancore-web:latest
```

Then in SCANCORE:

1. Open **Settings → Sync → Your server**.
2. Enter `http://<this computer's address>:8787`, for example `http://192.168.1.20:8787`.
3. Choose **Use this website** and create an account.
4. Sign in with the same account on your other devices.

Once everyone has an account, set `ALLOW_SIGNUP=false` so nobody else can make one.

<details>
<summary><b>Over the internet, with HTTPS</b></summary>
<br>

You need a domain pointing at the server, and ports 80 and 443 open.

```sh
git clone https://github.com/medium-gh/scancore-web.git
cd scancore-web
cp .env.example .env      # set SCANCORE_DOMAIN, and TRUST_PROXY=true
docker compose --profile https up -d
```

Caddy gets a certificate for your domain, and the app uses `https://<your domain>`. Without the profile (`docker compose up -d`), only the plain server on port 8787 runs.

</details>

<details>
<summary><b>Without Docker</b></summary>
<br>

With Node 22.13 or later:

```sh
git clone https://github.com/medium-gh/scancore-web.git
cd scancore-web
npm start
```

</details>

## Settings

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8787` | Port to listen on. |
| `HOST` | `0.0.0.0` | Address to listen on. |
| `DATA_DIR` | `./data` (`/data` in Docker) | Where the database lives. |
| `ALLOW_SIGNUP` | `true` | `false` once your accounts exist. |
| `TRUST_PROXY` | `false` | `true` behind Caddy, nginx or another proxy, so its forwarded address and HTTPS headers are used. |
| `MAX_DEVICES` | `20` | Devices per account. |
| `MAX_SNAPSHOT_MB` | `16` | Largest snapshot a device may store. |
| `ATTEMPT_LIMIT` | `10` | Sign-in and sign-up attempts per address in 15 minutes. |

## Looking after it

* **Backups:** everything is in `scancore-sync.db` in the data folder (the `scancore-data` volume in Docker). Copy it while the server is stopped, or run `sqlite3 scancore-sync.db ".backup backup.db"` while it runs.
* **Forgotten password:** `docker exec scancore-sync node server.mjs passwd <username> <new password>` (`node server.mjs passwd …` without Docker). The account's devices then sign in again with the new password.
* **Remove an account:** `node server.mjs delete <username>`.
* **Update:** `docker pull ghcr.io/medium-gh/scancore-web:latest` and recreate the container, or `git pull` and restart.

## Security

* Passwords are stored as scrypt hashes. Sessions are random tokens in an HttpOnly cookie, stored hashed.
* Plain `http://` is fine on a home network you trust. Over the internet, use HTTPS: without it, passwords and your library travel unencrypted.
* Sign-in and sign-up are limited to 10 attempts per 15 minutes per address.

<details>
<summary><b>API</b>, for anyone writing their own client</summary>
<br>

**Server and accounts**

* `GET /api/capabilities` → `{server: "scancore-web", version, signup, appSync: {devices, devicesOnly, live}, party, friends, lists, reactions, story}`
* `POST /api/auth/signup` `{email, username, password}`
* `POST /api/auth/login` `{email (or username), password}`
* `POST /api/auth/logout`
* `GET /api/auth/session` → `{user | null}`

**Sync**

* `GET /api/app/devices?since=<ms>` → `{devices: [{deviceId, name, platform, updatedAt, data}]}`
* `PUT /api/app/devices/<deviceId>` `{name, platform, data}` → `{updatedAt}`
* `DELETE /api/app/devices/<deviceId>`
* `GET /api/app/live?device=<id>&name=<name>&platform=<platform>`: server-sent events while the app is open. `presence` `{device, online}` for the account's other open apps, and `progress` or `handoff` `{from, data}` as they send them. The stream ends after 15 minutes and the app reconnects.
* `POST /api/app/live` `{from: {id, name, platform}, type: "progress" | "handoff", to?, data}` passes `data` to the account's other open apps (or only to `to`). Nothing is stored.

**Watch parties**

* `POST /api/app/party` → `{code}` (six letters and digits)
* `GET /api/app/party/<code>`: the party's server-sent events: `hello` `{you, host}`, then `state` `{state: {anime, episode, playing, position, age}}`, `members`, `chat` and `ended`.
* `POST /api/app/party/<code>` `{type: "state", state}` (host), `{type: "chat", text}`, or `{type: "end"}` (host).
* Nothing is stored. A party ends when its host leaves, or after six hours.

**Friends and activity**

* `GET /api/app/friends` → `{shareActivity, friends, sent, received}`, people as `{id, username}`
* `POST /api/app/friends` `{username}` follows someone; following each other makes friends.
* `PATCH /api/app/friends` `{shareActivity}`
* `DELETE /api/app/friends?user=<id>` stops following.
* `GET /api/app/activity?before=<ISO date>` → `{events: [{user, type ("read", "watched", "shared"), payload {media, title, unit, cover, sourceUrl}, at}]}`: what friends who share it read lately, from their devices' snapshots (one line per series an hour).

**Shared lists**

* `POST /api/app/lists` `{title, items: [{title, media, source, sourceUrl, cover, anilistId}]}` → `{code}`
* `GET /api/app/lists/<code>` (anyone), and the page `/lists/<code>`
* `GET /api/app/lists` (mine), `DELETE /api/app/lists?code=<code>`

**Reactions**

* `GET /api/app/reactions?thread=<thread>` → `{pages: [{page, total, counts}], mine}`
* `POST /api/app/reactions` `{thread, page, type}`: `LIKE`, `LOVE`, `LAUGH`, `WOW`, `SAD`, `ANGRY`, or `null` to take it back.
* A thread is `c:<series title>|<chapter number>`.

**Where an anime leaves off**

* `GET /api/story?anime=<AniList ids>` (anyone) → `{points: {"<id>": [{id, media ("comic" or "novel"), sourceId, chapter, volume, score, seeded, mine, submitted}]}}`, best first: the chapter or volume to go on from after that season.
* `POST /api/story` `{animeId, media, sourceId?, chapter | volume}` suggests one; the same one again counts as a vote for it.
* `POST /api/story/vote` `{id, value}`: `1`, `-1`, or `0` to take it back.

</details>

## Questions and help

[Discord](https://scancore.onl/discord) for questions and chat · [Issues](https://github.com/medium-gh/scancore-web/issues) for bugs and ideas · [SCANCORE](https://github.com/medium-gh/scancore) for the app

### License

MIT. Copyright 2026 Medium Dev.
