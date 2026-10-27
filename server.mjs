#!/usr/bin/env node
// SCANCORE sync server: accounts and device sync for the SCANCORE app, on
// your own machine. Each app install keeps one snapshot here (its library,
// removals, reading and watching progress, and activity) and reads the
// others'; the app merges them itself, so the server only stores them.
// Also: live progress between an account's apps, watch parties, friends
// (and what they read), lists shared by link, reactions on pages, and where
// each anime leaves off in its comic or novel.
//
// No dependencies: Node's own HTTP server, SQLite and scrypt.
//
//   node server.mjs                      start (see README.md for settings)
//   node server.mjs passwd <user> <new>  set an account's password
//   node server.mjs delete <user>        delete an account and its devices

import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { createHash, randomBytes, randomInt, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";

const VERSION = "1.2.0";
const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "0.0.0.0";
const DATA_DIR = process.env.DATA_DIR ?? join(process.cwd(), "data");
// New accounts; turn off once yours exist.
const ALLOW_SIGNUP = (process.env.ALLOW_SIGNUP ?? "true") !== "false";
// Behind a reverse proxy (Caddy, nginx): trust its X-Forwarded-* headers.
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const MAX_DEVICES = Number(process.env.MAX_DEVICES ?? 20);
const MAX_SNAPSHOT = Number(process.env.MAX_SNAPSHOT_MB ?? 16) * 1024 * 1024;
// Sign-in and sign-up attempts per address in 15 minutes.
const ATTEMPT_LIMIT = Number(process.env.ATTEMPT_LIMIT ?? 10);
const SESSION_DAYS = 90;
const COOKIE = "scancore-sync";

const hashPassword = promisify(scrypt);

// ------------------------------------------------------------------ storage

mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(join(DATA_DIR, "scancore-sync.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS devices (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id)
  );
  -- Friends: following each other.
  CREATE TABLE IF NOT EXISTS follows (
    follower INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (follower, following)
  );
  CREATE INDEX IF NOT EXISTS follows_following ON follows(following);
  -- What readers who share it read and watched lately (friends see it).
  CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS activity_user ON activity(user_id, created_at);
  -- Lists shared by a code anyone can open.
  CREATE TABLE IF NOT EXISTS shared_lists (
    code TEXT PRIMARY KEY,
    owner INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    items TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  -- Reactions on a chapter's pages: one per reader and page.
  CREATE TABLE IF NOT EXISTS page_reactions (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    thread TEXT NOT NULL,
    page INTEGER NOT NULL,
    type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, thread, page)
  );
  CREATE INDEX IF NOT EXISTS page_reactions_thread ON page_reactions(thread);
  -- Where an anime season leaves off in its comic or novel: the chapter or
  -- volume to go on from, voted on by readers (story-seeds.json starts it).
  CREATE TABLE IF NOT EXISTS story_points (
    id TEXT PRIMARY KEY,
    anime_id INTEGER NOT NULL,
    media TEXT NOT NULL,
    source_id INTEGER,
    chapter REAL,
    volume INTEGER,
    seeded INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS story_points_anime ON story_points(anime_id);
  CREATE TABLE IF NOT EXISTS story_votes (
    point_id TEXT NOT NULL REFERENCES story_points(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    value INTEGER NOT NULL,
    PRIMARY KEY (point_id, user_id)
  );
`);
// Whether a reader shares what they read with friends (off until they say).
if (!db.prepare("SELECT 1 FROM pragma_table_info('users') WHERE name = 'share_activity'").get())
  db.exec("ALTER TABLE users ADD COLUMN share_activity INTEGER NOT NULL DEFAULT 0");

// The same checked points as scancore.onl's, for anime nobody here has
// given one yet ([animeId, media, sourceId, chapter, volume]).
{
  const seeds = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "story-seeds.json"), "utf8"));
  const has = db.prepare("SELECT 1 FROM story_points WHERE anime_id = ? AND media = ?");
  const add = db.prepare(
    "INSERT INTO story_points(id, anime_id, media, source_id, chapter, volume, seeded, score, created_at) VALUES(?, ?, ?, ?, ?, ?, 1, 1, ?)",
  );
  for (const [animeId, media, sourceId, chapter, volume] of seeds.points)
    if (!has.get(animeId, media)) add.run(randomUUID(), animeId, media, sourceId, chapter, volume, Date.now());
}

const now = () => Date.now();
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

async function makePassword(password) {
  const salt = randomBytes(16);
  const key = await hashPassword(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("base64")}$${key.toString("base64")}`;
}

async function checkPassword(password, stored) {
  const [kind, salt, key] = stored.split("$");
  if (kind !== "scrypt") return false;
  const expected = Buffer.from(key, "base64");
  const actual = await hashPassword(password, Buffer.from(salt, "base64"), expected.length, { N: 16384, r: 8, p: 1 });
  return timingSafeEqual(actual, expected);
}

// Passwords from known data breaches are refused, as on scancore.onl.
// Pwned Passwords is asked with the first five characters of the SHA-1 only
// (k-anonymity, padded replies), so neither the password nor its hash
// leaves this server. Down or slower than 5 s: the check is skipped, never locking
// anyone out. PASSWORD_BREACH_CHECK=false turns it off (no internet).
const BREACH_CHECK = process.env.PASSWORD_BREACH_CHECK !== "false";
async function breachCount(password) {
  if (!BREACH_CHECK) return null;
  const digest = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`, {
      headers: { "Add-Padding": "true", "User-Agent": `scancore-web/${VERSION}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return null;
    for (const line of (await response.text()).split("\n")) {
      const [hash, count] = line.trim().split(":");
      if (hash === digest.slice(5)) return Number(count) || 0;
    }
    return 0;
  } catch {
    return null;
  }
}

// What is wrong with a password beyond the rules: built from the account's
// own name or address, or seen in a breach. Empty when it is fine.
async function unsafePassword(password, { username, email } = {}) {
  const lowered = String(password).toLowerCase();
  const own = [username, String(email ?? "").split("@")[0]]
    .map((part) => String(part ?? "").trim().toLowerCase())
    .filter((part) => part.length >= 4);
  if (own.some((part) => lowered.includes(part))) return "Your password can't contain your username or email.";
  if ((await breachCount(password)) > 0)
    return "This password has appeared in a data breach, so it's easy to guess. Choose a different one.";
  return "";
}

// ------------------------------------------------------------------ commands

const [command, ...args] = process.argv.slice(2);
if (command === "passwd" || command === "delete") {
  const user = db.prepare("SELECT id FROM users WHERE username = ? OR email = ?").get(args[0] ?? "", args[0] ?? "");
  if (!user) {
    console.error(`No account named ${args[0] ?? "(none given)"}.`);
    process.exit(1);
  }
  if (command === "delete") {
    db.prepare("DELETE FROM users WHERE id = ?").run(user.id);
    console.log("Deleted.");
  } else {
    const account = db.prepare("SELECT username, email FROM users WHERE id = ?").get(user.id);
    const problem = passwordProblem(args[1] ?? "") || (await unsafePassword(args[1], account));
    if (problem) {
      console.error(problem);
      process.exit(1);
    }
    db.prepare("UPDATE users SET password = ? WHERE id = ?").run(await makePassword(args[1]), user.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(user.id);
    console.log("Password changed; its devices sign in again.");
  }
  process.exit(0);
} else if (command) {
  console.error(`Unknown command ${command}. Use passwd <user> <password> or delete <user>.`);
  process.exit(1);
}

// ------------------------------------------------------------------ helpers

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// The same rules the app shows when creating an account.
function passwordProblem(password) {
  if (typeof password !== "string" || password.length < 8 || password.length > 128) return "At least 8 characters";
  if (!/[a-z]/.test(password)) return "A lowercase letter";
  if (!/[A-Z]/.test(password)) return "An uppercase letter";
  if (!/\d/.test(password)) return "A number";
  if (!/[^A-Za-z0-9]/.test(password)) return "A symbol";
  return null;
}

function clientAddress(request) {
  if (TRUST_PROXY) {
    const forwarded = request.headers["x-forwarded-for"];
    if (forwarded) return String(forwarded).split(",")[0].trim();
  }
  return request.socket.remoteAddress ?? "";
}

function isHttps(request) {
  return request.socket.encrypted || (TRUST_PROXY && request.headers["x-forwarded-proto"] === "https");
}

// Sign-in and sign-up attempts: ATTEMPT_LIMIT per 15 minutes per address.
const attempts = new Map();
function limitAttempts(request) {
  const key = clientAddress(request);
  const window = 15 * 60 * 1000;
  const list = (attempts.get(key) ?? []).filter((at) => now() - at < window);
  if (list.length >= ATTEMPT_LIMIT) throw new HttpError(429, "Too many attempts. Wait a few minutes and try again.");
  list.push(now());
  attempts.set(key, list);
}
setInterval(() => {
  for (const [key, list] of attempts) if (list.every((at) => now() - at > 15 * 60 * 1000)) attempts.delete(key);
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now());
}, 10 * 60 * 1000).unref();

async function readJson(request, limit) {
  if (!String(request.headers["content-type"] ?? "").toLowerCase().startsWith("application/json"))
    throw new HttpError(415, "JSON is required.");
  if (Number(request.headers["content-length"] ?? 0) > limit) throw new HttpError(413, "Request is too large.");
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, "Request is too large.");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new HttpError(400, "That is not valid JSON.");
  }
}

function cookieToken(request) {
  for (const part of String(request.headers.cookie ?? "").split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name === COOKIE) return value.join("=");
  }
  return null;
}

function currentUser(request) {
  const token = cookieToken(request);
  if (!token) return null;
  return (
    db
      .prepare(
        "SELECT users.id, users.email, users.username FROM sessions JOIN users ON users.id = sessions.user_id " +
          "WHERE sessions.token = ? AND sessions.expires_at > ?",
      )
      .get(sha256(token), now()) ?? null
  );
}

function requireUser(request) {
  const user = currentUser(request);
  if (!user) throw new HttpError(401, "Sign in to continue.");
  return user;
}

function startSession(request, response, userId) {
  const token = randomBytes(32).toString("base64url");
  db.prepare("INSERT INTO sessions(token, user_id, expires_at) VALUES(?, ?, ?)").run(
    sha256(token),
    userId,
    now() + SESSION_DAYS * 86400_000,
  );
  response.setHeader(
    "Set-Cookie",
    `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}` +
      (isHttps(request) ? "; Secure" : ""),
  );
}

const publicUser = (user) => ({ username: user.username, email: user.email, avatarUrl: null });

function send(response, status, body) {
  const text = JSON.stringify(body);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(text),
  });
  response.end(text);
}

const page = (signup) => `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCANCORE sync server</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:36em;margin:4em auto;padding:0 1em;background:#0e0f12;color:#e8e8ec">
<h1 style="font-size:1.4em">SCANCORE sync server</h1>
<p>This server keeps SCANCORE apps in step: library, reading and watching progress, and activity.</p>
<p>In SCANCORE, open Settings → Sync → <b>Your server</b>, enter this page's address and ${
  signup ? "create an account or sign in" : "sign in"
}.</p>
<p style="color:#8a8a94">scancore-web ${VERSION} · <a style="color:#8a8a94" href="https://github.com/medium-gh/scancore-web">source</a></p>`;

// ------------------------------------------------------------------ live

// Live progress between an account's apps: each open app keeps a stream of
// server-sent events, and what one app sends (where it is in a chapter or
// episode, or "continue on that device") goes straight to the others.
// Nothing is stored; device snapshots still carry everything.
const LIVE_PING_MS = 25_000;
const LIVE_LIFETIME_MS = 15 * 60_000;
const LIVE_MAX_BYTES = 32_768;
const liveBus = new EventEmitter();
liveBus.setMaxListeners(0);

const liveDevice = (value) => {
  const id = String(value?.id ?? "");
  if (!/^[A-Za-z0-9-]{8,64}$/.test(id)) throw new HttpError(400, "Invalid device ID.");
  return { id, name: String(value?.name ?? "").trim().slice(0, 80) || "SCANCORE", platform: String(value?.platform ?? "").trim().slice(0, 20) };
};

function liveStream(request, response, user, self) {
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  const write = (event, data) => response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  const channel = `user:${user.id}`;
  const listener = (message) => {
    if (message.from.id === self.id || (message.to && message.to !== self.id)) return;
    if (message.type === "hello") {
      write("presence", { device: message.from, online: true });
      liveBus.emit(channel, { type: "here", from: self, to: message.from.id });
    } else if (message.type === "here") write("presence", { device: message.from, online: true });
    else if (message.type === "bye") write("presence", { device: message.from, online: false });
    else write(message.type, { from: message.from, data: message.data });
  };
  liveBus.on(channel, listener);
  const ping = setInterval(() => response.write(": ping\n\n"), LIVE_PING_MS);
  const end = setTimeout(() => response.end(), LIVE_LIFETIME_MS);
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    clearInterval(ping);
    clearTimeout(end);
    liveBus.off(channel, listener);
    liveBus.emit(channel, { type: "bye", from: self });
  };
  response.on("close", finish);
  response.write("retry: 15000\n\n");
  liveBus.emit(channel, { type: "hello", from: self });
}

// ------------------------------------------------------------------ friends

// Readers follow each other by username; both ways makes friends.
const person = (row) => ({ id: String(row.id), username: row.username, displayName: null, avatarUrl: null });

function friendsOf(userId) {
  const following = db.prepare("SELECT users.id, users.username FROM follows JOIN users ON users.id = follows.following WHERE follows.follower = ?").all(userId);
  const followers = db.prepare("SELECT users.id, users.username FROM follows JOIN users ON users.id = follows.follower WHERE follows.following = ?").all(userId);
  const back = new Set(followers.map((r) => r.id));
  const mine = new Set(following.map((r) => r.id));
  return {
    friends: following.filter((r) => back.has(r.id)).map(person),
    sent: following.filter((r) => !back.has(r.id)).map(person),
    received: followers.filter((r) => !mine.has(r.id)).map(person),
  };
}

const httpsUrl = (value) => (typeof value === "string" && /^https?:\/\//.test(value) ? value.slice(0, 1000) : undefined);

// One line per series an hour (a binge is its latest chapter), and only
// for readers who share.
function recordActivity(userId, type, item) {
  const title = String(item.title ?? "").slice(0, 200);
  if (!title) return;
  if (!db.prepare("SELECT share_activity FROM users WHERE id = ?").get(userId)?.share_activity) return;
  const payload = JSON.stringify({
    media: item.media,
    title,
    unit: item.unit ? String(item.unit).slice(0, 200) : undefined,
    cover: httpsUrl(item.cover),
    source: item.source ? String(item.source).slice(0, 100) : undefined,
    sourceUrl: httpsUrl(item.sourceUrl),
  });
  const recent = db.prepare("SELECT id FROM activity WHERE user_id = ? AND type = ? AND title = ? AND created_at > ?").get(userId, type, title, now() - 3600_000);
  if (recent) db.prepare("UPDATE activity SET payload = ?, created_at = ? WHERE id = ?").run(payload, now(), recent.id);
  else db.prepare("INSERT INTO activity(user_id, type, title, payload, created_at) VALUES(?, ?, ?, ?, ?)").run(userId, type, title, payload, now());
  db.prepare("DELETE FROM activity WHERE user_id = ? AND created_at < ?").run(userId, now() - 90 * 86400_000);
}

// The app syncs here through device snapshots: what it read in the last
// minutes becomes activity (seconds or milliseconds, as apps write them).
function activityFromSnapshot(userId, data) {
  const series = data?.series ?? {};
  const progress = data?.progress ?? {};
  const since = now() - 15 * 60_000;
  const recent = [];
  for (const [id, units] of Object.entries(progress)) {
    let latest = null;
    for (const unit of Object.values(units ?? {})) {
      if (!Array.isArray(unit)) continue;
      const raw = Number(unit[6]) || 0;
      const at = raw < 1e12 ? raw * 1000 : raw;
      if (at >= since && (!latest || at > latest.at)) latest = { at, title: unit[0], number: unit[1] };
    }
    if (latest && series[id]) recent.push({ ...latest, series: series[id] });
  }
  recent.sort((a, b) => b.at - a.at);
  for (const r of recent.slice(0, 3)) {
    const media = r.series.media === "anime" ? "anime" : r.series.media === "novel" ? "novel" : "comic";
    recordActivity(userId, media === "anime" ? "watched" : "read", {
      media,
      title: r.series.title,
      unit: r.title || (r.number ? (media === "anime" ? `Episode ${r.number}` : `Chapter ${r.number}`) : undefined),
      cover: r.series.cover,
      sourceUrl: r.series.sourceUrl,
    });
  }
}

const LIST_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const listCode = () => Array.from({ length: 10 }, () => LIST_ALPHABET[randomInt(LIST_ALPHABET.length)]).join("");

function cleanItem(raw) {
  if (!raw || typeof raw !== "object") return null;
  const title = typeof raw.title === "string" ? raw.title.trim().slice(0, 200) : "";
  if (!title) return null;
  return {
    title,
    media: raw.media === "novel" || raw.media === "anime" ? raw.media : "comic",
    source: typeof raw.source === "string" ? raw.source.slice(0, 100) : undefined,
    sourceUrl: httpsUrl(raw.sourceUrl),
    cover: httpsUrl(raw.cover),
    anilistId: Number.isInteger(raw.anilistId) && raw.anilistId > 0 ? raw.anilistId : undefined,
  };
}

function sharedList(code) {
  if (!/^[a-z0-9]{6,20}$/.test(code)) return null;
  const row = db.prepare("SELECT shared_lists.*, users.username FROM shared_lists JOIN users ON users.id = shared_lists.owner WHERE code = ?").get(code);
  if (!row) return null;
  return {
    code: row.code,
    title: row.title,
    owner: { id: String(row.owner), username: row.username, displayName: null, avatarUrl: null },
    items: JSON.parse(row.items),
    at: new Date(row.created_at).toISOString(),
  };
}

const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const listPage = (list) => `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(list.title)} · SCANCORE</title>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:48em;margin:3em auto;padding:0 1em;background:#0e0f12;color:#e8e8ec">
<p style="color:#8a8a94;margin:0">Shared by @${escapeHtml(list.owner.username)}</p>
<h1 style="font-size:1.4em;margin:.2em 0 .6em">${escapeHtml(list.title)}</h1>
<p>${list.items.length} series. In SCANCORE, open Activity → Friends → <b>Open a shared list</b> and enter <code>${escapeHtml(list.code)}</code> to add them all to your library.</p>
<ul style="padding-left:1.2em">${list.items
  .map((i) => `<li>${i.sourceUrl ? `<a style="color:#e8e8ec" href="${escapeHtml(i.sourceUrl)}" rel="noreferrer">${escapeHtml(i.title)}</a>` : escapeHtml(i.title)} <span style="color:#8a8a94">· ${escapeHtml(i.media)}</span></li>`)
  .join("")}</ul>`;

const REACTIONS = new Set(["LIKE", "LOVE", "LAUGH", "WOW", "SAD", "ANGRY"]);
function threadOf(raw) {
  const thread = String(raw ?? "").trim();
  if (!/^(u:[0-9a-f-]{36}|c:[\s\S]{1,500})$/.test(thread)) throw new HttpError(400, "Invalid chapter.");
  return thread.toLowerCase();
}

// ------------------------------------------------------------------ parties

// Watch parties: a host opens a room and shares its code; everyone in it
// streams the episode from their own source, and the host's player state
// (episode, playing or paused, position) goes to the others. Chat lines
// pass through. Nothing is stored; a room ends when its host leaves (after
// a grace period for reconnecting) or after six hours.
const PARTY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PARTY_CODE = /^[A-HJ-NP-Z2-9]{6}$/;
const PARTY_LIFETIME_MS = 6 * 60 * 60_000;
const PARTY_HOST_GRACE_MS = 30_000;
const PARTY_STREAM_MS = 30 * 60_000;
const parties = new Map();
const partyBus = new EventEmitter();
partyBus.setMaxListeners(0);

const partyMember = (user) => ({ userId: String(user.id), name: user.username, avatar: null });
const partyMembers = (room) => ({ type: "members", host: room.host, members: [...room.members.values()].map(({ streams, ...m }) => m) });
function partyPublish(code, message) {
  partyBus.emit(code, message);
}
setInterval(() => {
  for (const [code, room] of parties)
    if (now() - room.created > PARTY_LIFETIME_MS) {
      parties.delete(code);
      partyPublish(code, { type: "ended" });
    }
}, 60_000).unref();

function partyState(value) {
  if (typeof value !== "object" || value === null) return null;
  const anime = value.anime;
  if (!anime || !Number.isInteger(anime.anilistId) || typeof anime.title !== "string") return null;
  if (typeof value.episode !== "number" || typeof value.playing !== "boolean" || typeof value.position !== "number") return null;
  if (!Number.isFinite(value.episode) || !Number.isFinite(value.position) || value.position < 0) return null;
  const cover = typeof anime.cover === "string" && anime.cover.startsWith("https://") ? anime.cover.slice(0, 500) : null;
  return { anime: { anilistId: anime.anilistId, title: anime.title.slice(0, 200), cover }, episode: value.episode, playing: value.playing, position: value.position, at: now() };
}

function partyStream(request, response, user, room) {
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  const write = (event, data) => response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  const member = partyMember(user);
  response.write("retry: 5000\n\n");
  write("hello", { you: member.userId, host: room.host });
  if (member.userId === room.host && room.hostGone) {
    clearTimeout(room.hostGone);
    room.hostGone = undefined;
  }
  const known = room.members.get(member.userId);
  room.members.set(member.userId, { ...member, streams: (known?.streams ?? 0) + 1 });
  let finished = false;
  const listener = (message) => {
    if (message.type === "state") write("state", { state: { ...message.state, age: Math.max(0, now() - message.state.at) } });
    else {
      const { type, ...data } = message;
      write(type, data);
    }
    if (message.type === "ended") response.end();
  };
  partyBus.on(room.code, listener);
  if (room.state) listener({ type: "state", state: room.state });
  partyPublish(room.code, partyMembers(room));
  const ping = setInterval(() => response.write(": ping\n\n"), LIVE_PING_MS);
  const end = setTimeout(() => response.end(), PARTY_STREAM_MS);
  response.on("close", () => {
    if (finished) return;
    finished = true;
    clearInterval(ping);
    clearTimeout(end);
    partyBus.off(room.code, listener);
    if (parties.get(room.code) !== room) return;
    const current = room.members.get(member.userId);
    if (current && current.streams > 1) current.streams -= 1;
    else room.members.delete(member.userId);
    if (member.userId === room.host && !room.members.has(member.userId))
      room.hostGone = setTimeout(() => {
        if (parties.get(room.code) !== room || room.members.has(room.host)) return;
        parties.delete(room.code);
        partyPublish(room.code, { type: "ended" });
      }, PARTY_HOST_GRACE_MS);
    partyPublish(room.code, partyMembers(room));
  });
}

// Moves a reader's vote on a story point to `value` and keeps its score in
// step; false when there is no such point.
function storyVote(pointId, userId, value) {
  if (!db.prepare("SELECT 1 FROM story_points WHERE id = ?").get(pointId)) return false;
  const before = db.prepare("SELECT value FROM story_votes WHERE point_id = ? AND user_id = ?").get(pointId, userId)?.value ?? 0;
  if (value === 0) db.prepare("DELETE FROM story_votes WHERE point_id = ? AND user_id = ?").run(pointId, userId);
  else
    db.prepare(
      "INSERT INTO story_votes(point_id, user_id, value) VALUES(?, ?, ?) ON CONFLICT(point_id, user_id) DO UPDATE SET value = excluded.value",
    ).run(pointId, userId, value);
  if (value !== before) db.prepare("UPDATE story_points SET score = score + ? WHERE id = ?").run(value - before, pointId);
  return true;
}

// ------------------------------------------------------------------ routes

async function route(request, response) {
  const url = new URL(request.url ?? "/", "http://localhost");
  const method = request.method ?? "GET";
  const path = url.pathname.replace(/\/+$/, "") || "/";

  // Browsers on other sites may not change anything here; the app sends no
  // Origin, and a page served by this host sends its own.
  if (method !== "GET" && method !== "HEAD") {
    const origin = request.headers.origin;
    if (origin && new URL(origin).host !== request.headers.host)
      throw new HttpError(403, "Cross-site requests are not allowed.");
  }

  if (method === "GET" && path === "/") {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return response.end(page(ALLOW_SIGNUP));
  }
  if (method === "GET" && path === "/api/health") return send(response, 200, { status: "ok" });
  if (method === "GET" && path === "/api/capabilities")
    // devicesOnly: the app syncs everything through device snapshots here.
    return send(response, 200, {
      server: "scancore-web",
      version: VERSION,
      signup: ALLOW_SIGNUP,
      // No email here: a forgotten password is reset by whoever runs the
      // server (node server.mjs passwd), and the app says so.
      recovery: false,
      appSync: { devices: true, devicesOnly: true, live: true },
      party: true,
      friends: true,
      lists: true,
      reactions: true,
      story: true,
    });

  if (method === "POST" && path === "/api/auth/signup") {
    limitAttempts(request);
    if (!ALLOW_SIGNUP) throw new HttpError(403, "This server does not take new accounts.");
    const body = await readJson(request, 16_384);
    const email = String(body.email ?? "").trim();
    const username = String(body.username ?? "").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)
      throw new HttpError(400, "Enter a valid email address");
    if (!/^[A-Za-z0-9_]{3,32}$/.test(username)) throw new HttpError(400, "3–32 letters, numbers or underscores");
    const problem = passwordProblem(body.password) || (await unsafePassword(body.password, { username, email }));
    if (problem) throw new HttpError(400, problem);
    if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email))
      throw new HttpError(409, "An account with that email already exists.");
    if (db.prepare("SELECT 1 FROM users WHERE username = ?").get(username))
      throw new HttpError(409, "That username is taken.");
    const result = db
      .prepare("INSERT INTO users(email, username, password, created_at) VALUES(?, ?, ?, ?)")
      .run(email, username, await makePassword(body.password), now());
    startSession(request, response, Number(result.lastInsertRowid));
    return send(response, 201, { user: { username, email, avatarUrl: null } });
  }

  if (method === "POST" && path === "/api/auth/login") {
    limitAttempts(request);
    const body = await readJson(request, 16_384);
    const login = String(body.email ?? "").trim();
    const user = db.prepare("SELECT * FROM users WHERE email = ? OR username = ?").get(login, login);
    if (!user || !(await checkPassword(String(body.password ?? ""), user.password)))
      throw new HttpError(401, "That email and password do not match an account here.");
    startSession(request, response, user.id);
    return send(response, 200, { user: publicUser(user) });
  }

  if (method === "POST" && path === "/api/auth/logout") {
    const token = cookieToken(request);
    if (token) db.prepare("DELETE FROM sessions WHERE token = ?").run(sha256(token));
    response.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
    return send(response, 200, { ok: true });
  }

  if (method === "GET" && path === "/api/auth/session") {
    const user = currentUser(request);
    return send(response, 200, { user: user ? publicUser(user) : null, history: [], serverStamp: now() });
  }

  if (method === "GET" && path === "/api/app/devices") {
    const user = requireUser(request);
    const since = Math.max(0, Number(url.searchParams.get("since") ?? 0) || 0);
    const rows = db
      .prepare(
        "SELECT device_id, name, platform, data, updated_at FROM devices WHERE user_id = ? AND updated_at > ? ORDER BY updated_at",
      )
      .all(user.id, since);
    return send(response, 200, {
      devices: rows.map((row) => ({
        deviceId: row.device_id,
        name: row.name,
        platform: row.platform,
        updatedAt: row.updated_at,
        data: JSON.parse(row.data),
      })),
    });
  }

  const device = path.match(/^\/api\/app\/devices\/([A-Za-z0-9-]{8,64})$/);
  if (method === "PUT" && device) {
    const user = requireUser(request);
    const body = await readJson(request, MAX_SNAPSHOT);
    const name = String(body.name ?? "").trim().slice(0, 80);
    const platform = String(body.platform ?? "").trim().slice(0, 20);
    if (!name || !platform || typeof body.data !== "object" || body.data === null || Array.isArray(body.data))
      throw new HttpError(400, "Invalid device snapshot.");
    const known = db.prepare("SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?").get(user.id, device[1]);
    if (!known && db.prepare("SELECT COUNT(*) AS n FROM devices WHERE user_id = ?").get(user.id).n >= MAX_DEVICES)
      throw new HttpError(409, `An account can sync up to ${MAX_DEVICES} devices.`);
    // Strictly increasing, so a device written twice in one millisecond is
    // still seen as changed by the others.
    const previous = db.prepare("SELECT MAX(updated_at) AS t FROM devices WHERE user_id = ?").get(user.id).t ?? 0;
    const updatedAt = Math.max(now(), previous + 1);
    db.prepare(
      "INSERT INTO devices(user_id, device_id, name, platform, data, updated_at) VALUES(?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(user_id, device_id) DO UPDATE SET name = excluded.name, platform = excluded.platform, " +
        "data = excluded.data, updated_at = excluded.updated_at",
    ).run(user.id, device[1], name, platform, JSON.stringify(body.data), updatedAt);
    activityFromSnapshot(user.id, body.data);
    return send(response, 200, { updatedAt });
  }

  if (method === "DELETE" && device) {
    const user = requireUser(request);
    db.prepare("DELETE FROM devices WHERE user_id = ? AND device_id = ?").run(user.id, device[1]);
    return send(response, 200, { ok: true });
  }

  if (method === "GET" && path === "/api/app/live") {
    const user = requireUser(request);
    const self = liveDevice({
      id: url.searchParams.get("device"),
      name: url.searchParams.get("name"),
      platform: url.searchParams.get("platform"),
    });
    return liveStream(request, response, user, self);
  }

  if (method === "POST" && path === "/api/app/live") {
    const user = requireUser(request);
    const body = await readJson(request, LIVE_MAX_BYTES);
    const from = liveDevice(body.from);
    if (body.type !== "progress" && body.type !== "handoff") throw new HttpError(400, "Unknown live message.");
    if (typeof body.data !== "object" || body.data === null || Array.isArray(body.data)) throw new HttpError(400, "Invalid live message.");
    const to = body.to == null ? undefined : liveDevice({ id: body.to }).id;
    const delivered = liveBus.listenerCount(`user:${user.id}`);
    liveBus.emit(`user:${user.id}`, { type: body.type, from, to, data: body.data });
    return send(response, 202, { ok: true, listeners: delivered });
  }

  // Friends: {shareActivity, friends, sent, received}; POST {username}
  // follows; PATCH {shareActivity}; DELETE ?user=<id> stops following.
  if (path === "/api/app/friends") {
    const user = requireUser(request);
    if (method === "GET") {
      const share = db.prepare("SELECT share_activity FROM users WHERE id = ?").get(user.id).share_activity === 1;
      return send(response, 200, { shareActivity: share, ...friendsOf(user.id) });
    }
    if (method === "POST") {
      const body = await readJson(request, 4096);
      const name = String(body.username ?? "").trim().replace(/^@/, "");
      if (!name) throw new HttpError(400, "Type a username.");
      const other = db.prepare("SELECT id, username FROM users WHERE username = ?").get(name);
      if (!other) throw new HttpError(404, "No one has that username.");
      if (other.id === user.id) throw new HttpError(400, "That is you.");
      db.prepare("INSERT OR IGNORE INTO follows(follower, following, created_at) VALUES(?, ?, ?)").run(user.id, other.id, now());
      return send(response, 201, person(other));
    }
    if (method === "PATCH") {
      const body = await readJson(request, 1024);
      if (typeof body.shareActivity !== "boolean") throw new HttpError(400, "shareActivity must be true or false.");
      db.prepare("UPDATE users SET share_activity = ? WHERE id = ?").run(body.shareActivity ? 1 : 0, user.id);
      return send(response, 200, { shareActivity: body.shareActivity });
    }
    if (method === "DELETE") {
      db.prepare("DELETE FROM follows WHERE follower = ? AND following = ?").run(user.id, Number(url.searchParams.get("user")) || 0);
      return send(response, 200, { ok: true });
    }
  }

  // What friends who share it read and watched, newest first.
  if (method === "GET" && path === "/api/app/activity") {
    const user = requireUser(request);
    const before = url.searchParams.get("before") ? Date.parse(url.searchParams.get("before")) : now() + 1;
    if (!Number.isFinite(before)) throw new HttpError(400, "Invalid date.");
    const friends = friendsOf(user.id).friends.map((f) => Number(f.id));
    if (friends.length === 0) return send(response, 200, { events: [] });
    const rows = db
      .prepare(
        `SELECT activity.*, users.username FROM activity JOIN users ON users.id = activity.user_id
         WHERE users.share_activity = 1 AND activity.user_id IN (${friends.map(() => "?").join(",")}) AND activity.created_at < ?
         ORDER BY activity.created_at DESC LIMIT 50`,
      )
      .all(...friends, before);
    return send(response, 200, {
      events: rows.map((r) => ({
        id: String(r.id),
        user: person({ id: r.user_id, username: r.username }),
        type: r.type,
        payload: JSON.parse(r.payload),
        at: new Date(r.created_at).toISOString(),
      })),
    });
  }

  // Lists shared by code: GET (mine), POST {title, items}, DELETE ?code=.
  if (path === "/api/app/lists") {
    const user = requireUser(request);
    if (method === "GET") {
      const rows = db.prepare("SELECT code, title, items, created_at FROM shared_lists WHERE owner = ? ORDER BY created_at DESC LIMIT 200").all(user.id);
      return send(response, 200, {
        lists: rows.map((r) => ({ code: r.code, title: r.title, count: JSON.parse(r.items).length, at: new Date(r.created_at).toISOString() })),
      });
    }
    if (method === "POST") {
      const body = await readJson(request, 512 * 1024);
      const items = (Array.isArray(body.items) ? body.items : []).map(cleanItem).filter(Boolean).slice(0, 500);
      if (items.length === 0) throw new HttpError(400, "The list is empty.");
      if (db.prepare("SELECT COUNT(*) AS n FROM shared_lists WHERE owner = ?").get(user.id).n >= 200)
        throw new HttpError(400, "You have shared as many lists as this server keeps. Remove one first.");
      const title = String(body.title ?? "").trim().slice(0, 100) || "A list";
      let code = listCode();
      while (db.prepare("SELECT 1 FROM shared_lists WHERE code = ?").get(code)) code = listCode();
      db.prepare("INSERT INTO shared_lists(code, owner, title, items, created_at) VALUES(?, ?, ?, ?, ?)").run(code, user.id, title, JSON.stringify(items), now());
      recordActivity(user.id, "shared", { media: items[0].media, title, unit: String(items.length) });
      return send(response, 201, { code });
    }
    if (method === "DELETE") {
      db.prepare("DELETE FROM shared_lists WHERE owner = ? AND code = ?").run(user.id, url.searchParams.get("code") ?? "");
      return send(response, 200, { ok: true });
    }
  }
  const listApi = path.match(/^\/api\/app\/lists\/([A-Za-z0-9]{6,20})$/);
  if (method === "GET" && listApi) {
    const list = sharedList(listApi[1].toLowerCase());
    if (!list) throw new HttpError(404, "This list is not shared any more.");
    return send(response, 200, list);
  }
  const listWeb = path.match(/^\/lists\/([A-Za-z0-9]{6,20})$/);
  if (method === "GET" && listWeb) {
    const list = sharedList(listWeb[1].toLowerCase());
    if (!list) throw new HttpError(404, "This list is not shared any more.");
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return response.end(listPage(list));
  }

  // Reactions on a chapter's pages: GET ?thread= {pages, mine}; POST
  // {thread, page, type} (type null takes it back).
  if (path === "/api/app/reactions") {
    if (method === "GET") {
      const thread = threadOf(url.searchParams.get("thread"));
      const user = currentUser(request);
      const pages = new Map();
      for (const r of db.prepare("SELECT page, type, COUNT(*) AS n FROM page_reactions WHERE thread = ? GROUP BY page, type").all(thread)) {
        const entry = pages.get(r.page) ?? { page: r.page, total: 0, counts: {} };
        entry.counts[r.type] = r.n;
        entry.total += r.n;
        pages.set(r.page, entry);
      }
      const mine = {};
      if (user) for (const r of db.prepare("SELECT page, type FROM page_reactions WHERE thread = ? AND user_id = ?").all(thread, user.id)) mine[String(r.page)] = r.type;
      return send(response, 200, { pages: [...pages.values()].sort((a, b) => a.page - b.page), mine });
    }
    if (method === "POST") {
      const user = requireUser(request);
      const body = await readJson(request, 4096);
      const thread = threadOf(body.thread);
      const page = Number(body.page);
      if (!Number.isInteger(page) || page < 0 || page > 5000) throw new HttpError(400, "Invalid page.");
      if (body.type === null) {
        db.prepare("DELETE FROM page_reactions WHERE user_id = ? AND thread = ? AND page = ?").run(user.id, thread, page);
        return send(response, 200, { page, type: null });
      }
      if (!REACTIONS.has(body.type)) throw new HttpError(400, "Invalid reaction.");
      db.prepare(
        "INSERT INTO page_reactions(user_id, thread, page, type, created_at) VALUES(?, ?, ?, ?, ?) " +
          "ON CONFLICT(user_id, thread, page) DO UPDATE SET type = excluded.type, created_at = excluded.created_at",
      ).run(user.id, thread, page, body.type, now());
      return send(response, 200, { page, type: body.type });
    }
  }

  // Where an anime leaves off: GET ?anime=1,2 {points: {"1": [...]}}, best
  // first; POST {animeId, media, sourceId?, chapter | volume} adds a point
  // (or votes for the same one); POST /vote {id, value} (1, -1 or 0).
  if (path === "/api/story" && method === "GET") {
    const ids = [...new Set((url.searchParams.get("anime") ?? "").split(",").map(Number))]
      .filter((id) => Number.isInteger(id) && id > 0 && id < 10_000_000)
      .slice(0, 50);
    const user = currentUser(request);
    const points = {};
    const list = db.prepare(
      "SELECT p.*, (SELECT value FROM story_votes v WHERE v.point_id = p.id AND v.user_id = ?) AS mine " +
        "FROM story_points p WHERE anime_id = ? ORDER BY score DESC, created_at ASC LIMIT 20",
    );
    for (const id of ids)
      points[String(id)] = list.all(user?.id ?? -1, id).map((p) => ({
        id: p.id,
        media: p.media,
        sourceId: p.source_id,
        chapter: p.chapter,
        volume: p.volume,
        score: p.score,
        seeded: p.seeded === 1,
        mine: p.mine ?? 0,
        submitted: !!user && p.user_id === user.id,
      }));
    return send(response, 200, { points });
  }
  if (path === "/api/story" && method === "POST") {
    const user = requireUser(request);
    const body = await readJson(request, 4096);
    const animeId = Number(body.animeId);
    const media = String(body.media ?? "");
    const sourceId = body.sourceId == null ? null : Number(body.sourceId);
    const chapter = body.chapter == null ? null : Math.round(Number(body.chapter) * 10) / 10;
    const volume = body.volume == null ? null : Number(body.volume);
    if (!Number.isInteger(animeId) || animeId <= 0 || (media !== "comic" && media !== "novel"))
      throw new HttpError(400, "An anime and comic or novel are required.");
    if (sourceId !== null && (!Number.isInteger(sourceId) || sourceId <= 0)) throw new HttpError(400, "That source entry is not valid.");
    const validChapter = chapter !== null && Number.isFinite(chapter) && chapter > 0 && chapter < 100_000;
    const validVolume = volume !== null && Number.isInteger(volume) && volume > 0 && volume < 1000;
    if (validChapter === validVolume) throw new HttpError(400, "Give a chapter or a volume.");
    const existing = db
      .prepare("SELECT id FROM story_points WHERE anime_id = ? AND media = ? AND chapter IS ? AND volume IS ?")
      .get(animeId, media, validChapter ? chapter : null, validVolume ? volume : null);
    if (existing) {
      storyVote(existing.id, user.id, 1);
      return send(response, 200, { ok: true, id: existing.id, existed: true });
    }
    const id = randomUUID();
    db.prepare(
      "INSERT INTO story_points(id, anime_id, media, source_id, chapter, volume, seeded, score, user_id, created_at) VALUES(?, ?, ?, ?, ?, ?, 0, 0, ?, ?)",
    ).run(id, animeId, media, sourceId, validChapter ? chapter : null, validVolume ? volume : null, user.id, now());
    storyVote(id, user.id, 1);
    return send(response, 200, { ok: true, id, existed: false });
  }
  if (path === "/api/story/vote" && method === "POST") {
    const user = requireUser(request);
    const body = await readJson(request, 1024);
    const value = Number(body.value);
    if (![1, -1, 0].includes(value)) throw new HttpError(400, "A vote is 1, -1 or 0.");
    if (!storyVote(String(body.id ?? ""), user.id, value)) throw new HttpError(404, "No such point.");
    return send(response, 200, { ok: true });
  }

  // Watch parties: POST opens one ({code}); GET /<code> is its stream;
  // POST /<code> {type: "state", state} (host), {type: "chat", text},
  // {type: "end"} (host).
  if (method === "POST" && path === "/api/app/party") {
    const user = requireUser(request);
    let code = "";
    do code = Array.from({ length: 6 }, () => PARTY_ALPHABET[randomInt(PARTY_ALPHABET.length)]).join("");
    while (parties.has(code));
    const room = { code, host: String(user.id), created: now(), state: null, members: new Map() };
    parties.set(code, room);
    return send(response, 201, { code });
  }
  const partyPath = path.match(/^\/api\/app\/party\/([A-Za-z0-9]{6})$/);
  if (partyPath) {
    const user = requireUser(request);
    const code = partyPath[1].toUpperCase();
    const room = PARTY_CODE.test(code) ? parties.get(code) : undefined;
    if (!room) throw new HttpError(404, "No party with that code.");
    if (method === "GET") return partyStream(request, response, user, room);
    if (method === "POST") {
      const body = await readJson(request, 4096);
      if (body.type === "state") {
        const state = partyState(body.state);
        if (!state) throw new HttpError(400, "Invalid player state.");
        if (room.host !== String(user.id)) throw new HttpError(403, "Only the host steers the party.");
        room.state = state;
        partyPublish(code, { type: "state", state });
      } else if (body.type === "chat") {
        const text = typeof body.text === "string" ? body.text.trim().slice(0, 300) : "";
        if (!text) throw new HttpError(400, "Say something first.");
        partyPublish(code, { type: "chat", from: partyMember(user), text, at: now() });
      } else if (body.type === "end") {
        if (room.host !== String(user.id)) throw new HttpError(404, "No party with that code.");
        clearTimeout(room.hostGone);
        parties.delete(code);
        partyPublish(code, { type: "ended" });
      } else throw new HttpError(400, "Unknown party message.");
      return send(response, 202, { ok: true });
    }
  }

  throw new HttpError(404, "Not found.");
}

const server = createServer((request, response) => {
  route(request, response).catch((error) => {
    const status = error instanceof HttpError ? error.status : 500;
    if (status === 500) console.error(error);
    if (!response.headersSent) send(response, status, { error: status === 500 ? "Something went wrong." : error.message });
    else response.end();
  });
});
server.requestTimeout = 120_000;
server.listen(PORT, HOST, () => {
  console.log(`SCANCORE sync server ${VERSION} on http://${HOST}:${PORT} (data in ${DATA_DIR}, sign-up ${ALLOW_SIGNUP ? "on" : "off"})`);
});
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    server.close();
    db.close();
    process.exit(0);
  });
