#!/usr/bin/env node
// SCANCORE sync server: accounts and device sync for the SCANCORE app, on
// your own machine. Each app install keeps one snapshot here (its library,
// removals, reading and watching progress, and activity) and reads the
// others'; the app merges them itself, so the server only stores them.
//
// No dependencies: Node's own HTTP server, SQLite and scrypt.
//
//   node server.mjs                      start (see README.md for settings)
//   node server.mjs passwd <user> <new>  set an account's password
//   node server.mjs delete <user>        delete an account and its devices

import { EventEmitter } from "node:events";
import { createServer } from "node:http";
import { randomBytes, scrypt, timingSafeEqual, createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { promisify } from "node:util";

const VERSION = "1.1.0";
const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "0.0.0.0";
const DATA_DIR = process.env.DATA_DIR ?? join(process.cwd(), "data");
// New accounts; turn off once yours exist.
const ALLOW_SIGNUP = (process.env.ALLOW_SIGNUP ?? "true") !== "false";
// Behind a reverse proxy (Caddy, nginx): trust its X-Forwarded-* headers.
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const MAX_DEVICES = Number(process.env.MAX_DEVICES ?? 20);
const MAX_SNAPSHOT = Number(process.env.MAX_SNAPSHOT_MB ?? 16) * 1024 * 1024;
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
`);

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
    const problem = passwordProblem(args[1] ?? "");
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

// Sign-in and sign-up attempts: 10 per 15 minutes per address.
const attempts = new Map();
function limitAttempts(request) {
  const key = clientAddress(request);
  const window = 15 * 60 * 1000;
  const list = (attempts.get(key) ?? []).filter((at) => now() - at < window);
  if (list.length >= 10) throw new HttpError(429, "Too many attempts. Wait a few minutes and try again.");
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
      appSync: { devices: true, devicesOnly: true, live: true },
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
    const problem = passwordProblem(body.password);
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
