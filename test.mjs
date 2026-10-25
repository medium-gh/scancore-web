// End-to-end checks against a server started on a free port with a
// temporary data folder.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";

const port = 18000 + Math.floor(Math.random() * 2000);
const base = `http://127.0.0.1:${port}`;
const dir = mkdtempSync(join(tmpdir(), "scancore-web-"));
let server;

before(async () => {
  server = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", "server.mjs"], {
    env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", DATA_DIR: dir, ATTEMPT_LIMIT: "1000" },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("server did not start");
});
after(() => {
  server.kill();
  rmSync(dir, { recursive: true, force: true });
});

const json = (body) => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
async function signUp(name) {
  const response = await fetch(`${base}/api/auth/signup`, json({ email: `${name}@example.test`, username: name, password: "Secret-pass1" }));
  assert.equal(response.status, 201);
  return response.headers.get("set-cookie").split(";")[0];
}
const put = (cookie, id, body) =>
  fetch(`${base}/api/app/devices/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify(body),
  });

test("capabilities say devices only", async () => {
  const caps = await (await fetch(`${base}/api/capabilities`)).json();
  assert.deepEqual(caps.appSync, { devices: true, devicesOnly: true, live: true });
});

test("accounts: rules, sign-in, session, sign-out", async () => {
  const weak = await fetch(`${base}/api/auth/signup`, json({ email: "a@example.test", username: "aa_bb", password: "short" }));
  assert.equal(weak.status, 400);
  const cookie = await signUp("reader_one");
  const session = await (await fetch(`${base}/api/auth/session`, { headers: { Cookie: cookie } })).json();
  assert.equal(session.user.username, "reader_one");
  assert.deepEqual(session.history, []);
  const duplicate = await fetch(`${base}/api/auth/signup`, json({ email: "READER_ONE@example.test", username: "x_y_z", password: "Secret-pass1" }));
  assert.equal(duplicate.status, 409);
  const bad = await fetch(`${base}/api/auth/login`, json({ email: "reader_one@example.test", password: "Wrong-pass1" }));
  assert.equal(bad.status, 401);
  const good = await fetch(`${base}/api/auth/login`, json({ email: "reader_one", password: "Secret-pass1" }));
  assert.equal(good.status, 200);
  const other = good.headers.get("set-cookie").split(";")[0];
  await fetch(`${base}/api/auth/logout`, { method: "POST", headers: { Cookie: other } });
  const gone = await (await fetch(`${base}/api/auth/session`, { headers: { Cookie: other } })).json();
  assert.equal(gone.user, null);
});

test("devices: write, read since, isolation, validation", async () => {
  const a = await signUp("reader_two");
  const b = await signUp("reader_three");
  assert.equal((await fetch(`${base}/api/app/devices`)).status, 401);
  const first = await (await put(a, "device-aaaa-1", { name: "Laptop", platform: "linux", data: { library: { x: 1 } } })).json();
  const second = await (await put(a, "device-bbbb-2", { name: "Phone", platform: "android", data: { library: {} } })).json();
  assert.ok(second.updatedAt > first.updatedAt);
  const all = await (await fetch(`${base}/api/app/devices?since=0`, { headers: { Cookie: a } })).json();
  assert.deepEqual(all.devices.map((d) => d.name), ["Laptop", "Phone"]);
  assert.deepEqual(all.devices[0].data, { library: { x: 1 } });
  const newer = await (await fetch(`${base}/api/app/devices?since=${first.updatedAt}`, { headers: { Cookie: a } })).json();
  assert.deepEqual(newer.devices.map((d) => d.name), ["Phone"]);
  const others = await (await fetch(`${base}/api/app/devices`, { headers: { Cookie: b } })).json();
  assert.equal(others.devices.length, 0);
  assert.equal((await put(a, "bad", { name: "x", platform: "linux", data: {} })).status, 404);
  assert.equal((await put(a, "device-cccc-3", { name: "", platform: "linux", data: {} })).status, 400);
  const cross = await fetch(`${base}/api/app/devices/device-aaaa-1`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Cookie: a, Origin: "https://elsewhere.example" },
    body: JSON.stringify({ name: "x", platform: "linux", data: {} }),
  });
  assert.equal(cross.status, 403);
});

test("a large snapshot fits", async () => {
  const a = await signUp("reader_four");
  const blob = "x".repeat(5 * 1024 * 1024);
  assert.equal((await put(a, "device-big-0001", { name: "Big", platform: "linux", data: { blob } })).status, 200);
});

// Reads a live stream's events as they come.
function listen(cookie, id, name) {
  const controller = new AbortController();
  const events = [];
  let wake = () => {};
  const ready = fetch(`${base}/api/app/live?device=${id}&name=${name}&platform=linux`, {
    headers: { Cookie: cookie, Accept: "text/event-stream" },
    signal: controller.signal,
  }).then(async (response) => {
    assert.equal(response.status, 200);
    (async () => {
      const decoder = new TextDecoder();
      let buffer = "";
      try {
        for await (const chunk of response.body) {
          buffer += decoder.decode(chunk, { stream: true });
          let end;
          while ((end = buffer.indexOf("\n\n")) >= 0) {
            const block = buffer.slice(0, end);
            buffer = buffer.slice(end + 2);
            const event = /^event: (.*)$/m.exec(block)?.[1];
            const data = /^data: (.*)$/m.exec(block)?.[1];
            if (event) events.push({ event, data: JSON.parse(data) });
            wake();
          }
        }
      } catch {}
    })();
  });
  const next = async (event) => {
    for (let i = 0; i < 50; i++) {
      const index = events.findIndex((e) => e.event === event);
      if (index >= 0) return events.splice(index, 1)[0].data;
      await new Promise((resolve) => {
        wake = resolve;
        setTimeout(resolve, 100);
      });
    }
    throw new Error(`no ${event} event`);
  };
  return { ready, next, events, close: () => controller.abort() };
}

test("live: presence, progress to the others, handoff to one device, isolation", async () => {
  const a = await signUp("reader_live");
  const b = await signUp("reader_else");
  assert.equal((await fetch(`${base}/api/app/live?device=device-live-0001`)).status, 401);
  const laptop = listen(a, "device-live-0001", "Laptop");
  await laptop.ready;
  const phone = listen(a, "device-live-0002", "Phone");
  await phone.ready;
  const stranger = listen(b, "device-live-0009", "Other");
  await stranger.ready;
  // Each sees the other come online.
  assert.equal((await laptop.next("presence")).device.name, "Phone");
  assert.deepEqual(await phone.next("presence"), { device: { id: "device-live-0001", name: "Laptop", platform: "linux" }, online: true });
  const post = (body) =>
    fetch(`${base}/api/app/live`, { method: "POST", headers: { "Content-Type": "application/json", Cookie: a }, body: JSON.stringify(body) });
  const from = { id: "device-live-0001", name: "Laptop", platform: "linux" };
  assert.equal((await post({ from, type: "progress", data: { seriesId: "comic:x:1", unit: ["Ch 1"] } })).status, 202);
  assert.deepEqual(await phone.next("progress"), { from, data: { seriesId: "comic:x:1", unit: ["Ch 1"] } });
  assert.equal((await post({ from, type: "handoff", to: "device-live-0002", data: { seriesId: "s" } })).status, 202);
  assert.equal((await phone.next("handoff")).data.seriesId, "s");
  assert.equal(laptop.events.filter((e) => e.event === "progress" || e.event === "handoff").length, 0);
  assert.equal((await post({ from, type: "nope", data: {} })).status, 400);
  assert.equal((await post({ from: { id: "x" }, type: "progress", data: {} })).status, 400);
  phone.close();
  assert.equal((await laptop.next("presence")).online, false);
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(stranger.events.length, 0);
  laptop.close();
  stranger.close();
});

const call = (cookie, path, method = "GET", body) =>
  fetch(`${base}${path}`, {
    method,
    headers: { Cookie: cookie, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });

test("friends: follow both ways, sharing what you read, activity from snapshots", async () => {
  const ann = await signUp("ann_f");
  const ben = await signUp("ben_f");
  assert.equal((await call(ann, "/api/app/friends", "POST", { username: "@BEN_F" })).status, 201);
  assert.equal((await call(ann, "/api/app/friends", "POST", { username: "nobody_here" })).status, 404);
  let mine = await (await call(ben, "/api/app/friends")).json();
  assert.deepEqual(mine.received.map((p) => p.username), ["ann_f"]);
  await call(ben, "/api/app/friends", "POST", { username: "ann_f" });
  mine = await (await call(ben, "/api/app/friends")).json();
  assert.deepEqual(mine.friends.map((p) => p.username), ["ann_f"]);
  assert.equal(mine.shareActivity, false);

  // Ann reads a chapter: nothing shows until she shares.
  const snapshot = (at) => ({
    name: "Laptop",
    platform: "linux",
    data: {
      series: { "comic:x:https://example.test/s": { media: "comic", title: "Solo Leveling", cover: "https://example.test/c.jpg", sourceUrl: "https://example.test/s" } },
      progress: { "comic:x:https://example.test/s": { c12: ["Chapter 12", "12", "https://example.test/s/12", "", 0.4, 0, at] } },
    },
  });
  await put(ann, "device-ann-1", snapshot(Math.floor(Date.now() / 1000)));
  assert.deepEqual((await (await call(ben, "/api/app/activity")).json()).events, []);
  await call(ann, "/api/app/friends", "PATCH", { shareActivity: true });
  await put(ann, "device-ann-1", snapshot(Math.floor(Date.now() / 1000)));
  await put(ann, "device-ann-1", snapshot(Math.floor(Date.now() / 1000)));
  const feed = (await (await call(ben, "/api/app/activity")).json()).events;
  assert.equal(feed.length, 1);
  assert.equal(feed[0].user.username, "ann_f");
  assert.equal(feed[0].type, "read");
  assert.equal(feed[0].payload.title, "Solo Leveling");
  assert.equal(feed[0].payload.unit, "Chapter 12");
  // Old reading is not news.
  await put(ann, "device-ann-2", { ...snapshot(1000), data: { ...snapshot(1000).data, series: { "comic:x:https://example.test/t": { media: "comic", title: "Old" } }, progress: { "comic:x:https://example.test/t": { c1: ["Ch 1", "1", "", "", 1, 1, 1000] } } } });
  assert.equal((await (await call(ben, "/api/app/activity")).json()).events.length, 1);
  // Ben does not share: Ann sees nothing of his.
  assert.deepEqual((await (await call(ann, "/api/app/activity")).json()).events, []);
  // Unfollowing ends the friendship.
  const id = mine.friends[0].id;
  await call(ben, `/api/app/friends?user=${id}`, "DELETE");
  assert.deepEqual((await (await call(ben, "/api/app/friends")).json()).friends, []);
});

test("lists: shared by code, opened by anyone, unsafe links dropped", async () => {
  const owner = await signUp("lister_l");
  const made = await call(owner, "/api/app/lists", "POST", {
    title: "Picks",
    items: [{ title: "One", media: "comic", sourceUrl: "https://example.test/1" }, { title: "Two", media: "novel", sourceUrl: "javascript:alert(1)" }, { media: "comic" }],
  });
  assert.equal(made.status, 201);
  const { code } = await made.json();
  const list = await (await fetch(`${base}/api/app/lists/${code}`)).json();
  assert.equal(list.title, "Picks");
  assert.equal(list.items.length, 2);
  assert.equal(list.items[1].sourceUrl, undefined);
  const html = await (await fetch(`${base}/lists/${code}`)).text();
  assert.match(html, /Picks/);
  assert.doesNotMatch(html, /javascript:/);
  assert.equal((await (await call(owner, "/api/app/lists")).json()).lists.length, 1);
  await call(owner, `/api/app/lists?code=${code}`, "DELETE");
  assert.equal((await fetch(`${base}/api/app/lists/${code}`)).status, 404);
  assert.equal((await call(owner, "/api/app/lists", "POST", { title: "Empty", items: [] })).status, 400);
});

test("reactions: per page, one each, taken back", async () => {
  const a = await signUp("react_a");
  const b = await signUp("react_b");
  const thread = "c:Solo Leveling|12";
  await call(a, "/api/app/reactions", "POST", { thread, page: 3, type: "LOVE" });
  await call(b, "/api/app/reactions", "POST", { thread, page: 3, type: "LAUGH" });
  await call(b, "/api/app/reactions", "POST", { thread, page: 3, type: "WOW" });
  let got = await (await call(b, `/api/app/reactions?thread=${encodeURIComponent(thread)}`)).json();
  assert.deepEqual(got.pages, [{ page: 3, total: 2, counts: { LOVE: 1, WOW: 1 } }]);
  assert.deepEqual(got.mine, { 3: "WOW" });
  await call(b, "/api/app/reactions", "POST", { thread, page: 3, type: null });
  got = await (await fetch(`${base}/api/app/reactions?thread=${encodeURIComponent(thread)}`)).json();
  assert.deepEqual(got.pages, [{ page: 3, total: 1, counts: { LOVE: 1 } }]);
  assert.equal((await call(a, "/api/app/reactions", "POST", { thread: "x", page: 1, type: "LIKE" })).status, 400);
  assert.equal((await call(a, "/api/app/reactions", "POST", { thread, page: 1, type: "MEH" })).status, 400);
});

test("watch party: the host's state reaches the guest, chat, end", async () => {
  const host = await signUp("party_host");
  const guest = await signUp("party_guest");
  const opened = await call(host, "/api/app/party", "POST", {});
  assert.equal(opened.status, 201);
  const { code } = await opened.json();
  assert.match(code, /^[A-HJ-NP-Z2-9]{6}$/);
  const hostStream = await call(host, `/api/app/party/${code}`);
  const guestStream = await call(guest, `/api/app/party/${code}`);
  const reader = guestStream.body.getReader();
  let seen = "";
  const until = async (pattern) => {
    while (!pattern.test(seen)) seen += new TextDecoder().decode((await reader.read()).value);
  };
  await until(/event: hello/);
  const state = { anime: { anilistId: 21, title: "One Piece" }, episode: 5, playing: true, position: 61 };
  assert.equal((await call(guest, `/api/app/party/${code}`, "POST", { type: "state", state })).status, 403);
  assert.equal((await call(host, `/api/app/party/${code}`, "POST", { type: "state", state })).status, 202);
  await until(/event: state\ndata: .*"episode":5/);
  await call(guest, `/api/app/party/${code}`, "POST", { type: "chat", text: "hi" });
  await until(/event: chat\ndata: .*"text":"hi"/);
  await call(host, `/api/app/party/${code}`, "POST", { type: "end" });
  await until(/event: ended/);
  hostStream.body.cancel();
  assert.equal((await call(guest, `/api/app/party/${code}`, "POST", { type: "chat", text: "late" })).status, 404);
});

test("where the anime leaves off: seeded points, suggestions and votes", async () => {
  // Seeded: Attack on Titan season 1 goes on from chapter 34.
  const seeded = await (await fetch(`${base}/api/story?anime=16498,21459`)).json();
  assert.equal(seeded.points["16498"][0].chapter, 34);
  assert.equal(seeded.points["16498"][0].seeded, true);
  assert.equal(seeded.points["21459"][0].chapter, 22);
  const a = await signUp("story_a");
  const b = await signUp("story_b");
  assert.equal((await fetch(`${base}/api/story`, json({ animeId: 1, media: "comic", chapter: 5 }))).status, 401);
  assert.equal((await call(a, "/api/story", "POST", { animeId: 1, media: "comic" })).status, 400);
  assert.equal((await call(a, "/api/story", "POST", { animeId: 1, media: "comic", chapter: 5, volume: 2 })).status, 400);
  const added = await (await call(a, "/api/story", "POST", { animeId: 1, media: "comic", sourceId: 9, chapter: 5 })).json();
  assert.equal(added.existed, false);
  // The same point from someone else is a vote for it.
  assert.equal((await (await call(b, "/api/story", "POST", { animeId: 1, media: "comic", chapter: 5 })).json()).existed, true);
  let mine = (await (await call(a, "/api/story?anime=1")).json()).points["1"][0];
  assert.deepEqual([mine.score, mine.mine, mine.submitted, mine.sourceId], [2, 1, true, 9]);
  assert.equal((await call(b, "/api/story/vote", "POST", { id: added.id, value: -1 })).status, 200);
  assert.equal((await (await call(b, "/api/story?anime=1")).json()).points["1"][0].score, 0);
  assert.equal((await call(b, "/api/story/vote", "POST", { id: added.id, value: 0 })).status, 200);
  mine = (await (await call(b, "/api/story?anime=1")).json()).points["1"][0];
  assert.deepEqual([mine.score, mine.mine, mine.submitted], [1, 0, false]);
  assert.equal((await call(b, "/api/story/vote", "POST", { id: "nope", value: 1 })).status, 404);
  assert.equal((await call(b, "/api/story/vote", "POST", { id: added.id, value: 3 })).status, 400);
});
