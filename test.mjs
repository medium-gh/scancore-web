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
    env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", DATA_DIR: dir },
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
