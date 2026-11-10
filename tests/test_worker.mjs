// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Testy Cloudflare Workera (proxy + relay Binance Guard na krawędzi), bez sieci:  node tests/test_worker.mjs
import assert from "node:assert";
import worker from "../cloudflare/worker.js";

let ok = 0, bad = 0;
const calls = [];
let reply = () => new Response("{}", { status: 200 });
globalThis.fetch = async (url, init) => { calls.push({ url: String(url), init }); return reply(String(url), init); };
async function t(name, fn) { calls.length = 0; try { await fn(); ok++; console.log("OK   " + name); } catch (e) { bad++; console.log("FAIL " + name + ": " + e.message); } }
const KEY = "K".repeat(64), SIG = "b".repeat(64);
const post = (body, ct = "application/json") => new Request("https://szlaban.remi-cloud.workers.dev/api/binance/relay",
  { method: "POST", headers: { "Content-Type": ct, "CF-Connecting-IP": "203.0.113." + Math.floor(Math.random() * 250) }, body: typeof body === "string" ? body : JSON.stringify(body) });
const signed = (ep, extra) => Object.assign({ endpoint: ep, apiKey: KEY, timestamp: String(Date.now()), recvWindow: "10000", signature: SIG }, extra || {});

await t("proxy: zwykłe ścieżki idą do Rendera bez zmian", async () => {
  reply = () => new Response("ok", { status: 200, headers: { "Content-Type": "text/plain" } });
  const r = await worker.fetch(new Request("https://szlaban.remi-cloud.workers.dev/healthz?x=1"));
  assert.strictEqual(calls[0].url, "https://szlaban.onrender.com/healthz?x=1");
  assert.strictEqual(r.headers.get("X-Served-By"), "cloudflare-worker");
  assert.strictEqual(r.headers.get("Cache-Control"), "no-store");
});
await t("relay: podpisane zapytanie składane od nowa, klucz w nagłówku", async () => {
  reply = () => new Response('{"ipRestrict":false}', { status: 200 });
  const r = await worker.fetch(post(signed("apiRestrictions")));
  assert.strictEqual(r.status, 200);
  assert.match(calls[0].url, /^https:\/\/api\.binance\.com\/sapi\/v1\/account\/apiRestrictions\?timestamp=\d{13}&recvWindow=10000&signature=b{64}$/);
  assert.strictEqual(calls[0].init.headers["X-MBX-APIKEY"], KEY);
  assert.strictEqual(calls[0].init.redirect, "manual");
  assert.strictEqual(r.headers.get("X-BG-Relay"), "cloudflare-edge");
  assert.strictEqual(r.headers.get("Cache-Control"), "no-store");
  assert.deepStrictEqual(await r.json(), { data: { ipRestrict: false } });
});
await t("relay: nie idzie do Rendera", async () => { reply = () => new Response("{}", { status: 200 }); await worker.fetch(post({ endpoint: "time" })); assert.ok(calls.every(c => !c.url.includes("onrender"))); });
await t("relay: endpoint spoza listy odrzucony bez połączenia", async () => {
  const r = await worker.fetch(post(signed("order"))); assert.strictEqual(r.status, 400); assert.strictEqual((await r.json()).error, "endpoint_not_allowed"); assert.strictEqual(calls.length, 0);
});
await t("relay: pole secret odrzucone", async () => { const r = await worker.fetch(post(signed("apiRestrictions", { secret: "x" }))); assert.strictEqual((await r.json()).error, "bad_field"); assert.strictEqual(calls.length, 0); });
await t("relay: wstrzyknięcie w podpis odrzucone", async () => { const r = await worker.fetch(post(signed("apiRestrictions", { signature: SIG + "&a=1" }))); assert.strictEqual((await r.json()).error, "bad_signature"); });
await t("relay: stary timestamp odrzucony", async () => { const r = await worker.fetch(post(signed("apiRestrictions", { timestamp: String(Date.now() - 3600000) }))); assert.strictEqual((await r.json()).error, "stale_timestamp"); });
await t("relay: wymagany JSON", async () => { const r = await worker.fetch(post("a=1", "application/x-www-form-urlencoded")); assert.strictEqual(r.status, 415); });
await t("relay: za duże ciało", async () => { const r = await worker.fetch(post(JSON.stringify({ endpoint: "x".repeat(3000) }))); assert.strictEqual(r.status, 413); });
await t("relay: 451 z CloudFront = geo_blocked", async () => {
  reply = () => new Response('{"code":0,"msg":"Service unavailable from a restricted location"}', { status: 451 });
  const r = await worker.fetch(post(signed("apiRestrictions"))); assert.strictEqual(r.status, 451); assert.strictEqual((await r.json()).error, "geo_blocked");
});
await t("relay: błąd Binance -2015 przekazany", async () => {
  reply = () => new Response('{"code":-2015,"msg":"Invalid API-key, IP, or permissions for action."}', { status: 401 });
  const j = await (await worker.fetch(post(signed("withdrawAddressList")))).json(); assert.strictEqual(j.binance_code, -2015);
});
await t("relay: GET na /api/binance/relay idzie do Rendera (tam 404)", async () => {
  reply = () => new Response('{"error":"x"}', { status: 404 });
  await worker.fetch(new Request("https://szlaban.remi-cloud.workers.dev/api/binance/relay")); assert.strictEqual(calls[0].url, "https://szlaban.onrender.com/api/binance/relay");
});
console.log("wynik: " + ok + " OK, " + bad + " FAIL");
process.exit(bad ? 1 : 0);
