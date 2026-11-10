// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Test e2e Binance Guard w przeglądarce bez okna (playwright-core + systemowy Chrome). Relay jest podmieniany
// w przeglądarce (page.route), więc test nie łączy się z Binance. Uruchom: BASE=http://127.0.0.1:8080 node tests/e2e_binance.js
"use strict";
const { chromium } = require("playwright-core");
const assert = require("assert");
const BASE = process.env.BASE || "http://127.0.0.1:8080";
const OUT = process.env.OUT || "";
const CHROME = process.env.CHROME || "/usr/bin/google-chrome";
const KEY = "E2EKEY" + "x".repeat(58), SECRET = "E2ESECRET" + "y".repeat(55);
let ok = 0, bad = 0;
async function t(name, fn) { try { await fn(); ok++; console.log("OK   " + name); } catch (e) { bad++; console.log("FAIL " + name + ": " + e.message); } }

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, args: ["--no-sandbox"] });
  const errors = [];
  const ctx = await browser.newContext({ locale: "pl-PL", viewport: { width: 1200, height: 900 } });
  const page = await ctx.newPage();
  page.on("pageerror", e => errors.push("pageerror: " + e.message));
  page.on("console", m => { if (m.type() === "error") errors.push("console: " + m.text()); });
  const bodies = [];
  let addrList = [{ coin: "BTC", network: "BTC", address: "bc1qsafe", addressTag: "", name: "Ledger", whiteStatus: true, origin: "", originType: "" }];
  await page.route("**/api/binance/relay", async route => {
    const b = route.request().postData(); bodies.push(b);
    const j = JSON.parse(b);
    const data = { time: { serverTime: Date.now() },
      apiRestrictions: { ipRestrict: false, createTime: Date.now() - 500 * 86400000, enableWithdrawals: true, enableInternalTransfer: false,
        permitsUniversalTransfer: false, enableVanillaOptions: false, enableReading: true, enableFutures: true, enableMargin: false,
        enableSpotAndMarginTrading: false, tradingAuthorityExpirationTime: 0 },
      accountStatus: { data: "Normal" }, apiTradingStatus: { data: { isLocked: false } }, withdrawAddressList: addrList }[j.endpoint];
    await route.fulfill({ status: 200, contentType: "application/json", headers: { "X-BG-Relay": "server" }, body: JSON.stringify({ data }) });
  });

  await page.goto(BASE + "/binance");
  await t("język z przeglądarki (pl)", async () => assert.match(await page.textContent("h1"), /Zamknij swoje konto/));
  await t("zastrzeżenie widoczne", async () => assert.match(await page.textContent("#disclaimer"), /nie jest powiązane z Binance/i));
  await page.fill("#apiKey", KEY); await page.fill("#apiSecret", SECRET);
  await page.click("#runAudit");
  await page.waitForSelector("#auditOut .findings li");
  await t("audyt: krytyczne przy włączonych wypłatach", async () => { const s = await page.textContent("#auditOut"); assert.match(s, /KRYTYCZNE/); assert.match(s, /Wypłaty przez API są WŁĄCZONE/); assert.match(s, /kontrakty futures/); assert.match(s, /500 dni/); });
  await t("sekret nigdy nie wysłany", async () => { assert.ok(bodies.length >= 3); for (const b of bodies) { assert.ok(!b.includes(SECRET)); assert.ok(!b.includes("ESECRET")); } assert.ok(bodies.some(b => /"signature":"[0-9a-f]{64}"/.test(b))); });
  await t("sekret nie trafia do localStorage", async () => assert.ok(!(await page.evaluate(() => JSON.stringify(localStorage))).includes("ESECRET")));
  if (OUT) await page.screenshot({ path: OUT + "binance-audit-pl.png", fullPage: true });

  await page.click("#tab-guard");
  await page.click("#fetchAddr"); await page.waitForSelector("#addrOut table");
  await page.click("#saveBase");
  await t("baseline zapisany (skróty, bez adresu)", async () => { const v = await page.evaluate(() => localStorage.getItem("bg.baseline.v1")); assert.ok(v && !v.includes("bc1qsafe")); });
  addrList = [{ coin: "BTC", network: "BTC", address: "bc1qATTACKER", addressTag: "", name: "Ledger", whiteStatus: true }];
  await page.click("#fetchAddr"); await page.waitForSelector("#diffOut .diff-alert");
  await t("strażnik wykrywa podmieniony adres", async () => assert.match(await page.textContent("#diffOut"), /bc1qATTACKER/));
  if (OUT) await page.screenshot({ path: OUT + "binance-guard-pl.png", fullPage: true });

  await page.click("#tab-detect");
  await page.fill("#detIn", "Pilne! Twoje konto Binance zostanie zablokowane w ciągu 24 godzin. Podaj kod 2FA: http://binance-verify.top/login");
  await page.click("#runDetect");
  await t("wykrywacz: krytyczne", async () => { const s = await page.textContent("#detOut"); assert.match(s, /KRYTYCZNE/); assert.match(s, /binance-verify\.top/); });
  await page.click('.lang[data-lang="zh"]');
  await t("przełącznik na chiński tłumaczy też wyniki", async () => { assert.match(await page.textContent("h1"), /锁好/); assert.match(await page.textContent("#detOut"), /严重/); });
  if (OUT) await page.screenshot({ path: OUT + "binance-detect-zh.png", fullPage: true });
  await page.reload();
  await t("wybór języka zapamiętany", async () => assert.match(await page.textContent("h1"), /锁好/));
  await page.click('.lang[data-lang="en"]');
  await t("angielski", async () => assert.match(await page.textContent("h1"), /Lock down/));
  await page.click("#tab-audit");
  await page.click('label.chip:has(input[value=manual]) span');
  await page.click("#c-chk_2fa");
  await t("lista ręczna liczy i zapamiętuje", async () => { assert.match(await page.textContent("#manualScore"), /1 of 9/); await page.reload(); await page.click('label.chip:has(input[value=manual]) span'); assert.match(await page.textContent("#manualScore"), /1 of 9/); });

  // brak podmiany relay: prawdziwy serwer (np. w USA -> 451) – komunikat musi być zrozumiały
  const p2 = await (await browser.newContext({ locale: "en-US" })).newPage();
  p2.on("pageerror", e => errors.push("pageerror2: " + e.message));
  await p2.goto(BASE + "/binance#audit");
  await p2.fill("#apiKey", KEY); await p2.fill("#apiSecret", SECRET); await p2.click("#runAudit");
  await p2.waitForFunction(() => document.getElementById("auditErr").classList.contains("on") || document.querySelector("#auditOut li"), null, { timeout: 30000 });
  await t("prawdziwy relay: czytelny wynik albo błąd", async () => { const s = await p2.textContent("#auditErr"); console.log("     relay: " + s.slice(0, 160)); assert.ok(s.length > 10 || (await p2.textContent("#auditOut")).length > 10); });
  if (OUT) await p2.screenshot({ path: OUT + "binance-relay-en.png", fullPage: true });
  const mob = await (await browser.newContext({ locale: "en-US", viewport: { width: 390, height: 844 }, isMobile: true })).newPage();
  await mob.goto(BASE + "/binance#detect");
  await t("mobile: brak poziomego przewijania", async () => assert.ok(await mob.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)));
  if (OUT) await mob.screenshot({ path: OUT + "binance-mobile.png", fullPage: true });
  await t("brak błędów JS / CSP", async () => assert.deepStrictEqual(errors.filter(e => !/451|Failed to load resource/.test(e)), []));
  await browser.close();
  console.log("wynik: " + ok + " OK, " + bad + " FAIL");
  process.exit(bad ? 1 : 0);
})();
