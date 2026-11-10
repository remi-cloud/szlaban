// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Testy offline Binance Guard (podpis HMAC, ocena klucza, porównanie adresów, kompletność tłumaczeń):
//   node tests/test_bg_core.js      (Node >= 20: WebCrypto w globalThis.crypto)
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const C = require("../static/bg-core.js");
const I = require("../static/bg-i18n.js");
let ok = 0, bad = 0;
async function t(name, fn) { try { await fn(); ok++; console.log("OK   " + name); } catch (e) { bad++; console.log("FAIL " + name + ": " + e.message); } }
const NOW = Date.UTC(2026, 10, 10);
const DAY = 86400000;
const READONLY = { ipRestrict: false, createTime: NOW - 10 * DAY, enableWithdrawals: false, enableInternalTransfer: false,
  permitsUniversalTransfer: false, enableVanillaOptions: false, enableReading: true, enableFutures: false, enableMargin: false,
  enableSpotAndMarginTrading: false, tradingAuthorityExpirationTime: 0 };
const ids = r => r.findings.map(f => f.id);

(async () => {
  // Wektory testowe z oficjalnej dokumentacji Binance (binance-spot-api-docs, rest-api.md, "HMAC Keys").
  const SECRET = "NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j";
  await t("HMAC – wektor 1 z dokumentacji Binance", async () => assert.strictEqual(await C.hmacHex(SECRET,
    "symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=0.1&recvWindow=5000&timestamp=1499827319559"),
    "c8db56825ae71d6d79447849e617115f4a920fa2acdcab2b053c4b2838bd6b71"));
  await t("HMAC – wektor 2 (znaki spoza ASCII) z dokumentacji Binance", async () => assert.strictEqual(await C.hmacHex(SECRET,
    "symbol=%EF%BC%91%EF%BC%92%EF%BC%93%EF%BC%94%EF%BC%95%EF%BC%96&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=0.1&recvWindow=5000&timestamp=1499827319559"),
    "e1353ec6b14d888f1164ae9af8228a3dbd508bc82eb867db8ab6046442f33ef3"));
  await t("signRequest: kolejność i brak sekretu w wyniku", async () => {
    const r = await C.signRequest("apiRestrictions", "k".repeat(64), SECRET, 1499827319559, 10000);
    assert.deepStrictEqual(Object.keys(r).sort(), ["apiKey", "endpoint", "recvWindow", "signature", "timestamp"]);
    assert.ok(!JSON.stringify(r).includes(SECRET));
    assert.strictEqual(r.signature, await C.hmacHex(SECRET, "timestamp=1499827319559&recvWindow=10000"));
  });
  await t("ocena: klucz tylko do odczytu, świeży, bez IP = średnie", async () => {
    const r = C.evaluateKey(READONLY, { data: "Normal" }, null, NOW);
    assert.strictEqual(r.overall, "medium"); assert.ok(ids(r).includes("read_only")); assert.ok(ids(r).includes("ip_off")); assert.ok(ids(r).includes("account_normal"));
  });
  await t("ocena: tylko odczyt + IP = OK", async () => assert.strictEqual(C.evaluateKey(Object.assign({}, READONLY, { ipRestrict: true }), null, null, NOW).overall, "ok"));
  await t("ocena: wypłaty włączone = krytyczne", async () => {
    const r = C.evaluateKey(Object.assign({}, READONLY, { enableWithdrawals: true, ipRestrict: true }), null, null, NOW);
    assert.strictEqual(r.overall, "critical"); assert.strictEqual(r.findings[0].id, "withdrawals_on");
  });
  await t("ocena: handel futures + brak IP = wysokie (oba)", async () => {
    const r = C.evaluateKey(Object.assign({}, READONLY, { enableFutures: true }), null, null, NOW);
    assert.strictEqual(r.overall, "high"); assert.ok(r.findings.some(f => f.id === "trading_on" && f.params.perm === "enableFutures"));
    assert.strictEqual(r.findings.find(f => f.id === "ip_off").level, "high");
  });
  await t("ocena: transfer uniwersalny = wysokie", async () => assert.ok(C.evaluateKey(Object.assign({}, READONLY, { permitsUniversalTransfer: true, ipRestrict: true }), null, null, NOW)
    .findings.some(f => f.id === "transfer_on" && f.level === "high")));
  await t("ocena: wiek klucza 400 dni = średnie, 120 dni = niskie", async () => {
    assert.strictEqual(C.evaluateKey(Object.assign({}, READONLY, { ipRestrict: true, createTime: NOW - 400 * DAY }), null, null, NOW).findings.find(f => f.id === "key_old").params.days, 400);
    assert.ok(ids(C.evaluateKey(Object.assign({}, READONLY, { ipRestrict: true, createTime: NOW - 120 * DAY }), null, null, NOW)).includes("key_aging"));
  });
  await t("ocena: nienormalny status konta = wysokie", async () => assert.strictEqual(C.evaluateKey(Object.assign({}, READONLY, { ipRestrict: true }), { data: "Locked" }, null, NOW).overall, "high"));
  await t("ocena: zablokowany handel API", async () => assert.ok(ids(C.evaluateKey(READONLY, null, { data: { isLocked: true, plannedRecoverTime: NOW } }, NOW)).includes("api_trading_locked")));

  const L1 = [
    { coin: "BTC", network: "BTC", address: "bc1qxyz", addressTag: "", name: "Ledger", whiteStatus: true, origin: "", originType: "" },
    { coin: "USDT", network: "TRX", address: "TXabc", addressTag: "", name: "Kantor", whiteStatus: true, origin: "", originType: "" },
    { coin: "XRP", network: "XRP", address: "rXRP1", addressTag: "123", name: "", whiteStatus: false, origin: "", originType: "" }];
  for (const mode of ["hash", "data"]) {
    await t("baseline (" + mode + "): bez zmian", async () => { const b = await C.makeBaseline(L1, mode, NOW); const d = await C.diffBaseline(b, L1); assert.strictEqual(d.alert, false); assert.strictEqual(d.unchanged, 3); });
    await t("baseline (" + mode + "): nowy, zmieniony, usunięty, biała lista", async () => {
      const b = await C.makeBaseline(L1, mode, NOW);
      const L2 = [Object.assign({}, L1[0], { address: "bc1qATTACKER" }), Object.assign({}, L1[1], { whiteStatus: false }),
        { coin: "ETH", network: "ETH", address: "0xEvil", addressTag: "", name: "New", whiteStatus: true }];
      const d = await C.diffBaseline(b, L2);
      assert.strictEqual(d.alert, true);
      assert.strictEqual(d.changed.length, 1); assert.strictEqual(d.changed[0].now.address, "bc1qATTACKER");
      assert.strictEqual(d.added.length, 1); assert.strictEqual(d.added[0].address, "0xEvil");
      assert.strictEqual(d.removed.length, 1); assert.strictEqual(d.whiteChanged.length, 1);
      if (mode === "hash") { assert.strictEqual(d.removed[0], null); assert.ok(!JSON.stringify(b).includes("bc1qxyz")); }
      else { assert.strictEqual(d.removed[0].address, "rXRP1"); assert.strictEqual(d.changed[0].before.address, "bc1qxyz"); }
    });
  }

  await t("tłumaczenia: EN/PL/ZH mają te same klucze i brak pustych", async () => {
    const k = Object.keys(I.en).sort();
    for (const l of ["pl", "zh"]) { assert.deepStrictEqual(Object.keys(I[l]).sort(), k, l); for (const x of k) assert.ok(String(I[l][x]).trim(), l + ":" + x); }
    for (const l of I.LANGS) for (const x of k) {
      const ph = s => (String(s).match(/\{\w+\}/g) || []).sort().join(",");
      assert.strictEqual(ph(I[l][x]), ph(I.en[x]), "placeholdery " + l + ":" + x);
    }
  });
  await t("tłumaczenia: każdy klucz użyty w HTML/JS istnieje", async () => {
    const st = path.join(__dirname, "..", "static");
    const html = fs.readFileSync(path.join(st, "binance.html"), "utf8");
    const used = new Set([...html.matchAll(/data-i18n(?:-ph)?="(\w+)"/g)].map(m => m[1]));
    const js = fs.readFileSync(path.join(st, "binance.js"), "utf8");
    for (const m of js.matchAll(/\bt\("(\w+)"(?!\s*\+)/g)) used.add(m[1]);
    for (const v of ["official", "related", "suspicious", "unknown", "invalid"]) used.add("v_" + v);
    for (const v of ["hash", "data"]) used.add("mode_" + v);
    for (const m of js.matchAll(/"(chk_\w+)"/g)) used.add(m[1]);
    const det = fs.readFileSync(path.join(st, "bg-detector.js"), "utf8");
    for (const m of det.matchAll(/(?:add|push)\(\{?\s*(?:code:\s*)?"(\w+)"(?!\s*\+)/g)) used.add("r_" + m[1]);
    for (const m of det.matchAll(/\["(\w+)", \d+, \//g)) used.add("r_cue_" + m[1]);
    const core = fs.readFileSync(path.join(st, "bg-core.js"), "utf8");
    for (const m of core.matchAll(/add\("(\w+)"/g)) used.add("f_" + m[1]);
    for (const m of core.matchAll(/"(enable\w+|permits\w+)"/g)) used.add("perm_" + m[1]);
    for (const lv of ["critical", "high", "medium", "low", "ok"]) used.add("lvl_" + lv);
    const missing = [...used].filter(k => !(k in I.en));
    assert.deepStrictEqual(missing, []);
    assert.ok(used.size > 120, "za mało kluczy znalezionych: " + used.size);
  });
  await t("zastrzeżenie o braku powiązania z Binance we wszystkich językach", async () => {
    assert.ok(/not affiliated/i.test(I.en.disclaimer)); assert.ok(/nie jest powiązane/i.test(I.pl.disclaimer)); assert.ok(/没有任何关联/.test(I.zh.disclaimer));
  });
  console.log("wynik: " + ok + " OK, " + bad + " FAIL");
  process.exit(bad ? 1 : 0);
})();
