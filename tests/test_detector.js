// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Testy offline wykrywacza fałszywego Binance:  node tests/test_detector.js
"use strict";
const assert = require("assert");
const D = require("../static/bg-detector.js");
let ok = 0, bad = 0;
function t(name, fn) { try { fn(); ok++; console.log("OK   " + name); } catch (e) { bad++; console.log("FAIL " + name + ": " + e.message); } }
const codes = r => r.reasons.map(x => x.code);
const A = (text, mode) => D.analyze(text, mode);

t("oficjalny link binance.com", () => { const r = A("https://www.binance.com/en/my/security"); assert.strictEqual(r.score, 0); assert.ok(codes(r).includes("official_only")); assert.strictEqual(r.hosts[0].verdict, "official"); });
t("oficjalne binance.info i binance.vision", () => { for (const u of ["https://accounts.binance.info/en/login", "https://testnet.binance.vision/"]) assert.strictEqual(A(u).hosts[0].verdict, "official"); });
t("goła domena binance.com", () => assert.strictEqual(A("binance.com").score, 0));
t("subdomena-pułapka binance.com.evil.io", () => { const r = A("https://binance.com.security-check.io/login"); assert.ok(codes(r).includes("brand_in_host")); assert.ok(r.score >= 45); });
t("binance-login.com", () => { const r = A("binance-login.com/verify"); assert.ok(codes(r).includes("brand_in_host")); assert.notStrictEqual(r.level, "low"); });
t("myślnik w końcówce binance.com-verify.top", () => { const r = A("http://binance.com-verify.top"); assert.ok(codes(r).includes("brand_in_host")); assert.ok(codes(r).includes("sus_tld")); assert.ok(codes(r).includes("no_https")); assert.strictEqual(r.level, "high"); });
t("cyrylickie і (homoglif, punycode)", () => { const r = A("https://bіnance.com"); assert.ok(codes(r).includes("homoglyph")); assert.ok(codes(r).includes("idn_host")); assert.ok(r.hosts[0].host.startsWith("xn--")); });
t("xn-- w tekście dekodowany", () => { const r = A("http://xn--bnance-pvf.com"); assert.ok(codes(r).includes("homoglyph")); const reason = r.reasons.find(x => x.code === "idn_host"); assert.strictEqual(reason.p.unicode, "bіnance.com"); });
t("cyfra zamiast litery b1nance.com", () => assert.ok(codes(A("b1nance.com")).includes("homoglyph")));
t("rn zamiast m / literówka binnance", () => { assert.ok(codes(A("binnance.io")).includes("typosquat")); assert.ok(codes(A("https://binanse.net")).includes("typosquat")); assert.ok(codes(A("biance.com")).includes("typosquat")); });
t("finance.yahoo.com to nie literówka", () => { const r = A("https://finance.yahoo.com"); assert.strictEqual(r.score, 0); assert.ok(!codes(r).includes("typosquat")); });
t("balance.com to nie literówka", () => assert.ok(!codes(A("https://balance.com")).includes("typosquat")));
t("trik z @ w linku", () => { const r = A("https://binance.com@evil.xyz/login"); assert.ok(codes(r).includes("userinfo_trick")); assert.strictEqual(r.hosts[0].host, "evil.xyz"); assert.ok(r.score >= 30); });
t("skracacz linków", () => assert.ok(codes(A("Click bit.ly/3xYz now")).includes("shortener")));
t("adres IP", () => assert.ok(codes(A("http://185.12.3.4/binance/login")).includes("ip_host")));
t("binance w ścieżce obcej strony", () => assert.ok(codes(A("https://example.org/binance.com/login")).includes("brand_in_path")));
t("dziwny port", () => assert.ok(codes(A("https://secure-wallet.example:8443/x")).includes("odd_port")));
t("domena powiązana binance.me", () => { const r = A("https://accounts.binance.me/en/register"); assert.strictEqual(r.hosts[0].verdict, "related"); assert.ok(r.score < 20); });
t("SMS EN: seed + 2FA + pilność + skracacz = krytyczne", () => {
  const r = A("Binance: Your account will be suspended within 24 hours. Reply with your 2FA code and 12-word seed phrase at bit.ly/bnb-help");
  ["cue_seed_phrase", "cue_codes", "cue_urgency", "shortener", "brand_with_foreign_link"].forEach(c => assert.ok(codes(r).includes(c), c));
  assert.strictEqual(r.level, "critical"); });
t("SMS PL: zablokowane + AnyDesk + bezpieczny portfel", () => {
  const r = A("Pilne! Twoje konto Binance zostanie zablokowane. Zainstaluj AnyDesk, a nasz konsultant przeleje środki na bezpieczny portfel.");
  ["cue_urgency", "cue_remote", "cue_move_funds"].forEach(c => assert.ok(codes(r).includes(c), c)); assert.ok(r.score >= 75); });
t("SMS ZH: 冻结 + 验证码 + obcy link", () => {
  const r = A("【币安】您的账户异常，将在24小时内冻结，请立即点击 http://binance-cn.vip 输入验证码");
  ["cue_urgency", "cue_codes", "brand_in_host", "sus_tld", "no_https"].forEach(c => assert.ok(codes(r).includes(c), c)); assert.strictEqual(r.level, "critical"); });
t("e-mail od nieoficjalnej domeny", () => { const r = A("From: Binance Support <support@binance-help.top>\nPlease verify your account"); assert.ok(codes(r).includes("sender_not_official")); assert.ok(codes(r).includes("cue_verify_account")); });
t("e-mail z oficjalnej domeny – ostrzeżenie o podrabianiu nadawcy", () => { const r = A("From: Binance <do-not-reply@ses.binance.com>\nWithdrawal successful"); assert.ok(codes(r).includes("sender_official_spoofable")); assert.strictEqual(r.score, 0); });
t("giveaway + apk", () => { const r = A("Free BNB airdrop! Download binance-pro.apk from our site"); assert.ok(codes(r).includes("cue_giveaway")); assert.ok(codes(r).includes("cue_apk")); });
t("pliki .pdf nie są domenami", () => assert.strictEqual(A("See report.pdf for details").hosts.length, 0));
t("tryb link bez linku", () => assert.ok(codes(A("hello there", "url")).includes("no_link_found")));
t("pusty tekst", () => { const r = A(""); assert.strictEqual(r.score, 0); assert.strictEqual(r.hosts.length, 0); });
t("wynik ograniczony do 100", () => assert.ok(A("Binance urgent seed phrase 2FA code AnyDesk safe wallet password free BNB airdrop http://binance-x.top bit.ly/a http://1.2.3.4").score <= 100));
t("punycode RFC 3492 (przykład z RFC: bücher)", () => assert.strictEqual(D.punyDecode("bcher-kva"), "bücher"));
t("odległość Damerau", () => { assert.strictEqual(D.dist("binance", "binnace"), 1); assert.strictEqual(D.dist("binance", "biannce"), 1); });
t("lista oficjalnych domen nie zawiera niezweryfikowanych", () => assert.deepStrictEqual(D.OFFICIAL, ["binance.com", "binance.info", "binance.vision"]));
console.log("wynik: " + ok + " OK, " + bad + " FAIL");
process.exit(bad ? 1 : 0);
