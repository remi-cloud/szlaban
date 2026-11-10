// SPDX-License-Identifier: AGPL-3.0-only
// Szlaban – Binance Guard: wykrywacz fałszywego Binance (linki, nadawcy e-maili, treść SMS/e-mail).
// Copyright (C) 2026 Robi (@robi44610)
// Działa w całości w przeglądarce (offline). Nic nie jest wysyłane na serwer. Testy: tests/test_detector.js
"use strict";
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.BGDetector = factory();
})(typeof self !== "undefined" ? self : this, function () {
  // Domeny potwierdzone w oficjalnych źródłach Binance (lista w README, sekcja Binance Guard):
  //  binance.com  – główna domena (FAQ „How to Identify URL Spoof Phishing”, dokumentacja API)
  //  binance.info – oficjalne centrum pomocy i Binance Verify (www.binance.info/en/official-verification)
  //  binance.vision – oficjalne serwery API: testnet.binance.vision, data-api.binance.vision (dokumentacja API)
  const OFFICIAL = ["binance.com", "binance.info", "binance.vision"];
  // Domeny powiązane z marką, ale NIE potwierdzone przez to narzędzie – zawsze sprawdź w Binance Verify.
  const RELATED = ["binance.me", "binance.us", "binance.org", "bnbchain.org"];
  const VERIFY_URL = "https://www.binance.com/en/official-verification";
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "bl.ink", "short.io", "v.gd", "shorte.st", "adf.ly", "lnkd.in",
    "qrco.de", "tr.ee", "linktr.ee", "u.to", "clck.ru", "surl.li", "dub.sh", "t.cn", "url.cn", "dwz.cn"];
  const SUS_TLDS = ["xyz", "top", "click", "link", "live", "online", "site", "shop", "icu", "buzz", "tk", "ml", "ga", "cf",
    "gq", "work", "support", "rest", "cyou", "monster", "sbs", "cfd", "lol", "quest", "zip", "mov", "fit", "country",
    "kim", "men", "loan", "win", "bid", "vip", "app", "pro", "help", "security", "services", "network", "wang", "cn.com"];
  const MULTI_SUFFIX = ["co.uk", "org.uk", "com.au", "com.br", "com.cn", "com.hk", "com.tw", "co.jp", "co.kr", "com.tr",
    "com.mx", "co.in", "co.za", "com.sg", "com.pl", "net.pl", "org.pl", "com.ng", "com.ph", "co.id", "com.vn", "com.ar"];
  const COMMON_WORDS = ["finance", "balance", "binary", "bianca", "binaries", "bnance"];
  const BRAND = "binance";

  // ---------- punycode (RFC 3492) – tylko dekodowanie, do pokazania prawdziwej nazwy ----------
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    let n = 128, i = 0, bias = 72;
    const out = [];
    let b = input.lastIndexOf("-");
    if (b < 0) b = 0;
    for (let j = 0; j < b; j++) out.push(input.charCodeAt(j));
    const adapt = (delta, num, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / num);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
    };
    for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error("punycode");
        const c = input.charCodeAt(idx++);
        const d = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (d >= base) throw new Error("punycode");
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  const toUnicodeHost = h => h.split(".").map(l => {
    if (!l.startsWith("xn--")) return l;
    try { return punyDecode(l.slice(4)); } catch (e) { return l; }
  }).join(".");

  // ---------- szkielet znaków (homoglify) ----------
  const CONF = { "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d",
    "ѕ": "s", "һ": "h", "ո": "n", "ɑ": "a", "α": "a", "ο": "o", "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t",
    "ε": "e", "η": "n", "ı": "i", "ɩ": "i", "ŋ": "n", "ƅ": "b", "Ь": "b", "в": "b", "п": "n", "и": "n", "ɴ": "n",
    "0": "o", "1": "i", "l": "i", "!": "i", "|": "i", "3": "e", "4": "a", "@": "a", "5": "s", "$": "s", "8": "b", "6": "b" };
  function skeleton(s) {
    s = s.normalize("NFKC").toLowerCase().normalize("NFD").replace(/\p{M}/gu, "");
    let o = "";
    for (const ch of s) o += CONF[ch] !== undefined ? CONF[ch] : ch;
    return o.replace(/rn/g, "m").replace(/vv/g, "w");
  }
  function dist(a, b) {  // Damerau-Levenshtein (wariant OSA)
    const d = [];
    for (let i = 0; i <= a.length; i++) { d[i] = [i]; }
    for (let j = 0; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
      const c = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
    return d[a.length][b.length];
  }
  const endsWithDomain = (h, d) => h === d || h.endsWith("." + d);
  const isOfficial = h => OFFICIAL.some(d => endsWithDomain(h, d));
  const isRelated = h => RELATED.some(d => endsWithDomain(h, d));
  function registrable(h) {
    const p = h.split(".");
    const last2 = p.slice(-2).join(".");
    return MULTI_SUFFIX.includes(last2) && p.length >= 3 ? p.slice(-3).join(".") : last2;
  }

  // ---------- reguły tekstowe (EN / PL / ZH) ----------
  const CUES = [
    ["seed_phrase", 40, /seed\s*phrase|recovery\s*phrase|secret\s*phrase|mnemonic|private\s*key|\b(12|24)[\s-]*(words|słów|slow)|fraz[aęy]\s*(seed|odzyskiwania|tajn)|klucz(a)?\s*prywatn|助记词|私钥|恢复短语|种子短语/iu],
    ["codes", 35, /2fa\s*code|verification\s*code|authenticator\s*code|security\s*code|sms\s*code|one[-\s]*time\s*(pass|code)|\botp\b|google\s*auth|kod(u|em)?\s*(2fa|weryfikacyjn|sms|z\s*aplikacji|uwierzytelni|bezpiecze)|验证码|谷歌验证|动态码|安全码|身份验证器/iu],
    ["remote", 35, /anydesk|teamviewer|rustdesk|quicksupport|ultraviewer|remote\s*(access|desktop|control)|screen\s*shar|zdaln(y|ego)\s*(dost[eę]p|pulpit)|udost[eę]pnij\s*ekran|udost[eę]pnianie\s*ekranu|远程(控制|协助|桌面)|屏幕共享/iu],
    ["move_funds", 35, /safe\s*(wallet|account|address)|secure\s*(wallet|account)|transfer\s*(your|all)\s*(funds|assets|crypto)|move\s*your\s*(funds|assets)|bezpieczn(y|ego|e)\s*(portfel|konto|adres)|przel(ej|ać)\s*(środki|srodki|wszystk)|安全(钱包|账户|地址)|转移(资产|资金)/iu],
    ["password", 25, /(send|enter|confirm|share)\s*(us\s*)?(your\s*)?password|podaj\s*(swoje\s*)?hasło|wyślij\s*hasło|发送密码|提供密码|输入密码/iu],
    ["urgency", 15, /urgent|immediately|within\s*(24|48|12)\s*h|suspend|frozen|freez|locked|will\s*be\s*(closed|deleted|disabled)|final\s*warning|act\s*now|verify\s*now|pilne|natychmiast|w\s*ci[aą]gu\s*(24|48|12)|zawieszon|zablokowan|zamro[żz]|ostatnie\s*ostrze|紧急|立即|马上|冻结|暂停|封禁|24小时内|账户异常|最后警告/iu],
    ["giveaway", 20, /airdrop|giveaway|double\s*your|free\s*(bnb|btc|usdt|crypto)|reward\s*claim|claim\s*(your\s*)?(reward|bonus)|darmow(e|y)\s*(bnb|btc|usdt|krypto)|odbierz\s*(nagrod|bonus)|rozdanie|空投|赠送|免费领取|领取奖励|翻倍/iu],
    ["apk", 20, /\.apk\b|\bapk\b|sideload|instaluj\s*aplikacj[eę]\s*z\s*linku|安装包|下载.{0,6}(app|应用)/iu],
    ["call_number", 10, /call\s*(us|this\s*number|support)|whatsapp|telegram\s*support|zadzwo[ńn]|infolini|致电|拨打|客服电话/iu],
    ["verify_account", 10, /verify\s*your\s*(account|identity)|confirm\s*your\s*(account|identity)|kyc\s*update|zweryfikuj\s*(swoje\s*)?konto|potwierd[źz]\s*(swoj[aą]\s*)?to[żz]samo|验证(您的)?账户|身份认证|更新kyc/iu]
  ];

  const EMAIL_RE = /[\p{L}\p{N}._%+-]+@((?:[\p{L}\p{N}-]+\.)+[\p{L}\p{N}-]{2,})/gu;
  const SCHEME_URL_RE = /(?:(?:https?|hxxps?|ftp):\/\/|www\.)[^\s<>"'`]+/giu;
  const BARE_URL_RE = /(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,62})\.)+(?:xn--[a-z0-9-]{2,59}|\p{L}{2,63})(?::\d{2,5})?(?:[\/?#][^\s<>"'`]*)?/giu;
  const FILE_EXT = ["pdf", "doc", "docx", "txt", "jpg", "jpeg", "png", "gif", "js", "py", "htm", "html", "csv", "xls", "xlsx"];
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

  function hostCheck(rawHost, ctx) {
    // rawHost: jak w tekście; ctx.add(code, weight, params)
    const reasons = [];
    const add = (code, w, p) => reasons.push({ code, w, p: Object.assign({ host: rawHost }, p || {}) });
    let ascii;
    try { ascii = new URL("http://" + rawHost.replace(/\.$/, "")).hostname; } catch (e) { return { verdict: "invalid", reasons, host: rawHost }; }
    ascii = ascii.replace(/\.$/, "").toLowerCase();
    const uni = toUnicodeHost(ascii);
    if (IPV4.test(ascii) || ascii.startsWith("[")) { add("ip_host", 30); return { verdict: "suspicious", reasons, host: ascii, display: uni }; }
    if (isOfficial(ascii)) return { verdict: "official", reasons, host: ascii, display: uni };
    const idn = ascii.split(".").some(l => l.startsWith("xn--")) || /[^\x00-\x7f]/.test(rawHost);
    if (idn) add("idn_host", 25, { unicode: uni, ascii });
    if (isRelated(ascii)) { add("related_domain", 10, { domain: RELATED.find(d => endsWithDomain(ascii, d)) }); return { verdict: "related", reasons, host: ascii, display: uni }; }
    const sk = skeleton(uni);
    const labels = sk.split(".");
    if (ascii.includes(BRAND)) add("brand_in_host", 45);
    else if (sk.replace(/[.-]/g, "").includes(BRAND)) add("homoglyph", 50, { unicode: uni });
    else {
      const rawLabels = uni.toLowerCase().split(".");
      for (let li = 0; li < labels.length - 1; li++) for (const [pi, part] of labels[li].split("-").entries()) {
        const orig = (rawLabels[li] || "").split("-")[pi] || "";
        if (part.length < 5 || part.length > 10 || COMMON_WORDS.includes(part) || COMMON_WORDS.includes(orig)) continue;
        const dd = dist(part, BRAND);
        if (dd === 1 || (dd === 2 && part[0] === "b")) { add("typosquat", 40, { label: part }); break; }
      }
    }
    const tld = ascii.split(".").pop();
    if (SUS_TLDS.includes(tld)) add("sus_tld", 15, { tld });
    if (SHORTENERS.some(d => endsWithDomain(ascii, d))) add("shortener", 25);
    if (ascii.split(".").length > 4) add("many_subdomains", 10);
    if (ascii.length > 45) add("long_host", 5);
    const bad = reasons.some(r => r.w >= 25);
    return { verdict: bad ? "suspicious" : "unknown", reasons, host: ascii, display: uni, registrable: registrable(ascii) };
  }

  function analyze(input, mode) {
    const text = String(input || "").slice(0, 20000);
    const reasons = [];
    const hosts = [];
    const seen = new Set();
    const push = r => { const k = r.code + "|" + (r.p && (r.p.host || r.p.label || "")); if (!seen.has(k)) { seen.add(k); reasons.push(r); } };
    // 1) linki ze schematem (http://, https://, www.) – najpierw, żeby „binance.com@zly.host” nie udawał e-maila
    const cands = [];
    for (const m of text.matchAll(SCHEME_URL_RE)) cands.push(m[0]);
    let rest = text.replace(SCHEME_URL_RE, " ");
    // 2) adresy e-mail (nadawcy)
    const emails = [];
    for (const m of rest.matchAll(EMAIL_RE)) emails.push({ addr: m[0], host: m[1] });
    rest = rest.replace(EMAIL_RE, " ");
    const plain = rest.replace(BARE_URL_RE, " ");   // tekst bez linków i adresów – do szukania wzmianek o marce
    const mentionsBrand = /binance|币安|幣安/i.test(plain.normalize("NFKC"));
    // 3) gołe domeny (bez http://)
    for (const m of rest.matchAll(BARE_URL_RE)) {
      const tld = m[0].split(/[\/?#:]/)[0].split(".").pop().toLowerCase();
      if (!FILE_EXT.includes(tld)) cands.push(m[0]);
    }
    for (const e of emails) {
      const hc = hostCheck(e.host);
      hosts.push({ kind: "email", value: e.addr, host: hc.host, display: hc.display, verdict: hc.verdict });
      hc.reasons.forEach(push);
      if (hc.verdict === "official") push({ code: "sender_official_spoofable", w: 0, p: { host: hc.host } });
      else if (hc.verdict !== "invalid" && (mentionsBrand || hc.reasons.length)) push({ code: "sender_not_official", w: 30, p: { host: hc.host || e.host } });
    }
    for (const c0 of cands) {
      let cand = c0.replace(/[.,;:!?)\]}>»"'”’]+$/u, "");
      if (!cand.includes(".")) continue;
      const hasScheme = /^[a-z]+:\/\//i.test(cand);
      if (/^hxxps?:\/\//i.test(cand)) cand = cand.replace(/^hxxp/i, "http");
      let u;
      try { u = new URL(hasScheme ? cand : "http://" + cand); } catch (e) { continue; }
      const rawHost = (cand.replace(/^[a-z]+:\/\//i, "").split(/[\/?#]/)[0].split("@").pop() || "").replace(/:\d+$/, "");
      const hc = hostCheck(rawHost);
      if (hc.verdict === "invalid") continue;
      hosts.push({ kind: "url", value: cand, host: hc.host, display: hc.display, verdict: hc.verdict });
      hc.reasons.forEach(push);
      if (u.username || u.password) push({ code: "userinfo_trick", w: 30, p: { host: hc.host, user: decodeURIComponent(u.username) } });
      if (hc.verdict !== "official") {
        if (hasScheme && u.protocol === "http:") push({ code: "no_https", w: 10, p: { host: hc.host } });
        if (u.port && !["80", "443"].includes(u.port)) push({ code: "odd_port", w: 10, p: { host: hc.host, port: u.port } });
        if (/binance/i.test(decodeURIComponent(u.pathname + u.search))) push({ code: "brand_in_path", w: 15, p: { host: hc.host } });
      } else if (hasScheme && u.protocol === "http:") push({ code: "official_http", w: 5, p: { host: hc.host } });
    }
    // 4) treść
    const norm = text.normalize("NFKC");
    for (const [code, w, re] of CUES) if (re.test(norm)) push({ code: "cue_" + code, w, p: {} });
    const foreign = hosts.filter(h => h.verdict !== "official" && h.verdict !== "related");
    if (mentionsBrand && foreign.some(h => h.kind === "url"))
      push({ code: "brand_with_foreign_link", w: 20, p: { host: foreign.find(h => h.kind === "url").host } });
    if (!hosts.length && mode === "url") push({ code: "no_link_found", w: 0, p: {} });
    let score = Math.min(100, reasons.reduce((s, r) => s + r.w, 0));
    const allOfficial = hosts.length > 0 && hosts.every(h => h.verdict === "official");
    if (allOfficial && score < 20) reasons.push({ code: "official_only", w: 0, p: {} });
    const level = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 20 ? "medium" : "low";
    reasons.sort((a, b) => b.w - a.w);
    return { score, level, reasons, hosts, verifyUrl: VERIFY_URL };
  }

  return { analyze, hostCheck, skeleton, punyDecode, toUnicodeHost, dist, isOfficial, OFFICIAL, RELATED, VERIFY_URL };
});
