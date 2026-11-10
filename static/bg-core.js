// SPDX-License-Identifier: AGPL-3.0-only
// Szlaban – Binance Guard: podpis HMAC w przeglądarce, ocena uprawnień klucza, porównanie adresów.
// Copyright (C) 2026 Robi (@robi44610)
// Ten plik działa w przeglądarce i w Node (testy). Bez zależności zewnętrznych.
"use strict";
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.BGCore = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const subtle = () => (globalThis.crypto && globalThis.crypto.subtle) || null;
  const enc = s => new TextEncoder().encode(s);
  const hex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, "0")).join("");

  // HMAC-SHA256(secret, payload) -> hex. Klucz importowany jako NIEEKSPORTOWALNY.
  async function hmacHex(secret, payload) {
    const s = subtle();
    if (!s) throw new Error("webcrypto_unavailable");
    const key = await s.importKey("raw", enc(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return hex(await s.sign("HMAC", key, enc(payload)));
  }
  async function sha256Hex(text) {
    const s = subtle();
    if (!s) throw new Error("webcrypto_unavailable");
    return hex(await s.digest("SHA-256", enc(text)));
  }

  // Zawsze ta sama kolejność co w relay (binance_relay.py / worker.js).
  const signPayload = (timestamp, recvWindow) => "timestamp=" + timestamp + "&recvWindow=" + recvWindow;
  async function signRequest(endpoint, apiKey, secret, timestamp, recvWindow) {
    const signature = await hmacHex(secret, signPayload(timestamp, recvWindow));
    return { endpoint, apiKey, timestamp: String(timestamp), recvWindow: String(recvWindow), signature };
  }

  const DAY = 86400000;
  const RANK = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  // Ocena odpowiedzi GET /sapi/v1/account/apiRestrictions (+ opcjonalnie status konta i API trading).
  function evaluateKey(p, accountStatus, tradingStatus, nowMs) {
    nowMs = nowMs || Date.now();
    const f = [];
    const add = (id, level, params) => f.push({ id, level, params: params || {} });
    const trading = ["enableSpotAndMarginTrading", "enableMargin", "enableFutures",
      "enablePortfolioMarginTrading", "enableVanillaOptions"].filter(k => p[k] === true);
    const moving = ["permitsUniversalTransfer", "enableInternalTransfer"].filter(k => p[k] === true);
    if (p.enableWithdrawals === true) add("withdrawals_on", "critical");
    else add("withdrawals_off", "ok");
    for (const k of moving) add("transfer_on", "high", { perm: k });
    for (const k of trading) add("trading_on", "high", { perm: k });
    if (!trading.length && !moving.length && p.enableWithdrawals !== true) add("read_only", "ok");
    if (p.ipRestrict === true) add("ip_on", "ok");
    else add("ip_off", (p.enableWithdrawals || trading.length || moving.length) ? "high" : "medium");
    if (typeof p.createTime === "number" && p.createTime > 0) {
      const days = Math.floor((nowMs - p.createTime) / DAY);
      if (days > 365) add("key_old", "medium", { days });
      else if (days > 90) add("key_aging", "low", { days });
      else add("key_fresh", "ok", { days });
    }
    if (typeof p.tradingAuthorityExpirationTime === "number" && p.tradingAuthorityExpirationTime > 0 && trading.length)
      add("trading_expiry", "low", { ts: p.tradingAuthorityExpirationTime });
    if (p.enableReading === false) add("reading_off", "low");
    if (accountStatus && typeof accountStatus.data === "string") {
      if (accountStatus.data.toLowerCase() === "normal") add("account_normal", "ok");
      else add("account_abnormal", "high", { status: accountStatus.data });
    }
    if (tradingStatus && tradingStatus.data && tradingStatus.data.isLocked === true)
      add("api_trading_locked", "medium", { ts: tradingStatus.data.plannedRecoverTime || 0 });
    let overall = "ok";
    for (const x of f) if (RANK[x.level] > RANK[overall]) overall = x.level;
    f.sort((a, b) => RANK[b.level] - RANK[a.level]);
    return { overall, findings: f };
  }

  // Adresy wypłat: odcisk wpisu i porównanie z punktem odniesienia (baseline).
  const norm = v => String(v === undefined || v === null ? "" : v).trim();
  const entryId = a => [norm(a.coin).toUpperCase(), norm(a.network).toUpperCase(), norm(a.address), norm(a.addressTag)].join("|");
  const nameId = a => [norm(a.coin).toUpperCase(), norm(a.network).toUpperCase(), norm(a.name)].join("|");

  // mode "data": pełne wpisy (tylko w tej przeglądarce); mode "hash": tylko skróty SHA-256.
  async function makeBaseline(list, mode, nowMs) {
    const items = [];
    for (const a of list) {
      const it = { id: await sha256Hex(entryId(a)), nid: await sha256Hex(nameId(a)), white: a.whiteStatus === true };
      if (mode === "data") it.entry = { coin: norm(a.coin), network: norm(a.network), address: norm(a.address),
        addressTag: norm(a.addressTag), name: norm(a.name), whiteStatus: a.whiteStatus === true };
      items.push(it);
    }
    return { v: 1, mode: mode === "data" ? "data" : "hash", created: nowMs || Date.now(), count: list.length, items };
  }

  async function diffBaseline(baseline, list) {
    const cur = [];
    for (const a of list) cur.push({ id: await sha256Hex(entryId(a)), nid: await sha256Hex(nameId(a)), a });
    const oldIds = new Set(baseline.items.map(i => i.id));
    const curIds = new Set(cur.map(c => c.id));
    const oldByNid = new Map(baseline.items.map(i => [i.nid, i]));
    const out = { added: [], removed: [], changed: [], whiteChanged: [], unchanged: 0 };
    const changedOld = new Set();
    for (const c of cur) {
      if (oldIds.has(c.id)) {
        const o = baseline.items.find(i => i.id === c.id);
        if (o && o.white !== (c.a.whiteStatus === true)) out.whiteChanged.push({ now: c.a, before: o.white });
        else out.unchanged++;
        continue;
      }
      const o = oldByNid.get(c.nid);
      if (o && !curIds.has(o.id) && norm(c.a.name)) { out.changed.push({ now: c.a, before: o.entry || null }); changedOld.add(o.id); }
      else out.added.push(c.a);
    }
    for (const o of baseline.items) if (!curIds.has(o.id) && !changedOld.has(o.id)) out.removed.push(o.entry || null);
    out.alert = out.added.length + out.removed.length + out.changed.length + out.whiteChanged.length > 0;
    return out;
  }

  return { hmacHex, sha256Hex, signPayload, signRequest, evaluateKey, makeBaseline, diffBaseline, entryId, RANK };
});
