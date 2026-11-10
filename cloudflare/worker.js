// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Szlaban – front na Cloudflare Workers. Reverse proxy do backendu na Renderze.
// Nic nie jest cache'owane: kazde zapytanie idzie do backendu.
const ORIGIN = "https://szlaban.onrender.com";

// ---- Binance Guard: relay TYLKO DO ODCZYTU, obslugiwany na krawedzi Cloudflare (blisko uzytkownika) ----
// Ta sama walidacja co binance_relay.py. Przyjmuje gotowy podpis HMAC, NIGDY sekret. Nic nie loguje
// (zadnego console.log; dane ida tylko w tresci POST, nie w URL). Backend na Renderze stoi w USA, a Binance
// odrzuca stamtad zapytania (HTTP 451), dlatego relay dziala tutaj.
const BINANCE_API = "https://api.binance.com";
const BG_ENDPOINTS = {
  time: ["/api/v3/time", false],
  apiRestrictions: ["/sapi/v1/account/apiRestrictions", true],
  accountStatus: ["/sapi/v1/account/status", true],
  apiTradingStatus: ["/sapi/v1/account/apiTradingStatus", true],
  withdrawAddressList: ["/sapi/v1/capital/withdraw/address/list", true],
};
const BG_ALLOWED = new Set(["endpoint", "apiKey", "timestamp", "recvWindow", "signature"]);
const BG_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "X-Robots-Tag": "noindex",
  "X-BG-Relay": "cloudflare-edge",
};
const bgJson = (status, body) => new Response(JSON.stringify(body), { status, headers: BG_HEADERS });

function bgBuild(data, nowMs) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return { err: [400, "bad_request"] };
  for (const k of Object.keys(data)) if (!BG_ALLOWED.has(k)) return { err: [400, "bad_field"] };
  const ep = BG_ENDPOINTS[data.endpoint];
  if (typeof data.endpoint !== "string" || !Object.prototype.hasOwnProperty.call(BG_ENDPOINTS, data.endpoint)) return { err: [400, "endpoint_not_allowed"] };
  const [path, signed] = ep;
  if (!signed) return { url: BINANCE_API + path, headers: {} };
  const key = String(data.apiKey ?? ""), ts = String(data.timestamp ?? ""), rw = String(data.recvWindow ?? ""), sig = String(data.signature ?? "");
  if (!/^[A-Za-z0-9]{16,128}$/.test(key)) return { err: [400, "bad_api_key"] };
  if (!/^\d{13}$/.test(ts)) return { err: [400, "bad_timestamp"] };
  if (!/^\d{1,5}$/.test(rw) || +rw < 1 || +rw > 60000) return { err: [400, "bad_recv_window"] };
  if (!/^[0-9a-fA-F]{64}$/.test(sig)) return { err: [400, "bad_signature"] };
  if (Math.abs((nowMs ?? Date.now()) - Number(ts)) > 300000) return { err: [400, "stale_timestamp"] };
  return { url: `${BINANCE_API}${path}?timestamp=${ts}&recvWindow=${rw}&signature=${sig.toLowerCase()}`, headers: { "X-MBX-APIKEY": key } };
}

// Prosty limit na IP w pamieci izolatu (best effort; nic nie jest zapisywane trwale).
const bgHits = new Map();
function bgLimited(ip, now) {
  const win = 600000, max = 40;
  if (bgHits.size > 5000) bgHits.clear();
  const q = (bgHits.get(ip) || []).filter(t => now - t < win);
  const limited = q.length >= max;
  if (!limited) q.push(now);
  bgHits.set(ip, q);
  return limited;
}

async function bgRelay(request) {
  if (bgLimited(request.headers.get("CF-Connecting-IP") || "?", Date.now())) return bgJson(429, { error: "rate_limited" });
  const len = Number(request.headers.get("Content-Length") || "0");
  if (!(len >= 0) || len > 2048) return bgJson(413, { error: "too_large" });
  const ct = (request.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
  if (ct !== "application/json") return bgJson(415, { error: "json_required" });
  let data;
  try {
    const text = await request.text();
    if (text.length > 2048) return bgJson(413, { error: "too_large" });
    data = JSON.parse(text || "{}");
  } catch (e) {
    return bgJson(400, { error: "bad_json" });
  }
  const b = bgBuild(data);
  if (b.err) return bgJson(b.err[0], { error: b.err[1] });
  let resp, body;
  try {
    resp = await fetch(b.url, {
      method: "GET",
      headers: Object.assign({ "User-Agent": "szlaban-binance-guard/1.0", Accept: "application/json" }, b.headers),
      redirect: "manual",
      cf: { cacheTtl: 0, cacheEverything: false },
    });
    body = await resp.text();
  } catch (e) {
    return bgJson(502, { error: "upstream_unreachable" });
  }
  if (body.length > 524288) return bgJson(502, { error: "upstream_too_large" });
  let parsed = null;
  try { parsed = body ? JSON.parse(body) : null; } catch (e) { parsed = null; }
  const binErr = parsed && typeof parsed === "object" && Number.isInteger(parsed.code) && parsed.code < 0;
  if ((resp.status === 451 || resp.status === 403) && !binErr) return bgJson(451, { error: "geo_blocked" });
  if (resp.status >= 300 && resp.status < 400) return bgJson(502, { error: "upstream_redirect" });
  if (resp.status === 429 || resp.status === 418) return bgJson(429, { error: "binance_rate_limit" });
  if (resp.status !== 200) {
    if (parsed && typeof parsed === "object" && "code" in parsed)
      return bgJson(400, { error: "binance_error", binance_code: parsed.code, binance_msg: String(parsed.msg ?? "").slice(0, 300) });
    return bgJson(502, { error: "upstream_error" });
  }
  if (parsed === null) return bgJson(502, { error: "upstream_bad_json" });
  return bgJson(200, { data: parsed });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/api/binance/relay" && request.method === "POST") return bgRelay(request);
    const target = ORIGIN + url.pathname + url.search;

    const headers = new Headers(request.headers);
    headers.delete("host");
    headers.delete("cookie"); // aplikacja nie uzywa ciasteczek
    const ip = request.headers.get("CF-Connecting-IP");
    if (ip) headers.set("X-Forwarded-For", ip); // limit skanow per IP dziala dalej
    headers.set("X-Forwarded-Host", url.host);
    headers.set("X-Forwarded-Proto", "https");

    const init = {
      method: request.method,
      headers,
      redirect: "manual",
      cf: { cacheTtl: 0, cacheEverything: false },
    };
    if (!["GET", "HEAD"].includes(request.method)) init.body = request.body;

    let resp;
    try {
      resp = await fetch(target, init);
    } catch (e) {
      return new Response(JSON.stringify({ error: "Backend chwilowo niedostepny, sprobuj za minute." }), {
        status: 502,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    const out = new Headers(resp.headers);
    // przepisz ewentualne przekierowania na wlasny host
    const loc = out.get("Location");
    if (loc && loc.startsWith(ORIGIN)) out.set("Location", loc.slice(ORIGIN.length) || "/");
    if (url.pathname.startsWith("/api/") || url.pathname === "/healthz") out.set("Cache-Control", "no-store");
    out.delete("set-cookie");
    out.set("X-Served-By", "cloudflare-worker");
    return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: out });
  },
};
