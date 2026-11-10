// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Robi (@robi44610)
// Szlaban – front na Cloudflare Workers. Reverse proxy do backendu na Renderze.
// Nic nie jest cache'owane: kazde zapytanie idzie do backendu.
const ORIGIN = "https://szlaban.onrender.com";

export default {
  async fetch(request) {
    const url = new URL(request.url);
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
