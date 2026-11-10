// SPDX-License-Identifier: AGPL-3.0-only
// Szlaban – Binance Guard, moduł 4: RE (statyczna analiza) + Blue Team (pułapki, puste aliasy, raport).
// Copyright (C) 2026 Robi (@robi44610). Wyłącznie obrona: nic nie jest uruchamiane, nic nie dotyka środków.
"use strict";
(function () {
  const $ = id => document.getElementById(id);
  const U = window.BGUI, D = window.BGDetector;
  const { t, el, clear, fmtDate } = U;
  const LS_TRAPS = "bg.traps.v1";
  const MAX = 20 * 1024 * 1024;
  let lastRe = null, lastTrap = null, lastHard = null;
  const hits = {};

  const err = (box, msg) => { const b = $(box); clear(b); if (msg) { b.textContent = msg; b.classList.add("on"); } else b.classList.remove("on"); };
  const errMsg = (code, status) => code === "too_large" ? t("re_too_big") : code === "busy" ? t("re_busy")
    : code === "rate_limited" ? t("err_rate") : t("err_other", { msg: code || ("HTTP " + status) });
  async function postJSON(url, body) {
    const r = await fetch(url, { method: "POST", cache: "no-store", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    let j = null; try { j = await r.json(); } catch (e) { /* brak */ }
    return { ok: r.ok, status: r.status, j: j || {} };
  }

  // ---------- A. RE ----------
  $("reRun").addEventListener("click", async () => {
    err("reErr", ""); clear($("reOut")); lastRe = null;
    const f = $("reFile").files[0];
    let body, name;
    if (f) { if (f.size > MAX) return err("reErr", t("re_too_big")); body = f; name = f.name; }
    else if ($("reText").value.trim()) { body = new Blob([$("reText").value], { type: "text/plain" }); name = "pasted.txt"; }
    else return;
    $("reRun").disabled = true; $("reStatus").textContent = t("running");
    try {
      const r = await fetch("/api/re/analyze", { method: "POST", cache: "no-store", credentials: "omit",
        headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(name) }, body });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) return err("reErr", errMsg(j.error, r.status));
      lastRe = j; renderRe(j);
    } catch (e) { err("reErr", t("err_net", { msg: e.message })); }
    finally { $("reRun").disabled = false; $("reStatus").textContent = ""; }
  });
  function sevOf(s) { return s === "high" ? "high" : s === "medium" ? "medium" : "low"; }
  function renderRe(r) {
    const o = $("reOut"); clear(o);
    // domeny i linki z pliku sprawdzamy tym samym wykrywaczem co moduł 3 (offline)
    const extra = [], seen = new Set();
    const hostsFrom = [...r.iocs.domains, ...r.iocs.urls.map(u => { try { return new URL(u).hostname; } catch (e) { return ""; } }), ...r.iocs.emails.map(e => e.split("@")[1])];
    for (const h of hostsFrom) {
      if (!h || seen.has(h)) continue; seen.add(h);
      const hc = D.hostCheck(h);
      const bad = hc.reasons.filter(x => x.w >= 25);
      if (bad.length) extra.push({ code: "lookalike", severity: "high", params: { host: hc.display || hc.host, why: t("r_" + bad[0].code, bad[0].p) } });
    }
    const all = [...extra, ...r.indicators];
    const score = Math.min(100, r.score + 30 * extra.length);
    const lvl = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 20 ? "medium" : "low";
    o.append(el("div", { class: "bg-overall" }, t("re_score") + ": " + score + "/100 ", el("span", { class: "lv lv-" + lvl }, t("lvl_" + lvl))));
    o.append(el("div", { class: "kv" },
      el("b", null, t("re_type")), el("span", null, t("t_" + r.type) + (r.name ? " · " + r.name : "")),
      el("b", null, t("re_size")), el("span", null, r.size.toLocaleString() + " B"),
      el("b", null, "SHA-256"), el("span", { class: "addr" }, r.sha256),
      el("b", null, "SHA-1"), el("span", { class: "addr" }, r.sha1),
      el("b", null, "MD5"), el("span", { class: "addr" }, r.md5)));
    o.append(el("p", { class: "small" }, el("a", { href: r.virustotal, target: "_blank", rel: "noopener noreferrer" }, t("re_vt"))));
    o.append(el("h3", null, t("re_ind")));
    const ul = el("ul", { class: "findings" });
    for (const i of all) {
      const p = Object.assign({}, i.params);
      if (p.items && i.code.startsWith("apk_")) p.items = p.items.split(", ").map(g => t("pg_" + g)).join(", ");
      if (p.kind) p.kind = t("t_" + p.kind);
      ul.append(el("li", { class: "l-" + sevOf(i.severity) }, el("div", { class: "ft" }, el("span", { class: "lv lv-" + sevOf(i.severity) }, t("lvl_" + sevOf(i.severity))), t("ri_" + i.code, p))));
    }
    if (!all.length) ul.append(el("li", { class: "l-ok" }, t("re_none")));
    o.append(ul);
    if (r.apk) o.append(el("div", { class: "kv" }, el("b", null, t("re_apk")), el("span", { class: "addr" }, r.apk.package || "?"),
      el("b", null, t("re_perms")), el("span", { class: "addr" }, (r.apk.permissions || []).join(", ") || "–")));
    if (r.ipa) o.append(el("div", { class: "kv" }, el("b", null, t("re_ipa")), el("span", { class: "addr" }, r.ipa.bundle_id + " (" + r.ipa.name + ")")));
    if (r.zip) o.append(el("details", null, el("summary", null, t("re_zip") + " (" + r.zip.entries + ")"), el("ul", { class: "small addr" }, ...r.zip.sample.map(n => el("li", null, n)))));
    o.append(el("h3", null, t("re_iocs")));
    const lists = [["re_urls", r.iocs.urls], ["re_domains", r.iocs.domains], ["re_ips", r.iocs.ips], ["re_emails", r.iocs.emails],
      ["re_wallets", r.iocs.wallets.map(w => w.kind.toUpperCase() + " " + w.value)], ["re_tg", r.iocs.telegram], ["re_hooks", r.iocs.webhooks]];
    for (const [k, arr] of lists) if (arr.length) o.append(el("details", { class: "ioc" }, el("summary", null, t(k) + " (" + arr.length + ")"), el("ul", { class: "small addr" }, ...arr.map(v => el("li", null, v)))));
  }

  // ---------- B. pułapki ----------
  const traps = () => { try { const v = JSON.parse(localStorage.getItem(LS_TRAPS) || "[]"); return Array.isArray(v) ? v : []; } catch (e) { return []; } };
  const saveTraps = a => { try { localStorage.setItem(LS_TRAPS, JSON.stringify(a.slice(-50))); } catch (e) { /* brak */ } };
  const rnd = (n, abc) => { const a = new Uint32Array(n); crypto.getRandomValues(a); return Array.from(a, x => abc[x % abc.length]).join(""); };
  const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  // Wszystkie wartości są fałszywe i zawierają znacznik SZLD; „klucze” i „adresy” to aliasy na link-pułapkę.
  function decoyFiles(tr) {
    const d = new Date(tr.created || Date.now()).toISOString().slice(0, 10);
    const keys = "Binance API backup  (" + d + ")\n\nAPI Key:    " + "SZLD" + rnd(60, ALNUM) + "\nSecret Key: " + "SZLD" + rnd(60, ALNUM) +
      "\n\nIP whitelist / key manager: " + tr.urls.restore + "\nWithdrawal address book:    " + tr.urls.wallet +
      "\nREST endpoint (test):       " + tr.urls.api + "\n\nref SZLD-" + tr.id + "\n";
    const blocks = Array.from({ length: 12 }, () => rnd(4, B32) + "-" + rnd(4, B32)).join(" ");
    const seed = "Wallet recovery backup (encrypted)  " + d + "\n\n" + blocks + "\n\nThe recovery phrase above is encrypted.\nDecrypt / restore: " +
      tr.urls.restore + "\n\nref SZLD-" + tr.id + "\n";
    return { keys, seed, bug: '<img src="' + tr.urls.gif + '" width="1" height="1" alt="">' };
  }
  function dl(name, text) {
    const a = el("a", { href: URL.createObjectURL(new Blob([text], { type: "text/plain" })), download: name, class: "ghostlink" }, t("trap_dl") + " " + name);
    return a;
  }
  const viewLink = tr => location.origin + "/binance#trap=" + tr.id + "." + tr.key;
  $("trapNew").addEventListener("click", async () => {
    err("trapErr", "");
    $("trapNew").disabled = true;
    try {
      const r = await postJSON("/api/trap/new", { label: $("trapLabel").value.trim(), kind: "file" });
      if (!r.ok) return err("trapErr", errMsg(r.j.error, r.status));
      const tr = { id: r.j.id, key: r.j.key, label: $("trapLabel").value.trim(), created: Date.now(), urls: r.j.urls };
      const all = traps(); all.push(tr); saveTraps(all);
      lastTrap = tr; renderTrap(tr); renderList();
    } catch (e) { err("trapErr", t("err_net", { msg: e.message })); }
    finally { $("trapNew").disabled = false; }
  });
  function renderTrap(tr) {
    const o = $("trapOut"); clear(o);
    if (!tr) return;
    const f = decoyFiles(tr);
    o.append(el("div", { class: "diff-ok" }, t("trap_created")),
      el("p", { class: "small" }, el("b", null, t("trap_view"))), el("div", { class: "copybox" }, viewLink(tr)),
      el("h3", null, t("trap_files")),
      el("div", { class: "bg-actions" }, dl(t("trap_file_keys"), f.keys), dl(t("trap_file_seed"), f.seed)),
      el("p", { class: "small" }, el("b", null, t("trap_url"))), el("div", { class: "copybox" }, tr.urls.restore),
      el("p", { class: "small" }, el("b", null, t("trap_api"))), el("div", { class: "copybox" }, tr.urls.api),
      el("p", { class: "small" }, el("b", null, t("trap_bug"))), el("div", { class: "copybox" }, f.bug));
  }
  function renderList() {
    const o = $("trapList"); clear(o);
    for (const tr of traps().slice().reverse()) {
      const res = el("div", { class: "small" });
      const h = hits[tr.id];
      if (h === null) res.append(t("trap_gone"));
      else if (h) {
        if (!h.length) res.append(t("trap_nohits"));
        else { res.append(el("b", { class: "warn" }, t("trap_hits", { count: h.length })));
          res.append(el("ul", null, ...h.map(x => el("li", { class: "addr" }, t("trap_hit_row", { date: fmtDate(x.ts * 1000), ip: x.ip, ua: x.ua || "–", path: x.path || "/" }))))); }
      }
      const chk = el("button", { type: "button", class: "ghost" }, t("trap_check"));
      chk.addEventListener("click", async () => {
        const r = await postJSON("/api/trap/hits", { id: tr.id, key: tr.key });
        hits[tr.id] = r.ok ? r.j.hits : null; renderList();
      });
      const del = el("button", { type: "button", class: "ghost" }, t("trap_del"));
      del.addEventListener("click", async () => {
        await postJSON("/api/trap/delete", { id: tr.id, key: tr.key });
        saveTraps(traps().filter(x => x.id !== tr.id)); delete hits[tr.id]; if (lastTrap && lastTrap.id === tr.id) { lastTrap = null; renderTrap(null); } renderList();
      });
      o.append(el("div", { class: "trapcard" }, el("b", null, tr.label || tr.id), " · " + fmtDate(tr.created), el("div", { class: "bg-actions" }, chk, del), res));
    }
  }
  // Link do panelu: #trap=<id>.<klucz> – fragment po # nie jest wysyłany do serwera.
  const m = (location.hash || "").match(/^#trap=([0-9a-f]{20})\.([A-Za-z0-9_-]{20,64})$/);
  if (m && !traps().some(x => x.id === m[1])) {
    const base = location.origin + "/t/" + m[1];
    const all = traps(); all.push({ id: m[1], key: m[2], label: "", created: Date.now(), urls: { page: base, gif: base + ".gif", api: base + "/api/v3/account", restore: base + "/restore", wallet: base + "/wallet" } });
    saveTraps(all);
  }
  if (m) {
    history.replaceState(null, "", "#blue");
    // otwarcie linku panelu od razu pokazuje trafienia tej pułapki
    postJSON("/api/trap/hits", { id: m[1], key: m[2] }).then(r => { hits[m[1]] = r.ok ? r.j.hits : null; renderList(); }).catch(() => {});
  }

  // ---------- C. raport utwardzenia ----------
  $("hardLoad").addEventListener("click", async () => {
    err("hardErr", "");
    try {
      const r = await fetch("/api/blueteam/report", { cache: "no-store", credentials: "omit" });
      if (!r.ok) return err("hardErr", errMsg(null, r.status));
      lastHard = await r.json(); renderHard(lastHard);
    } catch (e) { err("hardErr", t("err_net", { msg: e.message })); }
  });
  function renderHard(h) {
    const o = $("hardOut"); clear(o);
    const f = h.frontend;
    o.append(el("h3", null, t("hard_before")),
      el("p", { class: "small" }, t("hard_files", { files: f.files, apis: f.api_paths.length, hosts: f.external_hosts.length, secrets: f.secrets })),
      el("details", { class: "ioc" }, el("summary", null, "API (" + f.api_paths.length + ")"), el("ul", { class: "small addr" }, ...f.api_paths.map(x => el("li", null, x)))),
      el("details", { class: "ioc" }, el("summary", null, "hosts (" + f.external_hosts.length + ")"), el("ul", { class: "small addr" }, ...f.external_hosts.map(x => el("li", null, x)))),
      el("h3", null, t("hard_after")),
      el("p", { class: "small" }, t("hard_paths", { count: h.decoy_paths.length })),
      el("details", { class: "ioc" }, el("summary", null, "decoys"), el("ul", { class: "small addr" }, ...h.decoy_paths.map(x => el("li", null, x)))),
      el("p", null, el("b", null, t("hard_hits", { count: h.hits_total })), h.since ? " " + t("hard_since", { date: fmtDate(h.since * 1000) }) : ""));
    const rows = Object.entries(h.by_path);
    if (rows.length) o.append(el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, el("th", null, t("hard_table_path")), el("th", null, t("hard_table_n")))),
      el("tbody", null, ...rows.map(([p, n]) => el("tr", null, el("td", { class: "addr" }, p), el("td", null, String(n))))))));
    if (h.recent.length) o.append(el("p", { class: "small" }, el("b", null, t("hard_recent"))),
      el("ul", { class: "small" }, ...h.recent.map(x => el("li", { class: "addr" }, fmtDate(x.ts * 1000) + " · " + x.path + " · " + x.ip + " · " + (x.ua || "–") + (x.alias ? " · " + t("hard_alias") : "")))));
    if (h.storage === "ephemeral") o.append(el("p", { class: "small warn" }, t("hard_store")));
  }

  U.onLang.push(() => { if (lastRe) renderRe(lastRe); if (lastTrap) renderTrap(lastTrap); renderList(); if (lastHard) renderHard(lastHard); });
  renderList();
})();
