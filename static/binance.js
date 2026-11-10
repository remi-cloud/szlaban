// SPDX-License-Identifier: AGPL-3.0-only
// Szlaban – Binance Guard – interfejs. Copyright (C) 2026 Robi (@robi44610)
// Klucz tajny (secret) jest używany tylko w tej karcie do podpisu HMAC i nigdy nie jest wysyłany ani zapisywany.
"use strict";
(function () {
  const $ = id => document.getElementById(id);
  const I = window.BGI18N, C = window.BGCore, D = window.BGDetector;
  const LS_LANG = "bg.lang", LS_BASE = "bg.baseline.v1", LS_CHECK = "bg.checklist.v1";
  const RECV_WINDOW = 10000;
  let lang = "en", lastAudit = null, lastList = null, lastDet = null, lastErr = {}, busy = false, timeOffset = 0;

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } },
    del(k) { try { localStorage.removeItem(k); } catch (e) { /* brak */ } }
  };
  function pickLang() {
    const q = new URLSearchParams(location.search).get("lang");
    if (q && I.LANGS.includes(q)) return q;
    const saved = store.get(LS_LANG);
    if (saved && I.LANGS.includes(saved)) return saved;
    for (const l of (navigator.languages || [navigator.language || "en"])) {
      const p = String(l).toLowerCase().slice(0, 2);
      if (p === "pl") return "pl";
      if (p === "zh") return "zh";
      if (p === "en") return "en";
    }
    return "en";
  }
  const t = (key, params) => {
    let s = (I[lang] && I[lang][key]) || I.en[key] || key;
    if (params) s = s.replace(/\{(\w+)\}/g, (m, k) => (params[k] === undefined || params[k] === null) ? m : String(params[k]));
    return s;
  };
  const locale = () => ({ en: "en-GB", pl: "pl-PL", zh: "zh-CN" })[lang];
  const fmtDate = ms => new Date(ms).toLocaleString(locale(), { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) { if (k === "class") e.className = v; else e.setAttribute(k, v); }
    for (const k of kids) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return e;
  }
  const clear = node => { while (node.firstChild) node.removeChild(node.firstChild); };

  function applyLang(l) {
    lang = l;
    store.set(LS_LANG, l);
    document.documentElement.lang = l === "zh" ? "zh-CN" : l;
    document.title = t("page_title");
    document.querySelectorAll("[data-i18n]").forEach(n => { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll("[data-i18n-ph]").forEach(n => { n.placeholder = t(n.dataset.i18nPh); });
    document.querySelectorAll(".lang").forEach(b => { const on = b.dataset.lang === l; b.classList.toggle("on", on); b.setAttribute("aria-pressed", on ? "true" : "false"); });
    const vl = $("verifyLink");
    vl.href = "https://www.binance.com/" + ({ en: "en", pl: "pl", zh: "zh-CN" })[l] + "/official-verification";
    $("officialList").textContent = t("official_list", { list: D.OFFICIAL.join(", "), rel: D.RELATED.join(", ") });
    renderChecklist();
    renderBaseInfo();
    if (lastAudit) renderAudit(lastAudit);
    if (lastList) renderGuard(lastList.list, lastList.diff);
    if (lastDet) renderDetect(lastDet);
    for (const [box, e] of Object.entries(lastErr)) if (e) showErr(box, e);
  }

  // ---------- zakładki ----------
  function showTab(name) {
    document.querySelectorAll(".tab").forEach(b => b.setAttribute("aria-selected", b.dataset.tab === name ? "true" : "false"));
    ["audit", "guard", "detect"].forEach(n => $("sec-" + n).classList.toggle("hidden", n !== name));
    $("keypanel").classList.toggle("hidden", name === "detect");
    if (history.replaceState) history.replaceState(null, "", "#" + name);
  }
  document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));
  document.querySelectorAll(".lang").forEach(b => b.addEventListener("click", () => applyLang(b.dataset.lang)));
  $("kform").addEventListener("submit", e => e.preventDefault());

  // ---------- tryb klucz / ręczny ----------
  function setMode() {
    const manual = document.querySelector("input[name=kmode]:checked").value === "manual";
    $("keyform").classList.toggle("hidden", manual);
    $("auditKey").classList.toggle("hidden", manual);
    $("auditManual").classList.toggle("hidden", !manual);
  }
  document.querySelectorAll("input[name=kmode]").forEach(r => r.addEventListener("change", setMode));
  $("clearKeys").addEventListener("click", () => { $("apiKey").value = ""; $("apiSecret").value = ""; });

  // ---------- relay ----------
  async function relay(body) {
    let r;
    try {
      r = await fetch("/api/binance/relay", { method: "POST", cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } catch (e) { throw { kind: "net", msg: e.message }; }
    let j = null;
    try { j = await r.json(); } catch (e) { /* brak JSON */ }
    const via = r.headers.get("X-BG-Relay") || "";
    if (r.ok && j && "data" in j) return { data: j.data, via };
    throw Object.assign({ kind: "api", status: r.status }, j || { error: "http_" + r.status });
  }
  async function syncTime() {
    try {
      const t0 = Date.now();
      const r = await relay({ endpoint: "time" });
      if (r.data && typeof r.data.serverTime === "number") timeOffset = r.data.serverTime - Math.round((t0 + Date.now()) / 2);
    } catch (e) { if (e && e.error === "geo_blocked") throw e; timeOffset = 0; }
  }
  function credentials() {
    const k = $("apiKey").value.trim(), s = $("apiSecret").value.trim();
    if (!k || !s) throw { kind: "input" };
    if (!(window.crypto && window.crypto.subtle)) throw { kind: "crypto" };
    return { k, s };
  }
  async function signed(endpoint, cred) {
    const ts = Date.now() + timeOffset;
    const req = await C.signRequest(endpoint, cred.k, cred.s, ts, RECV_WINDOW);
    return relay(req);
  }
  function errNodes(e) {
    const out = [];
    if (!e) return out;
    if (e.kind === "input") out.push(t("err_input"));
    else if (e.kind === "crypto") out.push(t("err_crypto"));
    else if (e.kind === "net") out.push(t("err_net", { msg: e.msg }));
    else if (e.error === "geo_blocked") {
      out.push(t("err_geo"));
      if (!/workers\.dev$/.test(location.hostname) && !/^(127\.0\.0\.1|localhost)$/.test(location.hostname))
        out.push(el("span", null, t("err_geo_try"), el("a", { href: "https://szlaban.remi-cloud.workers.dev/binance" }, "https://szlaban.remi-cloud.workers.dev/binance")));
      out.push(t("err_geo_local"));
    } else if (e.error === "binance_error") {
      const c = e.binance_code;
      if (c === -2015 || c === -2014 || c === -2008) out.push(t("err_ip_key", { code: c }), t("err_geo_local"));
      else if (c === -1022) out.push(t("err_sig", { code: c }));
      else if (c === -1021) out.push(t("err_time", { code: c }));
      else out.push(t("err_binance", { code: c, msg: e.binance_msg || "" }));
    } else if (e.error === "rate_limited" || e.error === "binance_rate_limit") out.push(t("err_rate"));
    else out.push(t("err_other", { msg: e.message || e.error || String(e) }));
    return out;
  }
  function showErr(box, e) {
    lastErr[box] = e;
    const b = $(box);
    clear(b);
    errNodes(e).forEach((n, i) => { if (i) b.append(el("br")); b.append(n); });
    b.classList.add("on");
  }
  function hideErr(box) { lastErr[box] = null; $(box).classList.remove("on"); clear($(box)); }
  const viaText = via => t("relay_via", { via: via === "cloudflare-edge" ? t("via_edge") : t("via_server") });

  // ---------- moduł 1: audyt ----------
  $("runAudit").addEventListener("click", async () => {
    if (busy) return;
    hideErr("auditErr"); clear($("auditOut")); lastAudit = null;
    busy = true; $("runAudit").disabled = true; $("auditStatus").textContent = t("running");
    try {
      const cred = credentials();
      await syncTime();
      const p = await signed("apiRestrictions", cred);
      let st = null, tr = null;
      try { st = (await signed("accountStatus", cred)).data; } catch (e) { st = null; }
      try { tr = (await signed("apiTradingStatus", cred)).data; } catch (e) { tr = null; }
      lastAudit = { res: C.evaluateKey(p.data, st, tr, Date.now() + timeOffset), via: p.via };
      renderAudit(lastAudit);
    } catch (e) { showErr("auditErr", e); }
    finally { busy = false; $("runAudit").disabled = false; $("auditStatus").textContent = ""; }
  });
  function findingText(f) {
    const p = Object.assign({}, f.params);
    if (p.perm) p.perm = t("perm_" + p.perm);
    if (p.ts) p.date = fmtDate(p.ts);
    return { title: t("f_" + f.id, p), fix: (I.en["f_" + f.id + "_fix"]) ? t("f_" + f.id + "_fix", p) : "" };
  }
  function renderAudit(a) {
    const out = $("auditOut"); clear(out);
    out.append(el("div", { class: "bg-overall" }, t("overall") + ": ", el("span", { class: "lv lv-" + a.res.overall }, t("lvl_" + a.res.overall))));
    const ul = el("ul", { class: "findings" });
    for (const f of a.res.findings) {
      const x = findingText(f);
      ul.append(el("li", { class: "l-" + f.level }, el("div", { class: "ft" }, el("span", { class: "lv lv-" + f.level }, t("lvl_" + f.level)), x.title),
        x.fix ? el("div", { class: "fx" }, el("b", null, t("fix") + " "), x.fix) : null));
    }
    out.append(ul, el("div", { class: "meta" }, viaText(a.via)));
  }

  // ---------- lista ręczna ----------
  const CHECKS = ["chk_2fa", "chk_antiphish", "chk_whitelist", "chk_api", "chk_devices", "chk_email", "chk_password", "chk_verify", "chk_seed"];
  function checkState() { try { return JSON.parse(store.get(LS_CHECK) || "{}") || {}; } catch (e) { return {}; } }
  function renderChecklist() {
    const st = checkState(), ul = $("checklist"); clear(ul);
    for (const k of CHECKS) {
      const cb = el("input", { type: "checkbox", id: "c-" + k });
      cb.checked = st[k] === true;
      cb.addEventListener("change", () => { const s = checkState(); s[k] = cb.checked; store.set(LS_CHECK, JSON.stringify(s)); renderScore(); });
      ul.append(el("li", null, el("label", { for: "c-" + k }, cb, el("span", null, t(k)))));
    }
    renderScore();
  }
  function renderScore() {
    const st = checkState(), done = CHECKS.filter(k => st[k] === true).length;
    $("manualScore").textContent = t("manual_score", { done, total: CHECKS.length });
  }

  // ---------- moduł 2: strażnik adresów ----------
  function loadBase() { try { const b = JSON.parse(store.get(LS_BASE) || "null"); return b && b.v === 1 && Array.isArray(b.items) ? b : null; } catch (e) { return null; } }
  function renderBaseInfo() {
    const b = loadBase();
    $("baseInfo").textContent = b ? t("base_info", { date: fmtDate(b.created), count: b.count, mode: t("mode_" + b.mode) }) : t("base_none");
  }
  $("fetchAddr").addEventListener("click", async () => {
    if (busy) return;
    hideErr("guardErr"); clear($("diffOut")); clear($("addrOut")); lastList = null; $("saveBase").disabled = true;
    busy = true; $("fetchAddr").disabled = true; $("guardStatus").textContent = t("running");
    try {
      const cred = credentials();
      await syncTime();
      const r = await signed("withdrawAddressList", cred);
      const list = Array.isArray(r.data) ? r.data : [];
      const base = loadBase();
      const diff = base ? await C.diffBaseline(base, list) : null;
      lastList = { list, diff, via: r.via };
      renderGuard(list, diff);
      $("saveBase").disabled = false;
    } catch (e) { showErr("guardErr", e); }
    finally { busy = false; $("fetchAddr").disabled = false; $("guardStatus").textContent = ""; }
  });
  $("saveBase").addEventListener("click", async () => {
    if (!lastList) return;
    const mode = document.querySelector("input[name=smode]:checked").value;
    const b = await C.makeBaseline(lastList.list, mode, Date.now());
    store.set(LS_BASE, JSON.stringify(b));
    lastList.diff = null;
    renderGuard(lastList.list, null);
    renderBaseInfo();
    $("guardStatus").textContent = t("base_saved");
  });
  $("delBase").addEventListener("click", () => { store.del(LS_BASE); renderBaseInfo(); $("guardStatus").textContent = t("base_deleted"); });
  const ent = a => a ? { coin: a.coin || "", network: a.network || "", name: a.name || "", address: (a.address || "") + (a.addressTag ? " (" + a.addressTag + ")" : "") } : {};
  function renderGuard(list, diff) {
    const d = $("diffOut"), o = $("addrOut"); clear(d); clear(o);
    if (diff) {
      if (!diff.alert) d.append(el("div", { class: "diff-ok" }, t("diff_ok")));
      else {
        const ul = el("ul", { class: "small" });
        diff.added.forEach(a => ul.append(el("li", null, t("diff_added", ent(a)))));
        diff.changed.forEach(c => ul.append(el("li", null, t("diff_changed", ent(c.now)))));
        diff.removed.forEach(r => ul.append(el("li", null, r ? t("diff_removed", ent(r)) : t("diff_removed_hash"))));
        diff.whiteChanged.forEach(w => ul.append(el("li", null, t("diff_white", Object.assign(ent(w.now), { now: t(w.now.whiteStatus ? "yes" : "no") })))));
        d.append(el("div", { class: "diff-alert" }, el("b", null, t("diff_alert")), ul, el("div", { class: "small" }, t("diff_unknown_if"))));
      }
    }
    if (!list.length) { o.append(el("p", { class: "small" }, t("addr_none"))); return; }
    o.append(el("p", { class: "small" }, t("addr_count", { count: list.length })));
    const nw = list.filter(a => a.whiteStatus !== true).length;
    if (nw) o.append(el("p", { class: "small warn" }, t("nonwhite", { count: nw })));
    const tb = el("tbody");
    for (const a of list) tb.append(el("tr", null, el("td", null, a.coin || ""), el("td", null, a.network || ""), el("td", null, a.name || ""),
      el("td", { class: "addr" }, a.address || ""), el("td", { class: "addr" }, a.addressTag || ""), el("td", null, t(a.whiteStatus === true ? "yes" : "no"))));
    o.append(el("div", { class: "tw" }, el("table", null, el("thead", null, el("tr", null, ...["col_coin", "col_network", "col_name", "col_address", "col_tag", "col_white"].map(k => el("th", null, t(k))))), tb)));
    if (lastList && lastList.via) o.append(el("div", { class: "meta" }, viaText(lastList.via)));
  }

  // ---------- moduł 3: wykrywacz ----------
  $("runDetect").addEventListener("click", () => {
    const mode = document.querySelector("input[name=dmode]:checked").value;
    lastDet = D.analyze($("detIn").value, mode);
    renderDetect(lastDet);
  });
  function renderDetect(r) {
    const o = $("detOut"); clear(o);
    const col = { low: "var(--grn)", medium: "var(--yel)", high: "var(--red)", critical: "#ff2e6e" }[r.level];
    const bar = el("div"); bar.style.width = Math.max(3, r.score) + "%"; bar.style.background = col;
    o.append(el("div", { class: "bg-overall" }, t("risk_score") + ": " + r.score + "/100 ", el("span", { class: "lv lv-" + r.level }, t("lvl_" + r.level))),
      el("div", { class: "meter", role: "meter", "aria-valuenow": String(r.score), "aria-valuemin": "0", "aria-valuemax": "100" }, bar));
    const ul = el("ul", { class: "findings" });
    for (const x of r.reasons) {
      const lvl = x.w >= 40 ? "high" : x.w >= 20 ? "medium" : x.w > 0 ? "low" : "ok";
      ul.append(el("li", { class: "l-" + lvl }, el("div", { class: "ft" }, x.w ? el("span", { class: "lv lv-" + lvl }, "+" + x.w) : null, t("r_" + x.code, x.p))));
    }
    if (!r.reasons.some(x => x.w > 0)) ul.append(el("li", { class: "l-ok" }, t("det_low")));
    o.append(ul);
    if (r.hosts.length) {
      const hl = el("ul", { class: "hosts small" });
      for (const h of r.hosts) hl.append(el("li", null, el("span", { class: "mono" }, h.display && h.display !== h.host ? h.display + " (" + h.host + ")" : (h.host || h.value)), " – ",
        el("b", { class: "v-" + h.verdict }, t("v_" + h.verdict))));
      o.append(el("div", { class: "small" }, el("b", null, t("found_hosts"))), hl);
    }
  }

  // Po zamknięciu/ukryciu strony czyścimy pola z kluczem (np. przy powrocie z pamięci podręcznej bfcache).
  window.addEventListener("pagehide", () => { $("apiKey").value = ""; $("apiSecret").value = ""; });

  // ---------- start ----------
  applyLang(pickLang());
  setMode();
  const h = (location.hash || "").slice(1);
  showTab(["audit", "guard", "detect"].includes(h) ? h : "audit");
})();
