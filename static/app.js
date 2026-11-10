// SPDX-License-Identifier: AGPL-3.0-only
// Szlaban – frontend. Copyright (C) 2026 Robi (@robi44610)
"use strict";
(function () {
  const $ = id => document.getElementById(id);
  const SVGNS = "http://www.w3.org/2000/svg";
  const RISK_PL = { WYSOKIE: "WYSOKIE", SREDNIE: "ŚREDNIE", NISKIE: "NISKIE" };
  const RISK_COL = { WYSOKIE: "#ff4d2e", SREDNIE: "#ffcf4a", NISKIE: "#7bd389" };
  const NOTE_PL = {
    "nie znam nadawcy tx": ["nie znam nadawcy tx", false],
    "NIE Twoja tx (permit-podpis albo spam)": ["NIE Twoja tx (podpis permit albo spam)", true],
    "zwykle konto (EOA) - podejrzane!": ["zwykłe konto (EOA) – podejrzane!", true],
    "nie udalo sie sprawdzic": ["nie udało się sprawdzić", false],
    "nieznany kontrakt - sprawdz na etherscan": ["nieznany kontrakt – sprawdź na Etherscan", false],
    "zwykle konto (EOA) + bez limitu - bardzo podejrzane!": ["zwykłe konto (EOA) + bez limitu – bardzo podejrzane!", true]
  };
  const BL_NAMES = { scamsniffer: "ScamSniffer", forta_phish: "Forta phishing", forta_contracts: "Forta malicious contracts",
    forta_etherscan: "Forta/Etherscan labels", mew_darklist: "MEW darklist" };
  const plNote = n => NOTE_PL[n] || [n, false];
  const plMsg = m => String(m || "").replace(/logow/g, "zdarzeń").replace(/przelaczam na/g, "przełączam na");
  const usdFmt = new Intl.NumberFormat("pl-PL", { style: "currency", currency: "USD", maximumFractionDigits: 2 });
  const fmtUsd = x => x === null || x === undefined ? "–" : usdFmt.format(x);
  const dateFmt = ts => new Date(ts * 1000).toLocaleDateString("pl-PL", { year: "numeric", month: "short", day: "numeric" });
  let planAll = false, RES = null, CURRANGE = "year", sortKey = "risk", sortAsc = true, busy = false;

  const setStatus = t => { $("status").textContent = t; };
  const setProg = p => { $("track").classList.add("on"); $("track").querySelector(".fill").style.width = Math.max(0, Math.min(100, p)) + "%"; };
  const showErr = t => { $("err").textContent = t; $("err").classList.add("on"); };
  const clearErr = () => { $("err").classList.remove("on"); $("err").textContent = ""; };
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) { if (k === "class") e.className = v; else e.setAttribute(k, v); }
    for (const k of kids) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return e;
  }
  function sv(tag, attrs, text) {
    const e = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (text !== undefined) e.textContent = text;
    return e;
  }
  const ext = (href, text, cls) => el("a", { href, target: "_blank", rel: "noopener noreferrer", class: cls || "" }, text);
  const short = a => a.slice(0, 8) + "…" + a.slice(-6);
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const finish = () => { busy = false; $("go").disabled = false; $("go").textContent = "Prześwietl"; };

  document.querySelectorAll("input[name=range]").forEach(r => r.addEventListener("change", () =>
    $("custom").classList.toggle("on", document.querySelector("input[name=range]:checked").value === "custom")));
  ["fRisky", "fUnknown", "fForeign"].forEach(id => $(id).addEventListener("change", renderTable));
  document.querySelectorAll("#tbl th[data-k]").forEach(th => th.addEventListener("click", () => {
    const k = th.dataset.k; if (sortKey === k) sortAsc = !sortAsc; else { sortKey = k; sortAsc = true; } renderTable();
  }));
  $("addr").addEventListener("keydown", e => { if (e.key === "Enter") $("go").click(); });
  $("go").addEventListener("click", () => { if (!busy) scan().catch(e => { showErr("Błąd połączenia z serwerem: " + e.message); finish(); }); });
  $("shareBtn").addEventListener("click", async () => {
    const url = location.origin + "/r/" + RES.owner + "?range=" + encodeURIComponent(CURRANGE);
    try { await navigator.clipboard.writeText(url); $("shareMsg").textContent = "Skopiowano: " + url; }
    catch (e) { $("shareMsg").textContent = url; }
  });
  $("copyPlan").addEventListener("click", async () => {
    const lines = ["Szlaban – plan sprzątania dla " + RES.owner, ""];
    RES.plan.forEach((p, i) => lines.push((i + 1) + ". Cofnij zgodę " + p.token + " dla " + (p.spender_name || p.spender) + " – " + p.why.join(", ")));
    lines.push("", "Cofnij na: " + RES.revoke_url);
    try { await navigator.clipboard.writeText(lines.join("\n")); $("copyPlan").textContent = "Skopiowano ✓"; } catch (e) { $("copyPlan").textContent = "Kopiowanie zablokowane"; }
    setTimeout(() => { $("copyPlan").textContent = "Skopiuj plan"; }, 2500);
  });

  async function api(url, opts) {
    let r;
    try { r = await fetch(url, Object.assign({ cache: "no-store", credentials: "omit" }, opts || {})); }
    catch (e) { throw new Error("brak połączenia z serwerem Szlabanu"); }
    let j = {}; try { j = await r.json(); } catch (e) {}
    return { code: r.status, j };
  }

  async function scan(fromLink) {
    clearErr();
    const addr = $("addr").value.trim();
    if (/\.eth$/i.test(addr)) return showErr("Nazwy ENS (np. vitalik.eth) nie są obsługiwane. Wklej adres zaczynający się od 0x (40 znaków).");
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return showErr("To nie jest poprawny adres Ethereum. Adres ma postać 0x + 40 znaków (cyfry 0–9 i litery a–f), np. 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045.");
    let range = fromLink || document.querySelector("input[name=range]:checked").value;
    if (range === "custom") {
      const f = $("fromB").value.trim(), t = $("toB").value.trim();
      if (!/^\d+$/.test(f)) return showErr("Podaj numer bloku początkowego (liczba całkowita, np. 15000000).");
      if (t && !/^\d+$/.test(t)) return showErr("Blok końcowy musi być liczbą całkowitą albo pusty.");
      if (t && Number(f) > Number(t)) return showErr("Blok początkowy jest większy niż końcowy.");
      range = f + "-" + (t || "latest");
    }
    CURRANGE = range;
    busy = true; $("go").disabled = true; $("go").textContent = "Prześwietlam…";
    $("results").classList.add("hidden"); setProg(1); setStatus("Wysyłam zlecenie…");
    const t0 = Date.now();
    let { code, j } = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ address: addr, range }) });
    if (code >= 400 || !j.job_id) { finish(); setProg(0); return showErr(j.error || ("Błąd serwera (HTTP " + code + ").")); }
    const jid = j.job_id; let netFails = 0;
    while (j.status === "running") {
      setProg(j.progress || 1);
      setStatus(plMsg(j.message) + "  · " + Math.round((Date.now() - t0) / 1000) + " s");
      await sleep(1000);
      let r;
      try { r = await api("/api/job/" + jid); netFails = 0; }
      catch (e) { if (++netFails > 10) { finish(); return showErr("Utracono połączenie z serwerem. Spróbuj ponownie."); } continue; }
      if (r.code >= 400 && r.code !== 502) { finish(); setProg(0); return showErr(r.j.error || ("Błąd serwera (HTTP " + r.code + ").")); }
      j = r.j;
    }
    finish();
    if (j.status === "error") { setProg(0); setStatus(""); return showErr(j.error || "Skan się nie powiódł."); }
    setProg(100);
    setStatus("Gotowe" + (j.cached ? " (wynik z pamięci serwera, do 10 min)" : "") + " · skan " + j.result.seconds + " s");
    RES = j.result; RES.rows.forEach((r, i) => { r.idx = i + 1; r.v = BigInt(r.allowance_raw); });
    sortKey = "risk"; sortAsc = true; planAll = false;
    if (location.pathname !== "/r/" + RES.owner) history.replaceState(null, "", "/r/" + RES.owner + "?range=" + encodeURIComponent(range));
    renderAll();
  }

  const defaultRows = () => RES.rows.filter(r => !r.hidden_unknown && !r.hidden_foreign);

  function renderAll() {
    const rows = defaultRows();
    // licznik
    const c = { WYSOKIE: 0, SREDNIE: 0, NISKIE: 0 }; rows.forEach(r => c[r.risk]++);
    $("cH").textContent = c.WYSOKIE; $("cS").textContent = c.SREDNIE; $("cN").textContent = c.NISKIE;
    $("cF").textContent = rows.filter(r => r.forgotten).length;
    $("cB").textContent = rows.filter(r => r.blacklist && r.blacklist.length).length;
    // kwota
    const m = $("money");
    if (RES.usd_at_risk_total === undefined) { m.textContent = "–"; $("moneyNote").textContent = RES.analysis_error || "Analiza kwot niedostępna."; }
    else {
      m.textContent = fmtUsd(RES.usd_at_risk_total); m.classList.toggle("zero", RES.usd_at_risk_total < 1);
      $("moneyNote").textContent = "Tyle dolarów z Twojego obecnego salda mogą dziś wyjąć spenderzy z aktywnymi zgodami (każdy token liczony raz)." +
        (RES.usd_unpriced_rows ? " Zgody bez wiarygodnej ceny (niewliczone): " + RES.usd_unpriced_rows + "." : "") + (RES.prices_ok === false ? " Część cen niedostępna." : "");
    }
    $("meta").textContent = "Adres " + RES.owner + " · bloki " + RES.from_block + "–" + RES.to_block + " · zdarzeń Approval: " + RES.approval_events +
      " · par sprawdzonych: " + RES.pairs_checked + " · aktywnych zgód: " + RES.active_allowances;
    renderGauge(); renderPlan(); renderTimeline(rows); renderTable(); renderDed(); renderSources();
    $("revokeLink").href = RES.revoke_url; $("revokeLink").textContent = "revoke.cash/address/" + short(RES.owner);
    $("results").classList.remove("hidden");
  }

  function renderGauge() {
    const g = $("gauge"); g.replaceChildren();
    if (!RES.score) { $("grade").textContent = "brak danych"; return; }
    const v = RES.score.value, col = v >= 80 ? "#7bd389" : v >= 60 ? "#ffcf4a" : v >= 40 ? "#ffb000" : "#ff4d2e";
    const svg = sv("svg", { viewBox: "0 0 220 220", role: "img", "aria-label": "Wskaźnik odporności " + v + " na 100" });
    const R = 92, C = 2 * Math.PI * R;
    // znaczniki co 10
    for (let i = 0; i < 40; i++) { const a = (i / 40) * 2 * Math.PI - Math.PI / 2;
      svg.append(sv("line", { x1: 110 + Math.cos(a) * 104, y1: 110 + Math.sin(a) * 104, x2: 110 + Math.cos(a) * (i % 4 ? 100 : 96), y2: 110 + Math.sin(a) * (i % 4 ? 100 : 96), stroke: "#3a342b", "stroke-width": 2 })); }
    svg.append(sv("circle", { cx: 110, cy: 110, r: R, fill: "none", stroke: "#2a251e", "stroke-width": 14 }));
    svg.append(sv("circle", { cx: 110, cy: 110, r: R, fill: "none", stroke: col, "stroke-width": 14, "stroke-linecap": "round",
      "stroke-dasharray": (C * v / 100) + " " + C, transform: "rotate(-90 110 110)" }));
    svg.append(sv("text", { x: 110, y: 118, "text-anchor": "middle", fill: col, "font-size": 64, "font-weight": 800, "font-family": "ui-monospace,Menlo,monospace" }, String(v)));
    svg.append(sv("text", { x: 110, y: 146, "text-anchor": "middle", fill: "#a39a88", "font-size": 14, "font-family": "ui-monospace,Menlo,monospace" }, "/ 100"));
    g.append(svg);
    $("grade").textContent = RES.score.grade.toUpperCase(); $("grade").style.color = col;
  }

  function renderPlan() {
    const ol = $("plan"); ol.replaceChildren();
    if (!RES.plan || !RES.plan.length) { ol.append(el("li", { class: "lvl-n" }, el("div", null, "Nic pilnego do cofnięcia w tym zakresie. Szlabany opuszczone. ✓"), el("div"))); return; }
    const byKey = new Map(RES.rows.map(r => [r.token_address + r.spender, r]));
    const LIMIT = 25, list = planAll ? RES.plan : RES.plan.slice(0, LIMIT);
    list.forEach(p => {
      const r = byKey.get(p.token_address + p.spender) || {};
      const li = el("li", { class: r.risk === "SREDNIE" ? "lvl-s" : r.risk === "NISKIE" ? "lvl-n" : "" },
        el("div", null,
          el("div", { class: "what" }, "Cofnij ", ext("https://etherscan.io/token/" + p.token_address + "?a=" + RES.owner, p.token), " → ",
            ext("https://etherscan.io/address/" + p.spender, p.spender_name || short(p.spender))),
          el("div", { class: "why" }, ...p.why.map(w => el("span", null, w)))),
        el("div", { class: "usd" + (p.usd_at_risk ? "" : " na") }, p.usd_at_risk ? fmtUsd(p.usd_at_risk) : (p.usd_at_risk === 0 ? "saldo 0 $" : "brak ceny")));
      ol.append(li);
    });
    if (RES.plan.length > LIMIT) {
      const btn = el("button", { type: "button", class: "ghost" }, planAll ? "Pokaż tylko pierwsze " + LIMIT : "Pokaż cały plan (" + RES.plan.length + " pozycji)");
      btn.addEventListener("click", () => { planAll = !planAll; renderPlan(); });
      ol.append(el("li", { class: "more" }, btn));
    }
  }

  function renderTimeline(rows) {
    const box = $("timeline"); box.replaceChildren();
    const pts = rows.filter(r => r.approval_ts);
    if (!pts.length) { box.append(el("p", { class: "small" }, "Brak dat do pokazania.")); return; }
    const W = 1000, H = 250, L = 70, Rm = 20, lanes = { WYSOKIE: 70, SREDNIE: 130, NISKIE: 190 };
    const now = RES.analyzed_at || Math.floor(Date.now() / 1000);
    let t0 = Math.min(...pts.map(p => p.approval_ts)), t1 = now;
    if (t1 - t0 < 86400 * 30) t0 = t1 - 86400 * 30;
    const x = t => L + (W - L - Rm) * (t - t0) / (t1 - t0);
    const svg = sv("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Oś czasu zgód" });
    // strefa "zapomniane" (> 365 dni)
    const fx = x(now - 365 * 86400);
    if (fx > L) { svg.append(sv("rect", { x: L, y: 30, width: fx - L, height: 190, fill: "rgba(255,176,0,0.05)" }));
      svg.append(sv("text", { x: L + 6, y: 214, fill: "#ffb000", "font-size": 12, "font-family": "ui-monospace,monospace" }, "strefa zapomnianych (> 1 rok)")); }
    for (const [k, y] of Object.entries(lanes)) {
      svg.append(sv("line", { x1: L, x2: W - Rm, y1: y, y2: y, stroke: "#2e2a23", "stroke-dasharray": "4 6" }));
      svg.append(sv("text", { x: 4, y: y + 4, fill: RISK_COL[k], "font-size": 12, "font-weight": 700, "font-family": "ui-monospace,monospace" }, RISK_PL[k]));
    }
    // os lat
    const y0 = new Date(t0 * 1000).getFullYear(), y1 = new Date(t1 * 1000).getFullYear();
    for (let y = y0; y <= y1; y++) { const t = Date.UTC(y, 0, 1) / 1000; if (t < t0) continue;
      svg.append(sv("line", { x1: x(t), x2: x(t), y1: 30, y2: 220, stroke: "#3a342b" }));
      svg.append(sv("text", { x: x(t), y: 240, fill: "#a39a88", "font-size": 12, "text-anchor": "middle", "font-family": "ui-monospace,monospace" }, String(y))); }
    svg.append(sv("line", { x1: x(now), x2: x(now), y1: 30, y2: 220, stroke: "#ffb000", "stroke-width": 2 }));
    svg.append(sv("text", { x: x(now) - 4, y: 24, fill: "#ffb000", "font-size": 12, "text-anchor": "end", "font-family": "ui-monospace,monospace" }, "dziś"));
    const maxUsd = Math.max(1, ...pts.map(p => p.usd_at_risk || 0));
    // rozsun kropki w tym samym miejscu
    const seen = new Map();
    pts.sort((a, b) => (a.usd_at_risk || 0) - (b.usd_at_risk || 0)).forEach(p => {
      const cx = x(p.approval_ts), base = lanes[p.risk];
      const key = p.risk + Math.round(cx / 8); const n = seen.get(key) || 0; seen.set(key, n + 1);
      const cy = base + (n % 2 ? 1 : -1) * Math.ceil(n / 2) * 9;
      const r = 5 + 13 * Math.sqrt((p.usd_at_risk || 0) / maxUsd);
      const g = sv("g", {});
      if (p.forgotten) { g.append(sv("circle", { cx, cy, r: r + 5, fill: "none", stroke: "#ffb000", "stroke-width": 2, class: "pulse" }));
        g.append(sv("circle", { cx, cy, r: r + 3, fill: "none", stroke: "#ffb000", "stroke-width": 1.5 })); }
      g.append(sv("circle", { cx, cy, r, fill: RISK_COL[p.risk], "fill-opacity": 0.85, stroke: "#0b0a08", "stroke-width": 1.5 }));
      g.append(sv("title", {}, p.token + " → " + (p.spender_name || p.spender) + "\nustawiona: " + dateFmt(p.approval_ts) +
        (p.days_since_approval !== null ? " (" + p.days_since_approval + " dni temu)" : "") + "\nzagrożone: " + fmtUsd(p.usd_at_risk) + (p.forgotten ? "\nZAPOMNIANA" : "")));
      if ((p.usd_at_risk || 0) >= maxUsd * 0.5 && p.usd_at_risk > 0)
        g.append(sv("text", { x: Math.max(L + 60, cx), y: Math.max(14, cy - r - 8), fill: "#efe7d6", "font-size": 12, "text-anchor": "middle", "font-family": "ui-monospace,monospace" }, p.token + " " + fmtUsd(p.usd_at_risk)));
      svg.append(g);
    });
    box.append(svg);
  }

  function renderTable() {
    if (!RES) return;
    const showUnk = $("fUnknown").checked, showFor = $("fForeign").checked, risky = $("fRisky").checked;
    let hidU = 0, hidF = 0; const base = [];
    for (const r of RES.rows) {
      if (r.hidden_unknown && !showUnk) { hidU++; continue; }
      if (r.hidden_foreign && !showFor) { hidF++; continue; }
      base.push(r);
    }
    const num = new Map(); base.forEach((r, i) => num.set(r, i + 1));
    const rows = risky ? base.filter(r => r.risk !== "NISKIE") : base.slice();
    const lc = s => String(s).toLowerCase(), nz = v => (v === null || v === undefined) ? -1 : v;
    const cmp = {
      idx: (a, b) => a.idx - b.idx, risk: (a, b) => a.idx - b.idx,
      token: (a, b) => lc(a.token).localeCompare(lc(b.token)) || a.idx - b.idx,
      spender: (a, b) => lc(a.spender_name || "~" + a.spender).localeCompare(lc(b.spender_name || "~" + b.spender)) || a.idx - b.idx,
      amount: (a, b) => (a.v < b.v ? -1 : a.v > b.v ? 1 : 0) || a.idx - b.idx,
      usd: (a, b) => nz(a.usd_at_risk) - nz(b.usd_at_risk) || a.idx - b.idx,
      age: (a, b) => nz(a.spender_age_days) - nz(b.spender_age_days) || a.idx - b.idx,
      days: (a, b) => nz(a.days_since_approval) - nz(b.days_since_approval) || a.idx - b.idx,
      note: (a, b) => a.note.localeCompare(b.note) || a.idx - b.idx
    }[sortKey];
    rows.sort(cmp); if (!sortAsc) rows.reverse();
    document.querySelectorAll("#tbl th[data-k]").forEach(th => {
      const lbl = th.textContent.replace(/ [▲▼]$/, ""), on = th.dataset.k === sortKey;
      th.classList.toggle("sorted", on); th.textContent = on ? lbl + (sortAsc ? " ▲" : " ▼") : lbl;
    });
    const tb = $("tbl").tBodies[0]; tb.replaceChildren();
    const cell = (label, cls, ...kids) => el("td", { "data-l": label, class: cls || "" }, el("div", { class: "cell" }, ...kids));
    if (!rows.length) tb.append(el("tr", null, el("td", { colspan: "9" }, risky && base.length ? "Brak ryzykownych zgód w tym zakresie." : "Brak aktywnych zgód do pokazania (wszystkie cofnięte albo zero).")));
    for (const r of rows) {
      const notes = el("span");
      r.notes.forEach((n, i) => { const [t, w] = plNote(n); if (i) notes.append("; "); notes.append(w ? el("span", { class: "warn" }, t) : t); });
      (r.blacklist || []).forEach(b => notes.append(" ", el("span", { class: "bl", title: b.label || "" }, "czarna lista: " + (BL_NAMES[b.source] || b.source))));
      const kind = r.spender_kind || "";
      const kindTxt = kind === "kontrakt" ? null : kind === "eoa" ? "zwykłe konto (EOA)" : kind.startsWith("eoa7702:") ? "EOA z delegacją EIP-7702 → " + short(kind.slice(8)) : null;
      const age = r.spender_age_days !== null && r.spender_age_days !== undefined
        ? el("span", null, r.spender_age_days + " dni", el("div", { class: "small" }, "od bloku " + r.spender_created_block))
        : (kind.startsWith("eoa") ? "– (EOA)" : "–");
      tb.append(el("tr", null,
        cell("#", "", num.get(r)),
        cell("Token", "", ext("https://etherscan.io/token/" + r.token_address + "?a=" + RES.owner, r.token, "tok"), el("div", { class: "small mono" }, short(r.token_address))),
        cell("Spender", "mono", ext("https://etherscan.io/address/" + r.spender, short(r.spender)), r.spender_name ? el("div", { class: "small" }, r.spender_name) : null, kindTxt ? el("div", { class: "small warn" }, kindTxt) : null),
        cell("Zgoda", "mono" + (r.unlimited ? " unl" : ""), r.allowance),
        cell("Zagrożone", "mono", r.usd_at_risk === undefined ? "–" : fmtUsd(r.usd_at_risk)),
        cell("Ryzyko", "", el("span", { class: "risk r-" + r.risk }, RISK_PL[r.risk])),
        cell("Wiek spendera", "mono", age),
        cell("Ustawiona", "mono", r.approval_ts ? el("span", null, dateFmt(r.approval_ts), el("div", { class: r.forgotten ? "small warn" : "small" }, (r.forgotten ? "zapomniana · " : "") + r.days_since_approval + " dni temu")) : "blok " + r.last_approval_block),
        cell("Uwagi", "", notes, el("div", { class: "small" }, ext("https://etherscan.io/tx/" + r.tx_hash, "transakcja zgody")))));
    }
    const hi = [];
    if (hidU) hi.push("Ukryto " + hidU + " zgód na tokeny bez symbolu/decimals (zwykle spam).");
    if (hidF) hi.push("Ukryto " + hidF + " zgód z cudzych transakcji dla znanych routerów (typowy spam memecoinów).");
    if (RES.unreadable) hi.push("Nie udało się odczytać allowance dla " + RES.unreadable + " par.");
    if (RES.nft_events_skipped) hi.push("Pominięto " + RES.nft_events_skipped + " zdarzeń NFT (ERC-721).");
    $("hiddenInfo").textContent = hi.join(" ");
  }

  function renderDed() {
    const tb = $("ded").tBodies[0]; tb.replaceChildren();
    const old = $("ded").tFoot; if (old) old.remove();
    if (!RES.score) return;
    RES.score.deductions.forEach(d => tb.append(el("tr", null,
      el("td", null, d.label, d.rule ? el("div", { class: "small" }, d.rule) : null),
      el("td", { class: "mono" }, d.id === "usd" ? fmtUsd(d.count) : d.count),
      el("td", { class: "mono" }, d.per_item ? "−" + d.per_item : "progi"),
      el("td", { class: "mono" }, "−" + d.cap),
      el("td", { class: "pts" + (d.points ? "" : " z") }, d.points ? "−" + d.points : "0"))));
    const tf = $("ded").createTFoot();
    tf.append(el("tr", null, el("td", { colspan: "4" }, "Wynik: 100 − " + (100 - RES.score.value) + " ="), el("td", null, String(RES.score.value))));
    if (RES.price_source) $("minConf").textContent = String(RES.price_source.min_confidence).replace(".", ",");
  }

  function renderSources() {
    const ul = $("sources"); ul.replaceChildren();
    ul.append(el("li", null, "Zgody, salda, kod i daty bloków: publiczne węzły Ethereum (Tenderly, MEV Blocker, Flashbots, PublicNode, dRPC) – zapytania eth_getLogs, eth_call, eth_getCode, eth_getBlockByNumber."));
    if (RES.price_source) ul.append(el("li", null, "Ceny: ", ext(RES.price_source.url, RES.price_source.name), " (bez klucza; pomijamy ceny o pewności < " + RES.price_source.min_confidence + ")."));
    (RES.blacklist_sources || []).forEach(s => ul.append(el("li", null, "Czarna lista: ", ext(s.page, s.name), " – " + s.entries + " adresów, " + s.note + (s.ok ? "" : " (NIEDOSTĘPNA przy tym skanie)") + ".")));
    ul.append(el("li", null, "Znane kontrakty: lista marek z zgody.py (Uniswap, 1inch, CoW, 0x, ParaSwap, Balancer, Aave, KyberSwap…), adresy sprawdzone w oficjalnych dokumentacjach."));
  }

  // link do raportu: /r/<adres>?range=...
  const m = location.pathname.match(/^\/r\/(0x[0-9a-fA-F]{40})\/?$/);
  if (m) {
    $("addr").value = m[1];
    const rg = new URLSearchParams(location.search).get("range") || "year";
    if (/^(all|year)$/.test(rg)) document.querySelector("input[name=range][value=" + rg + "]").checked = true;
    else if (/^\d{1,9}-(\d{1,9}|latest)?$/.test(rg)) { document.querySelector("input[name=range][value=custom]").checked = true; $("custom").classList.add("on");
      const [a, b] = rg.split("-"); $("fromB").value = a; if (b && b !== "latest") $("toB").value = b; }
    if (/^(all|year|\d{1,9}-(\d{1,9}|latest)?)$/.test(rg)) { busy = false; scan(/^\d/.test(rg) ? undefined : rg).catch(e => { showErr(e.message); finish(); }); }
  }
})();
