# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""forensics.py - dodatkowa analiza wyniku skanu (tylko prawdziwe dane, tylko odczyt).

* saldo tokena (balanceOf) i cena z DefiLlama -> "kwota zagrozona" w USD
* kryminalistyka spendera: kontrakt / EOA / EOA z delegacja EIP-7702,
  wiek kontraktu (blok utworzenia przez wyszukiwanie binarne eth_getCode na wezle archiwalnym),
  obecnosc na publicznych czarnych listach adresow (GitHub)
* os czasu: data ostatniej zgody (timestamp bloku), "zapomniane od X dni"
* Wskaznik odpornosci 0-100 z jawnym wzorem i plan sprzatania
"""
import json
import math
import os
import threading
import time
import urllib.request
from decimal import Decimal

from zgody import RPC, RPCError, enc_addr, decode_uint

ARCHIVE_ENDPOINTS = ["https://mainnet.gateway.tenderly.co", "https://rpc.mevblocker.io", "https://eth.drpc.org"]
CALL_ENDPOINTS = ["https://ethereum-rpc.publicnode.com", "https://mainnet.gateway.tenderly.co",
                  "https://rpc.mevblocker.io", "https://eth.drpc.org"]
SEL_BALANCE = "0x70a08231"  # balanceOf(address)
PRICE_API = "https://coins.llama.fi/prices/current/"
PRICE_MIN_CONFIDENCE = 0.9
UA = {"User-Agent": "szlaban/1.0 (read-only approvals audit)"}
BATCH = 100
FORGOTTEN_DAYS = 365

# Publiczne listy adresow (wszystkie z GitHub, otwarte licencje). UWAGA: to listy historyczne.
BLACKLISTS = [
    {"id": "scamsniffer", "name": "ScamSniffer scam-database (address.json)",
     "url": "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
     "page": "https://github.com/scamsniffer/scam-database", "kind": "json_list",
     "note": "wg README nieaktualizowana od lutego 2024"},
    {"id": "forta_phish", "name": "Forta labelled-datasets: phishing_scams.csv",
     "url": "https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/phishing_scams.csv",
     "page": "https://github.com/forta-network/labelled-datasets", "kind": "csv0", "note": "stan ze stycznia 2023"},
    {"id": "forta_contracts", "name": "Forta labelled-datasets: malicious_smart_contracts.csv",
     "url": "https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/malicious_smart_contracts.csv",
     "page": "https://github.com/forta-network/labelled-datasets", "kind": "csv0", "note": "stan ze stycznia 2023"},
    {"id": "forta_etherscan", "name": "Forta labelled-datasets: etherscan_malicious_labels.csv",
     "url": "https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/etherscan_malicious_labels.csv",
     "page": "https://github.com/forta-network/labelled-datasets", "kind": "csv0", "note": "stan ze stycznia 2023"},
    {"id": "mew_darklist", "name": "MyEtherWallet ethereum-lists: addresses-darklist.json",
     "url": "https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json",
     "page": "https://github.com/MyEtherWallet/ethereum-lists", "kind": "mew", "note": "ostatnia zmiana listy: 2020"},
]
_bl_lock = threading.Lock()
_bl = {"loaded": 0, "index": {}, "sources": []}   # index: addr -> [(source_id, label)]
BL_TTL = 24 * 3600


def _get(url, timeout=30, data=None):
    req = urllib.request.Request(url, headers=UA, data=data)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_blacklists(force=False):
    with _bl_lock:
        if not force and _bl["loaded"] and time.time() - _bl["loaded"] < BL_TTL:
            return _bl
        if os.environ.get("ZGODY_NO_BLACKLIST") == "1":
            _bl.update(loaded=time.time(), index={}, sources=[])
            return _bl
        index, sources = {}, []
        for src in BLACKLISTS:
            n = 0
            try:
                raw = _get(src["url"]).decode("utf-8", "replace")
                if src["kind"] == "json_list":
                    items = [(a, "") for a in json.loads(raw)]
                elif src["kind"] == "mew":
                    items = [(x.get("address", ""), x.get("comment", "")) for x in json.loads(raw)]
                else:
                    lines = raw.splitlines()[1:]
                    items = []
                    for ln in lines:
                        cols = ln.split(",")
                        items.append((cols[0], cols[1] if len(cols) > 1 else ""))
                for a, lab in items:
                    a = (a or "").strip().lower()
                    if len(a) == 42 and a.startswith("0x"):
                        index.setdefault(a, []).append((src["id"], lab.strip()[:120]))
                        n += 1
                ok = True
            except Exception as e:  # lista niedostepna - dzialamy dalej
                ok = False
            sources.append({"id": src["id"], "name": src["name"], "page": src["page"], "note": src["note"],
                            "entries": n, "ok": ok})
        if index or not _bl["loaded"]:
            _bl.update(loaded=time.time(), index=index, sources=sources)
        return _bl


def fetch_prices(tokens):
    """DefiLlama, bez klucza. Zwraca {token: (price, confidence, timestamp)}."""
    out = {}
    if os.environ.get("ZGODY_NO_PRICES") == "1":
        return out, False
    ok = True
    for i in range(0, len(tokens), 60):
        part = tokens[i:i + 60]
        url = PRICE_API + ",".join("ethereum:" + t for t in part)
        for attempt in range(2):
            try:
                d = json.loads(_get(url, timeout=25))
                for k, v in (d.get("coins") or {}).items():
                    t = k.split(":", 1)[1].lower()
                    out[t] = (float(v.get("price") or 0), float(v.get("confidence") or 0), v.get("timestamp"))
                break
            except Exception:
                if attempt:
                    ok = False
                time.sleep(1)
    return out, ok


def _batch(rpc, calls):
    res = []
    for i in range(0, len(calls), BATCH):
        res.extend(rpc.batch(calls[i:i + BATCH]))
    return res


def creation_blocks(spenders, latest, rpc_arch, progress=None):
    """Wyszukiwanie binarne: najnizszy blok, w ktorym adres ma juz kod. ~25 rund paczek."""
    lo = {s: 0 for s in spenders}
    hi = {s: latest for s in spenders}
    failed = set()
    rounds = 0
    while True:
        todo = [s for s in spenders if s not in failed and lo[s] < hi[s]]
        if not todo:
            break
        rounds += 1
        mids = {s: (lo[s] + hi[s]) // 2 for s in todo}
        res = _batch(rpc_arch, [("eth_getCode", [s, hex(mids[s])]) for s in todo])
        for s, r in zip(todo, res):
            if isinstance(r, RPCError) or r is None:
                failed.add(s)
            elif r not in ("0x", "0x0"):
                hi[s] = mids[s]
            else:
                lo[s] = mids[s] + 1
        if progress:
            progress(rounds)
        if rounds > 40:
            break
    return {s: (None if s in failed else hi[s]) for s in spenders}


def block_times(blocks, rpc_arch):
    blocks = sorted({b for b in blocks if b is not None})
    res = _batch(rpc_arch, [("eth_getBlockByNumber", [hex(b), False]) for b in blocks])
    out = {}
    for b, r in zip(blocks, res):
        if isinstance(r, dict) and r.get("timestamp"):
            out[b] = int(r["timestamp"], 16)
    return out


def human_usd(x):
    if x is None:
        return None
    return round(x, 2)


def enrich(result, progress=None):
    def prog(p, m):
        if progress:
            progress(p, m)
    owner = result["owner"]
    rows = result["rows"]
    visible = [r for r in rows if not r["hidden_unknown"] and not r["hidden_foreign"]]
    rpc = RPC(CALL_ENDPOINTS, timeout=60)
    rpc_arch = RPC(ARCHIVE_ENDPOINTS, timeout=60)
    now = int(time.time())

    # 1) salda i ceny
    prog(90, "Analiza: salda tokenów (balanceOf)…")
    tokens = sorted({r["token_address"] for r in rows})
    bal_res = _batch(rpc, [("eth_call", [{"to": t, "data": SEL_BALANCE + enc_addr(owner)}, "latest"]) for t in tokens])
    balances = {t: (None if isinstance(r, RPCError) else decode_uint(r)) for t, r in zip(tokens, bal_res)}
    prog(92, "Analiza: ceny tokenów (DefiLlama)…")
    prices, prices_ok = fetch_prices(tokens)

    # 2) kryminalistyka spenderow (dla widocznych wierszy)
    spenders = sorted({r["spender"] for r in visible})
    code_res = _batch(rpc, [("eth_getCode", [s, "latest"]) for s in spenders])
    kinds = {}
    for s, r in zip(spenders, code_res):
        if isinstance(r, RPCError) or r is None:
            kinds[s] = "nieznany"
        elif r in ("0x", "0x0"):
            kinds[s] = "eoa"
        elif r.lower().startswith("0xef0100") and len(r) == 2 + 46:
            kinds[s] = "eoa7702:0x" + r[8:].lower()
        else:
            kinds[s] = "kontrakt"
    contracts = [s for s in spenders if kinds[s] == "kontrakt"]
    prog(93, "Analiza: wiek kontraktów (wyszukiwanie binarne na węźle archiwalnym)…")
    cblocks = creation_blocks(contracts, result["latest_block"], rpc_arch,
                              lambda n: prog(93 + min(4, n // 7), "Analiza: wiek kontraktów – runda %d…" % n))
    prog(97, "Analiza: daty zgód…")
    times = block_times([r["last_approval_block"] for r in visible] + list(cblocks.values()), rpc_arch)
    bl = load_blacklists()

    # 3) wiersze
    for r in rows:
        t, s = r["token_address"], r["spender"]
        allowance = int(r["allowance_raw"])
        bal = balances.get(t)
        dec = r.get("decimals")
        p = prices.get(t)
        r["balance_raw"] = None if bal is None else str(bal)
        r["price_usd"] = None
        r["price_confidence"] = None
        r["usd_at_risk"] = None
        if p:
            r["price_confidence"] = p[1]
        if bal is not None and p and p[1] >= PRICE_MIN_CONFIDENCE and r.get("decimals") is not None:
            exposed = min(allowance, bal)
            usd = Decimal(exposed) / (Decimal(10) ** r["decimals"]) * Decimal(repr(p[0]))
            r["price_usd"] = p[0]
            r["usd_at_risk"] = human_usd(float(usd))
            r["balance_fmt"] = str(Decimal(bal) / (Decimal(10) ** r["decimals"]))
        elif bal == 0:
            r["usd_at_risk"] = 0.0
        k = kinds.get(s)
        r["spender_kind"] = k  # None dla ukrytych
        cb = cblocks.get(s)
        r["spender_created_block"] = cb
        r["spender_created_ts"] = times.get(cb) if cb else None
        r["spender_age_days"] = (now - times[cb]) // 86400 if cb in times else None
        hitsbl = bl["index"].get(s, [])
        r["blacklist"] = [{"source": a, "label": b} for a, b in hitsbl]
        ts = times.get(r["last_approval_block"])
        r["approval_ts"] = ts
        r["days_since_approval"] = (now - ts) // 86400 if ts else None
        r["forgotten"] = bool(r["unlimited"] and ts and (now - ts) // 86400 >= FORGOTTEN_DAYS)

    score = resilience(visible)
    plan = cleanup_plan(visible)
    # Suma bez podwojnego liczenia: saldo tokena mozna ukrasc tylko raz, wiec dla kazdego
    # tokena bierzemy najwieksza ekspozycje sposrod jego zgod.
    per_token = {}
    for r in visible:
        if r["usd_at_risk"] is not None:
            per_token[r["token_address"]] = max(per_token.get(r["token_address"], 0), r["usd_at_risk"])
    total = sum(per_token.values())
    priced = sum(1 for r in visible if r["usd_at_risk"] is not None)
    result["usd_at_risk_total"] = round(total, 2)
    result["usd_priced_rows"] = priced
    result["usd_unpriced_rows"] = len(visible) - priced
    result["prices_ok"] = prices_ok
    result["price_source"] = {"name": "DefiLlama coins API", "url": "https://defillama.com/docs/api",
                              "min_confidence": PRICE_MIN_CONFIDENCE}
    result["blacklist_sources"] = bl["sources"]
    result["score"] = score
    result["plan"] = plan
    result["analyzed_at"] = now
    return result


# ---------- Wskaznik odpornosci (jawny wzor) ----------
SCORE_RULES = [
    # id, opis, punkty za sztuke, limit
    ("blacklist", "spender na publicznej czarnej liście", 25, 50),
    ("eoa", "zgoda dla zwykłego konta (EOA, także z delegacją EIP-7702)", 10, 20),
    ("unlimited", "zgoda nielimitowana", 4, 24),
    ("forgotten", "nielimitowana zgoda ustawiona ponad 365 dni temu i od tego czasu niezmieniana (zapomniana)", 2, 10),
    ("foreign", "zgoda ustawiona cudzą transakcją (podpis permit albo spam)", 3, 9),
]
USD_STEPS = [(100000, 25), (10000, 20), (1000, 15), (100, 10), (10, 5)]


def resilience(rows):
    ded = []
    counts = {
        "blacklist": sum(1 for r in rows if r["blacklist"]),
        "eoa": sum(1 for r in rows if (r.get("spender_kind") or "").startswith("eoa")),
        "unlimited": sum(1 for r in rows if r["unlimited"]),
        "forgotten": sum(1 for r in rows if r["forgotten"]),
        "foreign": sum(1 for r in rows if r["tx_sender"] and not r["own_transaction"]),
    }
    total = 0
    for rid, desc, pts, cap in SCORE_RULES:
        n = counts[rid]
        d = min(n * pts, cap)
        total += d
        ded.append({"id": rid, "label": desc, "count": n, "per_item": pts, "cap": cap, "points": d})
    per_token = {}
    for r in rows:
        if r["usd_at_risk"] is not None:
            per_token[r["token_address"]] = max(per_token.get(r["token_address"], 0), r["usd_at_risk"])
    usd = sum(per_token.values())
    du = 0
    for lim, pts in USD_STEPS:
        if usd >= lim:
            du = pts
            break
    total += du
    ded.append({"id": "usd", "label": "łączna kwota zagrożona (USD)", "count": round(usd, 2),
                "per_item": None, "cap": 25, "points": du,
                "rule": "≥10 $: −5, ≥100 $: −10, ≥1 000 $: −15, ≥10 000 $: −20, ≥100 000 $: −25"})
    value = max(0, 100 - total)
    grade = ("Twierdza" if value >= 80 else "Solidnie" if value >= 60 else
             "Do sprzątania" if value >= 40 else "Alarm")
    return {"value": value, "grade": grade, "deductions": ded}


def cleanup_plan(rows):
    def key(r):
        kind = r.get("spender_kind") or ""
        return (0 if r["blacklist"] else 1,
                -(r["usd_at_risk"] or 0),
                0 if (kind.startswith("eoa") and r["unlimited"]) else 1,
                0 if r["unlimited"] and not r["spender_name"] else 1,
                0 if r["unlimited"] else 1,
                -(r["days_since_approval"] or 0))
    plan = []
    for r in sorted([r for r in rows if r["risk"] != "NISKIE" or r["blacklist"] or (r["usd_at_risk"] or 0) > 0], key=key):
        why = []
        if r["blacklist"]:
            why.append("na czarnej liście")
        if (r["usd_at_risk"] or 0) > 0:
            why.append("zagrożone %.2f $" % r["usd_at_risk"])
        if (r.get("spender_kind") or "").startswith("eoa"):
            why.append("zwykłe konto (EOA)")
        if r["unlimited"]:
            why.append("bez limitu")
        if r["forgotten"]:
            why.append("bez zmian od %d dni" % r["days_since_approval"])
        if not r["spender_name"] and not (r.get("spender_kind") or "").startswith("eoa"):
            why.append("nieznany kontrakt")
        if r["tx_sender"] and not r["own_transaction"]:
            why.append("nie Twoja transakcja")
        plan.append({"token": r["token"], "token_address": r["token_address"], "spender": r["spender"],
                     "spender_name": r["spender_name"], "usd_at_risk": r["usd_at_risk"], "why": why})
    return plan
