# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""scanner.py - logika zgody.py jako funkcja (dla serwera www).

Uzywa bez zmian funkcji i list z zgody.py (RPC, get_logs, KNOWN_SPENDERS,
reguly ryzyka). TYLKO ODCZYT: zadnych kluczy, portfela ani transakcji.
"""
import os
import threading
import time

import zgody
from zgody import (RPC, RPCError, get_logs, enc_addr, decode_uint, decode_string,
                   fmt_amount, KNOWN_SPENDERS, UNLIMITED_THRESHOLD, SEL_ALLOWANCE,
                   SEL_SYMBOL, SEL_DECIMALS)

YEAR_BLOCKS = 2600000
BATCH = 100

# Komunikaty postepu z get_logs() (zgody.info) kierujemy do zadania biezacego watku.
_tl = threading.local()
_orig_info = zgody.info


def _info(msg):
    cb = getattr(_tl, "cb", None)
    if cb:
        cb(None, msg.strip())
    else:
        _orig_info(msg)


zgody.info = _info


def endpoints():
    """Lista wezlow; ZGODY_RPC (przecinki) nadpisuje wszystkie - do testow / wlasnego wezla."""
    o = os.environ.get("ZGODY_RPC", "").strip()
    if o:
        lst = [u.strip() for u in o.split(",") if u.strip()]
        return lst, lst, lst
    return zgody.LOG_ENDPOINTS, zgody.CALL_ENDPOINTS, zgody.TX_ENDPOINTS


class ScanError(Exception):
    pass


def resolve_range(rng, latest):
    """rng: 'all' | 'year' | 'OD-DO' (DO moze byc 'latest' albo puste)."""
    if rng == "all":
        return 0, latest
    if rng == "year":
        return max(0, latest - YEAR_BLOCKS), latest
    a, _, b = rng.partition("-")
    f = int(a)
    t = latest if b in ("", "latest") else min(int(b), latest)
    if f > t:
        raise ScanError("Blok początkowy jest większy niż końcowy (najnowszy blok: %d)." % latest)
    return f, t


def scan(owner, rng, progress=None, timeout=90):
    """Zwraca slownik jak `zgody.py --json` + wszystkie wiersze z flagami
    hidden_unknown / hidden_foreign (filtrowanie robi frontend jak flagi CLI)."""
    def prog(pct, msg):
        if progress:
            progress(pct, msg)
    owner = owner.lower()
    log_eps, call_eps, tx_eps = endpoints()
    rpc = RPC(call_eps, timeout=min(timeout, 60))
    t0 = time.time()
    prog(2, "Łączę się z siecią Ethereum...")
    try:
        latest = int(rpc.call("eth_blockNumber", []), 16)
    except RPCError as e:
        raise ScanError("Nie mogę połączyć się z żadnym publicznym węzłem Ethereum. "
                        "Spróbuj za kilka minut. (%s)" % e)
    from_b, to_b = resolve_range(rng, latest)
    prog(5, "1/3 Pobieram zdarzenia Approval (bloki %d–%d)..." % (from_b, to_b))
    _tl.cb = lambda p, m: prog(None, "1/3 " + m)
    try:
        logs = get_logs(owner, from_b, to_b, log_eps, False, timeout)
    except RPCError as e:
        raise ScanError("Wszystkie publiczne węzły odmówiły pobrania historii. Spróbuj krótszego "
                        "zakresu (np. „ostatni rok”) albo za kilka minut. Szczegóły: %s" % e)
    finally:
        _tl.cb = None

    latest_by_pair = {}
    nft_skipped = 0
    for lg in logs:
        topics = lg.get("topics", [])
        if len(topics) != 3:
            nft_skipped += 1
            continue
        token = lg["address"].lower()
        spender = "0x" + topics[2][-40:].lower()
        key = (token, spender)
        pos = (int(lg["blockNumber"], 16), int(lg.get("logIndex", "0x0"), 16))
        if key not in latest_by_pair or pos > latest_by_pair[key][0]:
            latest_by_pair[key] = (pos, lg)
    pairs = list(latest_by_pair.keys())

    prog(40, "2/3 Sprawdzam aktualne zgody allowance() – %d par..." % len(pairs))
    allowances = {}
    for i in range(0, len(pairs), BATCH):
        part = pairs[i:i + BATCH]
        calls = [("eth_call", [{"to": t, "data": SEL_ALLOWANCE + enc_addr(owner) + enc_addr(s)}, "latest"])
                 for t, s in part]
        res = rpc.batch(calls)
        for (t, s), r in zip(part, res):
            allowances[(t, s)] = None if isinstance(r, RPCError) else decode_uint(r)
        done = min(i + BATCH, len(pairs))
        prog(40 + 35 * done // max(1, len(pairs)), "2/3 Zgody: %d/%d" % (done, len(pairs)))
        time.sleep(0.2)
    active = [(k, v) for k, v in allowances.items() if v]
    unreadable = sum(1 for v in allowances.values() if v is None)

    prog(76, "3/3 Pobieram dane tokenów i sprawdzam spenderów...")
    tokens = sorted({t for (t, _), _v in active})
    spenders = sorted({s for (_, s), _v in active})
    calls = []
    for t in tokens:
        calls.append(("eth_call", [{"to": t, "data": SEL_SYMBOL}, "latest"]))
        calls.append(("eth_call", [{"to": t, "data": SEL_DECIMALS}, "latest"]))
    for s in spenders:
        calls.append(("eth_getCode", [s, "latest"]))
    results = []
    for i in range(0, len(calls), BATCH):
        results.extend(rpc.batch(calls[i:i + BATCH]))
        time.sleep(0.2)
    meta, codes = {}, {}
    for idx, t in enumerate(tokens):
        sym_r, dec_r = results[2 * idx], results[2 * idx + 1]
        sym = None if isinstance(sym_r, RPCError) else decode_string(sym_r)
        dec = None if isinstance(dec_r, RPCError) else decode_uint(dec_r)
        if dec is not None and dec > 77:
            dec = None
        meta[t] = (sym, dec)
    off = 2 * len(tokens)
    for idx, s in enumerate(spenders):
        r = results[off + idx]
        codes[s] = None if isinstance(r, RPCError) else (r not in ("0x", "0x0", None))

    prog(88, "3/3 Sprawdzam, kto wysłał transakcje ze zgodami...")
    tx_hashes = sorted({latest_by_pair[k][1]["transactionHash"] for k, _v in active})
    tx_from = {}
    rpc_tx = RPC(tx_eps, timeout=min(timeout, 60))
    for i in range(0, len(tx_hashes), BATCH):
        part = tx_hashes[i:i + BATCH]
        res = rpc_tx.batch([("eth_getTransactionByHash", [h]) for h in part])
        for h, r in zip(part, res):
            tx_from[h] = r.get("from", "").lower() if isinstance(r, dict) else None
        time.sleep(0.2)
    for h in [h for h, f in tx_from.items() if not f]:
        for url in tx_eps:
            try:
                r = rpc_tx.call_on(url, "eth_getTransactionByHash", [h])
            except RPCError:
                continue
            if isinstance(r, dict) and r.get("from"):
                tx_from[h] = r["from"].lower()
                break

    rows = []
    for (t, s), v in active:
        sym, dec = meta.get(t, (None, None))
        known = KNOWN_SPENDERS.get(s)
        is_contract = codes.get(s)
        sender = tx_from.get(latest_by_pair[(t, s)][1]["transactionHash"])
        own_tx = sender == owner
        notes = []
        if sender is None:
            notes.append("nie znam nadawcy tx")
        elif not own_tx:
            notes.append("NIE Twoja tx (permit-podpis albo spam)")
        unlimited = v >= UNLIMITED_THRESHOLD
        if known:
            notes.append("znany: " + known)
        elif is_contract is False:
            notes.append("zwykle konto (EOA) - podejrzane!")
        elif is_contract is None:
            notes.append("nie udalo sie sprawdzic")
        else:
            notes.append("nieznany kontrakt - sprawdz na etherscan")
        risk = "WYSOKIE" if unlimited else ("NISKIE" if known else "SREDNIE")
        if is_contract is False and unlimited:
            notes[-1] = "zwykle konto (EOA) + bez limitu - bardzo podejrzane!"
        rows.append({
            "token": sym or "?", "token_address": t, "spender": s, "spender_name": known,
            "spender_is_contract": is_contract, "allowance_raw": str(v),
            "allowance": fmt_amount(v, dec), "decimals": dec, "unlimited": unlimited, "risk": risk,
            "notes": notes, "note": "; ".join(notes),
            "last_approval_block": latest_by_pair[(t, s)][0][0],
            "own_transaction": own_tx, "tx_sender": sender,
            "tx_hash": latest_by_pair[(t, s)][1]["transactionHash"],
            "hidden_unknown": sym is None or dec is None,   # CLI: ukryte bez --show-unknown-tokens
            "hidden_foreign": (not own_tx) and bool(known),  # CLI: ukryte bez --all
        })
    order = {"WYSOKIE": 0, "SREDNIE": 1, "NISKIE": 2}
    rows.sort(key=lambda r: (order[r["risk"]], r["token"].lower()))
    visible = [r for r in rows if not r["hidden_unknown"] and not r["hidden_foreign"]]
    summary = {k: sum(1 for r in visible if r["risk"] == k) for k in order}
    prog(89, "Skan zgód gotowy.")
    return {"owner": owner, "from_block": from_b, "to_block": to_b, "latest_block": latest,
            "approval_events": len(logs), "pairs_checked": len(pairs), "nft_events_skipped": nft_skipped,
            "active_allowances": len(active), "unreadable": unreadable,
            "hidden_unknown_tokens": sum(1 for r in rows if r["hidden_unknown"]),
            "hidden_foreign_known": sum(1 for r in rows if r["hidden_foreign"] and not r["hidden_unknown"]),
            "summary": summary, "seconds": round(time.time() - t0, 1),
            "revoke_url": "https://revoke.cash/address/" + owner, "rows": rows}
