#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""
zgody.py - skaner zgod (approvals) ERC-20 dla adresu Ethereum.

TYLKO ODCZYT: narzedzie nie zna zadnych kluczy prywatnych, nie laczy sie
z portfelem, niczego nie podpisuje i nie wysyla transakcji. Wysyla wylacznie
zapytania eth_getLogs / eth_call / eth_getCode / eth_blockNumber do
publicznych wezlow RPC Ethereum (bez kluczy API, bez rejestracji).

Wymagania: tylko python3 (biblioteka standardowa). Na Arch Linux: pacman -S python
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal, getcontext

getcontext().prec = 100
VERSION = "1.0"

# Publiczne wezly bez klucza API (sprawdzone 10.11.2026).
# eth_getLogs dla calej historii obsluguja tylko niektore:
LOG_ENDPOINTS = [
    "https://mainnet.gateway.tenderly.co",
    "https://rpc.mevblocker.io",
    "https://rpc.flashbots.net",
]
# eth_getTransactionByHash dla starych transakcji (publicnode nie ma pelnej historii):
TX_ENDPOINTS = [
    "https://rpc.mevblocker.io",
    "https://mainnet.gateway.tenderly.co",
    "https://eth.drpc.org",
]
# eth_call / eth_getCode (stan biezacy):
CALL_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://mainnet.gateway.tenderly.co",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
]

APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
SEL_ALLOWANCE = "0xdd62ed3e"  # allowance(address,address)
SEL_SYMBOL = "0x95d89b41"     # symbol()
SEL_DECIMALS = "0x313ce567"   # decimals()
MAX_UINT = 2 ** 256 - 1
UNLIMITED_THRESHOLD = 2 ** 255  # wszystko >= 2^255 traktujemy jak "bez limitu"

# Znane kontrakty (spender). Adresy w malych literach. Kazdy sprawdzony: ma kod w sieci
# (eth_getCode) + Uniswap/KyberSwap z oficjalnych docs, MetaMask wg etykiety Etherscan.
# "Znany" NIE znaczy "bezpieczny na zawsze" - to tylko znana marka, nie audyt.
KNOWN_SPENDERS = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router02",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
    "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router (stary)",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router v4",
    "0x4c82d1fbfe28c977cbb58d8c7ff8fcf9f70a2cca": "Uniswap Universal Router 2.1.1",
    "0x23617e59a5925b2a4bf75d73ff6711cd0b29de85": "Uniswap Universal Router 2.1.2",
    "0xc36442b4a4522e871399cd717abdd847ab11fe88": "Uniswap V3 Positions NFT",
    "0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e": "Uniswap V4 PositionManager",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Router v4",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch Router v5",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch Router v6",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0xdef171fe48cf0115b1d80b88dc8eab59176fee57": "ParaSwap Augustus v5",
    "0x6a000f20005980200259b80c5102003040001068": "ParaSwap Augustus v6",
    "0xc92e8bdf79f0507f65a392b0ab4667716bfe0110": "CoW Protocol VaultRelayer",
    "0xba12222222228d8ba445958a75a0704d566bf2c8": "Balancer Vault",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x881d40237659c251811cec9c364ef91dc08d300c": "MetaMask Swap Router",
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": "Aave V2 LendingPool",
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool",
    "0xc3d688b66703497daa19211eedff47f25384cdc3": "Compound V3 cUSDCv3",
    "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap MetaAggregationRouterV2",
    "0x6868d319c8c9a78f7d39dc3602c5c917315132d7": "KyberSwap AggregationRouterV3",
}

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text, code):
    return "\033[%sm%s\033[0m" % (code, text) if USE_COLOR else text


def info(msg):
    print(msg, file=sys.stderr, flush=True)


class RPCError(Exception):
    pass


class RPC:
    def __init__(self, endpoints, timeout=60, retries=2, verbose=False):
        self.endpoints = list(endpoints)
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self._id = 0

    def _post(self, url, payload):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "zgody.py/%s (read-only)" % VERSION})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def call_on(self, url, method, params):
        """Jedno zapytanie na konkretny wezel. Rzuca RPCError z opisem."""
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        try:
            resp = self._post(url, payload)
        except urllib.error.HTTPError as e:
            raise RPCError("HTTP %s" % e.code)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RPCError("polaczenie/timeout: %s" % getattr(e, "reason", e))
        except ValueError:
            raise RPCError("niepoprawna odpowiedz (nie JSON)")
        if isinstance(resp, dict) and resp.get("error"):
            raise RPCError(str(resp["error"].get("message", resp["error"]))[:200])
        if not isinstance(resp, dict) or "result" not in resp:
            raise RPCError("brak pola result")
        return resp["result"]

    def call(self, method, params):
        """Zapytanie z ponawianiem i przelaczaniem na kolejne wezly."""
        last = None
        for url in self.endpoints:
            for attempt in range(self.retries + 1):
                try:
                    return self.call_on(url, method, params)
                except RPCError as e:
                    last = e
                    if self.verbose:
                        info("  [%s] %s: %s" % (url, method, e))
                    if is_rate_limit(str(e)):
                        time.sleep(2 * (attempt + 1))
                        continue
                    if "execution reverted" in str(e).lower() or "revert" in str(e).lower():
                        raise
                    time.sleep(0.5)
        raise RPCError("wszystkie wezly zawiodly (%s)" % last)

    def batch(self, calls):
        """calls = [(method, params), ...] -> lista (wynik albo RPCError)."""
        results = [None] * len(calls)
        payload = []
        for i, (m, p) in enumerate(calls):
            payload.append({"jsonrpc": "2.0", "id": i, "method": m, "params": p})
        for url in self.endpoints:
            for attempt in range(min(self.retries, 1) + 1):
                try:
                    resp = self._post(url, payload)
                    if not isinstance(resp, list):
                        raise RPCError("wezel nie obsluguje batch")
                    got = {}
                    for item in resp:
                        if "error" in item and item["error"]:
                            got[item.get("id")] = RPCError(str(item["error"].get("message", "")))
                        else:
                            got[item.get("id")] = item.get("result")
                    # jesli wezel odrzucil metode globalnie (np. rate limit) - probuj dalej
                    errs = [v for v in got.values() if isinstance(v, RPCError)]
                    if errs and all(is_rate_limit(str(e)) or "not whitelisted" in str(e) for e in errs) \
                            and len(errs) == len(calls):
                        raise RPCError(str(errs[0]))
                    for i in range(len(calls)):
                        results[i] = got.get(i, RPCError("brak odpowiedzi"))
                    return results
                except urllib.error.HTTPError as e:
                    err = "HTTP %s" % e.code
                except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
                    err = "polaczenie/timeout: %s" % e
                except RPCError as e:
                    err = str(e)
                if self.verbose:
                    info("  [%s] batch: %s" % (url, err))
                time.sleep(1 if is_rate_limit(err) else 0.3)
        # wezly odrzucaja duza paczke -> dziel na polowy
        if len(calls) > 10:
            half = len(calls) // 2
            return self.batch(calls[:half]) + self.batch(calls[half:])
        # ostatecznie: pojedynczo
        for i, (m, p) in enumerate(calls):
            try:
                results[i] = self.call(m, p)
            except RPCError as e:
                results[i] = e
        return results


def is_rate_limit(msg):
    m = msg.lower()
    if "range" in m or "block" in m:
        return False
    return any(k in m for k in ("429", "rate limit", "too many requests", "usage limit", "rate exceeded"))


def is_range_error(msg):
    m = msg.lower()
    return any(k in m for k in (
        "range", "too many", "limit", "exceed", "timeout", "time-out", "timed out",
        "504", "503", "502", "temporarily unavailable", "response size", "query returned more",
        "pruned"))


def get_logs(owner, from_block, to_block, endpoints, verbose=False, timeout=90):
    """Pobiera logi Approval z dzieleniem zakresu blokow na kawalki."""
    rpc = RPC(endpoints, timeout=timeout, retries=0, verbose=verbose)
    topic_owner = "0x" + owner[2:].lower().rjust(64, "0")
    logs = []
    ep_idx = 0
    cur = from_block
    chunk = to_block - from_block + 1
    MIN_CHUNK = 1000
    fails_here = 0
    while cur <= to_block:
        end = min(cur + chunk - 1, to_block)
        url = endpoints[ep_idx]
        params = [{"fromBlock": hex(cur), "toBlock": hex(end),
                   "topics": [APPROVAL_TOPIC, topic_owner]}]
        try:
            res = rpc.call_on(url, "eth_getLogs", params)
            logs.extend(res)
            info("  bloki %d-%d: %d logow (%s)" % (cur, end, len(res), short_host(url)))
            cur = end + 1
            fails_here = 0
            chunk = min(chunk * 2, to_block - from_block + 1)
        except RPCError as e:
            msg = str(e)
            if verbose:
                info("  [%s] %d-%d: %s" % (short_host(url), cur, end, msg))
            if is_rate_limit(msg) and fails_here < 3:
                fails_here += 1
                time.sleep(3 * fails_here)
                continue
            if is_range_error(msg) and chunk > MIN_CHUNK:
                chunk = max(chunk // 4, MIN_CHUNK)
                continue
            # zmiana wezla
            ep_idx += 1
            fails_here = 0
            chunk = to_block - cur + 1
            if ep_idx >= len(endpoints):
                raise RPCError("nie udalo sie pobrac logow dla blokow %d-%d (%s)" % (cur, end, msg))
            info("  przelaczam na %s" % short_host(endpoints[ep_idx]))
    return logs


def short_host(url):
    return url.split("//", 1)[-1].split("/", 1)[0]


def enc_addr(a):
    return a[2:].lower().rjust(64, "0")


def decode_uint(hexstr):
    if not hexstr or hexstr == "0x":
        return None
    try:
        return int(hexstr[2:66] or "0", 16) if len(hexstr) > 66 else int(hexstr, 16)
    except ValueError:
        return None


def decode_string(hexstr):
    """symbol(): zwykly string ABI albo bytes32 (np. MKR)."""
    if not hexstr or hexstr == "0x":
        return None
    raw = bytes.fromhex(hexstr[2:])
    try:
        if len(raw) >= 96:
            off = int.from_bytes(raw[0:32], "big")
            ln = int.from_bytes(raw[off:off + 32], "big")
            s = raw[off + 32: off + 32 + ln].decode("utf-8", "replace")
        else:
            s = raw[:32].rstrip(b"\0").decode("utf-8", "replace")
    except Exception:
        return None
    s = "".join(ch for ch in s if ch.isprintable()).strip()
    return s[:16] if s else None


def fmt_amount(value, decimals):
    if value >= UNLIMITED_THRESHOLD:
        return "NIELIMITOWANA"
    if decimals is None:
        return "%d (surowo)" % value
    d = Decimal(value) / (Decimal(10) ** decimals)
    if d >= Decimal(10) ** 12:
        return "%.3e" % d
    if d < Decimal("0.0001"):
        return "<0.0001"
    s = "{:,.4f}".format(d).rstrip("0").rstrip(".")
    return s.replace(",", " ")


def parse_block(s, latest):
    s = str(s).strip().lower()
    if s == "latest":
        return latest
    if s.startswith("-"):
        return max(0, latest - int(s[1:]))
    return int(s, 16) if s.startswith("0x") else int(s)


def build_parser():
    p = argparse.ArgumentParser(
        prog="zgody.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Skaner zgod ERC-20 (approvals) dla adresu Ethereum - TYLKO ODCZYT.\n"
            "Szuka zdarzen Approval wystawionych przez adres, sprawdza AKTUALNA zgode\n"
            "przez allowance() i oznacza ryzykowne (nielimitowane, dla zwyklych kont,\n"
            "dla nieznanych kontraktow). Nie uzywa kluczy, portfela ani transakcji."),
        epilog=(
            "Przyklady:\n"
            "  python3 zgody.py 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\n"
            "  python3 zgody.py ADRES --from-block -2600000      (ok. ostatni rok)\n"
            "  python3 zgody.py ADRES --from-block 18000000 --to-block 19000000\n"
            "  python3 zgody.py ADRES --only-risky --json > wynik.json\n\n"
            "Ryzyko: WYSOKIE = zgoda bez limitu; SREDNIE = zgoda dla zwyklego konta (EOA)\n"
            "lub nieznanego kontraktu; NISKIE = ograniczona zgoda dla znanego kontraktu.\n"
            "Cofanie zgod: https://revoke.cash/address/ADRES (robisz to sam w portfelu)."),
    )
    p.add_argument("address", help="adres Ethereum 0x... (40 znakow hex; ENS nieobslugiwany)")
    p.add_argument("--from-block", default="0",
                   help="blok poczatkowy: numer, 0x.., albo -N = ostatnie N blokow (domyslnie 0 = cala historia)")
    p.add_argument("--to-block", default="latest", help="blok koncowy (domyslnie latest)")
    p.add_argument("--rpc", action="append",
                   help="wlasny wezel RPC (mozna podac kilka razy); zastepuje wbudowana liste")
    p.add_argument("--only-risky", action="store_true", help="pokaz tylko WYSOKIE i SREDNIE")
    p.add_argument("--show-unknown-tokens", action="store_true",
                   help="pokaz tez tokeny bez symbolu/decimals (czesto spam)")
    p.add_argument("--all", action="store_true",
                   help="pokaz wszystko, takze zdarzenia z cudzych tx dla znanych routerow (zwykle spam)")
    p.add_argument("--json", action="store_true", help="wynik w JSON (do skryptow)")
    p.add_argument("--no-color", action="store_true", help="bez kolorow")
    p.add_argument("--timeout", type=int, default=90, help="timeout zapytania w sekundach (domyslnie 90)")
    p.add_argument("-v", "--verbose", action="store_true", help="pokazuj bledy wezlow")
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    return p


def main():
    global USE_COLOR
    args = build_parser().parse_args()
    if args.no_color or args.json:
        USE_COLOR = False

    owner = args.address.strip()
    if not (owner.startswith("0x") and len(owner) == 42):
        info("Blad: podaj adres w formacie 0x + 40 znakow hex (ENS typu nazwa.eth nie jest obslugiwany).")
        return 2
    try:
        int(owner[2:], 16)
    except ValueError:
        info("Blad: adres zawiera niedozwolone znaki.")
        return 2
    owner = owner.lower()

    log_eps = args.rpc or LOG_ENDPOINTS
    call_eps = args.rpc or CALL_ENDPOINTS
    rpc = RPC(call_eps, timeout=min(args.timeout, 60), verbose=args.verbose)

    try:
        latest = int(rpc.call("eth_blockNumber", []), 16)
        from_b = parse_block(args.from_block, latest)
        to_b = parse_block(args.to_block, latest)
    except (RPCError, ValueError) as e:
        info("Blad: nie moge odczytac numeru bloku / zly parametr: %s" % e)
        return 1
    if from_b > to_b:
        info("Blad: --from-block jest wiekszy niz --to-block.")
        return 2

    info("Adres: %s | bloki %d-%d (ostatni: %d)" % (owner, from_b, to_b, latest))
    info("1/3 Pobieram zdarzenia Approval (eth_getLogs)...")
    t0 = time.time()
    try:
        logs = get_logs(owner, from_b, to_b, log_eps, args.verbose, args.timeout)
    except RPCError as e:
        info("Blad: %s" % e)
        info("Sprobuj mniejszego zakresu (--from-block -500000) albo pozniej (limity publicznych wezlow).")
        return 1

    # Tylko ERC-20: 3 tematy (ERC-721 ma 4 - tokenId jest indeksowany)
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
    info("  %d zdarzen, %d unikalnych par token/spender (pominieto %d zdarzen NFT ERC-721)"
         % (len(logs), len(pairs), nft_skipped))

    info("2/3 Sprawdzam AKTUALNE zgody allowance() (eth_call)...")
    allowances = {}
    BATCH = 100
    for i in range(0, len(pairs), BATCH):
        part = pairs[i:i + BATCH]
        calls = [("eth_call", [{"to": t, "data": SEL_ALLOWANCE + enc_addr(owner) + enc_addr(s)}, "latest"])
                 for t, s in part]
        res = rpc.batch(calls)
        for (t, s), r in zip(part, res):
            allowances[(t, s)] = None if isinstance(r, RPCError) else decode_uint(r)
        info("  %d/%d" % (min(i + BATCH, len(pairs)), len(pairs)))
        time.sleep(0.2)

    active = [(k, v) for k, v in allowances.items() if v]
    unreadable = sum(1 for v in allowances.values() if v is None)

    info("3/3 Pobieram dane tokenow i sprawdzam spenderow...")
    tokens = sorted({t for (t, _), _v in active})
    spenders = sorted({s for (_, s), _v in active})
    meta = {}
    calls = []
    for t in tokens:
        calls.append(("eth_call", [{"to": t, "data": SEL_SYMBOL}, "latest"]))
        calls.append(("eth_call", [{"to": t, "data": SEL_DECIMALS}, "latest"]))
    codes = {}
    for s in spenders:
        calls.append(("eth_getCode", [s, "latest"]))
    results = []
    for i in range(0, len(calls), BATCH):
        results.extend(rpc.batch(calls[i:i + BATCH]))
        time.sleep(0.2)
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

    # Kto wyslal transakcje z ostatnim Approval? Jesli nie wlasciciel, to byl to
    # podpis offline (permit) albo falszywe zdarzenie wyemitowane przez spam-token.
    tx_hashes = sorted({latest_by_pair[k][1]["transactionHash"] for k, _v in active})
    tx_from = {}
    tx_eps = args.rpc or TX_ENDPOINTS
    rpc_tx = RPC(tx_eps, timeout=min(args.timeout, 60), verbose=args.verbose)
    for i in range(0, len(tx_hashes), BATCH):
        part = tx_hashes[i:i + BATCH]
        res = rpc_tx.batch([("eth_getTransactionByHash", [h]) for h in part])
        for h, r in zip(part, res):
            tx_from[h] = r.get("from", "").lower() if isinstance(r, dict) else None
        time.sleep(0.2)
    for h in [h for h, f in tx_from.items() if not f]:  # brak wyniku -> sprobuj innych wezlow
        for url in tx_eps:
            try:
                r = rpc_tx.call_on(url, "eth_getTransactionByHash", [h])
            except RPCError:
                continue
            if isinstance(r, dict) and r.get("from"):
                tx_from[h] = r["from"].lower()
                break

    rows = []
    hidden_unknown = 0
    hidden_foreign = 0
    for (t, s), v in active:
        sym, dec = meta.get(t, (None, None))
        if (sym is None or dec is None) and not args.show_unknown_tokens:
            hidden_unknown += 1
            continue
        known = KNOWN_SPENDERS.get(s)
        is_contract = codes.get(s)
        sender = tx_from.get(latest_by_pair[(t, s)][1]["transactionHash"])
        own_tx = sender == owner
        if not own_tx and known and not args.all:
            # zdarzenie nie z Twojej transakcji + znany router = typowy spam memecoinow
            hidden_foreign += 1
            continue
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
        if unlimited:
            risk = "WYSOKIE"
        elif known:
            risk = "NISKIE"
        else:
            risk = "SREDNIE"
        if is_contract is False and unlimited:
            notes[-1] = "zwykle konto (EOA) + bez limitu - bardzo podejrzane!"
        blk = latest_by_pair[(t, s)][0][0]
        rows.append({
            "token": sym or "?", "token_address": t, "spender": s, "spender_name": known,
            "spender_is_contract": is_contract, "allowance_raw": str(v),
            "allowance": fmt_amount(v, dec), "unlimited": unlimited, "risk": risk,
            "note": "; ".join(notes), "last_approval_block": blk,
            "own_transaction": own_tx, "tx_sender": sender,
            "tx_hash": latest_by_pair[(t, s)][1]["transactionHash"],
        })
    order = {"WYSOKIE": 0, "SREDNIE": 1, "NISKIE": 2}
    rows.sort(key=lambda r: (order[r["risk"]], r["token"].lower()))
    if args.only_risky:
        rows = [r for r in rows if r["risk"] != "NISKIE"]

    elapsed = time.time() - t0
    if args.json:
        print(json.dumps({"owner": owner, "from_block": from_b, "to_block": to_b,
                          "approval_events": len(logs), "pairs_checked": len(pairs),
                          "active_allowances": len(active), "hidden_unknown_tokens": hidden_unknown,
                          "hidden_foreign_known": hidden_foreign,
                          "unreadable": unreadable, "rows": rows}, indent=2, ensure_ascii=False))
        return 0

    print()
    print(c("ZGODY ERC-20 dla %s" % owner, "1"))
    print("Zakres blokow: %d-%d | zdarzen Approval: %d | par sprawdzonych: %d | czas: %.0fs"
          % (from_b, to_b, len(logs), len(pairs), elapsed))
    print()
    if not rows:
        print(c("Brak aktywnych zgod do pokazania (wszystkie cofniete albo zero).", "32"))
    else:
        hdr = "%-4s %-12s %-42s %-18s %-8s %s" % ("#", "TOKEN", "SPENDER (kto moze wydawac)", "ZGODA", "RYZYKO", "UWAGI")
        print(c(hdr, "1"))
        print("-" * len(hdr) + "-" * 20)
        colors = {"WYSOKIE": "1;31", "SREDNIE": "33", "NISKIE": "32"}
        for i, r in enumerate(rows, 1):
            print("%-4d %-12s %-42s %-18s %s %s" % (
                i, r["token"][:12], r["spender"], r["allowance"][:18],
                c("%-8s" % r["risk"], colors[r["risk"]]), r["note"]))
            print("     token: %s" % r["token_address"])
    print()
    cnt = {k: sum(1 for r in rows if r["risk"] == k) for k in order}
    print("Podsumowanie: WYSOKIE %d | SREDNIE %d | NISKIE %d" % (cnt["WYSOKIE"], cnt["SREDNIE"], cnt["NISKIE"]))
    if hidden_unknown:
        print("Ukryto %d zgod na tokeny bez symbolu/decimals (zwykle spam) - pokaz: --show-unknown-tokens"
              % hidden_unknown)
    if hidden_foreign:
        print("Ukryto %d zgod z cudzych transakcji dla znanych routerow (typowy spam memecoinow) - pokaz: --all"
              % hidden_foreign)
    if unreadable:
        print("Nie udalo sie odczytac allowance dla %d par (token zepsuty/spam lub blad wezla)." % unreadable)
    print()
    print(c("Jak cofnac zgode (revoke):", "1"))
    print("  1. Otworz https://revoke.cash/address/%s" % owner)
    print("  2. Polacz SWOJ portfel tylko na oficjalnej stronie revoke.cash i kliknij Revoke przy zgodzie.")
    print("  3. Cofniecie to transakcja w sieci - kosztuje gaz. To narzedzie NIGDY niczego nie wysyla.")
    print("Uwaga: 'NIELIMITOWANA' = kontrakt moze zabrac WSZYSTKIE tokeny tego typu, takze te kupione pozniej.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        info("\nPrzerwano (Ctrl+C).")
        sys.exit(130)
