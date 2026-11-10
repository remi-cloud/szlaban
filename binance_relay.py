# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""binance_relay.py - minimalny przekaznik (relay) dla modulu Binance Guard.

PROJEKT BEZPIECZENSTWA (patrz README, sekcja Binance Guard):
  * Przegladarka sama podpisuje zapytanie (HMAC-SHA256, WebCrypto). SEKRET NIGDY tu nie trafia.
  * Relay dostaje tylko: nazwe endpointu z listy dozwolonych, API key, timestamp, recvWindow
    i gotowy podpis (64 znaki hex). Kazde pole jest walidowane osobno, a zapytanie jest
    skladane od nowa w stalej kolejnosci "timestamp=..&recvWindow=..&signature=..".
  * Tylko GET i tylko endpointy TYLKO DO ODCZYTU z listy ENDPOINTS (zweryfikowane w oficjalnej
    specyfikacji Binance: github.com/binance/binance-api-swagger, spot_api.yaml).
  * Nic nie jest logowane ani zapisywane (ani klucz, ani podpis, ani odpowiedz). Brak cache.
  * Bez przekierowan, limit czasu 10 s, limit rozmiaru odpowiedzi 512 KB.
Tylko biblioteka standardowa Pythona.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request

API_BASE = os.environ.get("BINANCE_API_BASE", "https://api.binance.com").rstrip("/")
TIMEOUT = 10
MAX_BODY = 512 * 1024
MAX_SKEW_MS = 5 * 60 * 1000   # timestamp musi byc w +-5 min od zegara serwera (przeciw powtorkom)

# nazwa -> (sciezka, czy podpisane). Tylko odczyt (USER_DATA / NONE). Zadnych endpointow TRADE/wyplat.
ENDPOINTS = {
    "time": ("/api/v3/time", False),
    "apiRestrictions": ("/sapi/v1/account/apiRestrictions", True),
    "accountStatus": ("/sapi/v1/account/status", True),
    "apiTradingStatus": ("/sapi/v1/account/apiTradingStatus", True),
    "withdrawAddressList": ("/sapi/v1/capital/withdraw/address/list", True),
}
APIKEY_RE = re.compile(r"^[A-Za-z0-9]{16,128}$")
SIG_RE = re.compile(r"^[0-9a-fA-F]{64}$")
TS_RE = re.compile(r"^\d{13}$")
RW_RE = re.compile(r"^\d{1,5}$")


class RelayError(Exception):
    def __init__(self, status, code, msg):
        Exception.__init__(self, code)
        self.status, self.code, self.msg = status, code, msg


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def build_request(data, now_ms=None):
    """Waliduje dane od przegladarki. Zwraca (url, headers). Rzuca RelayError."""
    if not isinstance(data, dict):
        raise RelayError(400, "bad_request", "JSON object expected.")
    allowed = {"endpoint", "apiKey", "timestamp", "recvWindow", "signature"}
    if set(data) - allowed:
        raise RelayError(400, "bad_field", "Unknown field. Never send your secret key.")
    name = data.get("endpoint")
    if not isinstance(name, str) or name not in ENDPOINTS:
        raise RelayError(400, "endpoint_not_allowed", "Endpoint not on the read-only allowlist.")
    path, signed = ENDPOINTS[name]
    if not signed:
        return API_BASE + path, {}
    key, ts, rw, sig = (str(data.get(k, "")) for k in ("apiKey", "timestamp", "recvWindow", "signature"))
    if not APIKEY_RE.match(key):
        raise RelayError(400, "bad_api_key", "API key format invalid.")
    if not TS_RE.match(ts):
        raise RelayError(400, "bad_timestamp", "Timestamp must be 13 digits (ms).")
    if not RW_RE.match(rw) or not 1 <= int(rw) <= 60000:
        raise RelayError(400, "bad_recv_window", "recvWindow must be 1-60000.")
    if not SIG_RE.match(sig):
        raise RelayError(400, "bad_signature", "Signature must be 64 hex characters (HMAC-SHA256).")
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if abs(now_ms - int(ts)) > MAX_SKEW_MS:
        raise RelayError(400, "stale_timestamp", "Timestamp too far from server time. Check your clock.")
    q = "timestamp=%s&recvWindow=%s&signature=%s" % (ts, rw, sig.lower())
    return API_BASE + path + "?" + q, {"X-MBX-APIKEY": key}


def call(data, now_ms=None):
    """Zwraca (status_http, slownik_json). Nigdy nie loguje danych wejsciowych."""
    url, headers = build_request(data, now_ms)
    headers = dict(headers)
    headers["User-Agent"] = "szlaban-binance-guard/1.0"
    headers["Accept"] = "application/json"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            status, body = r.status, r.read(MAX_BODY + 1)
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(MAX_BODY + 1)
    except (urllib.error.URLError, OSError, ValueError):
        raise RelayError(502, "upstream_unreachable", "Binance API unreachable from this server.")
    if len(body) > MAX_BODY:
        raise RelayError(502, "upstream_too_large", "Response too large.")
    try:
        parsed = json.loads(body.decode("utf-8")) if body else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    if status in (451, 403) and not (isinstance(parsed, dict) and isinstance(parsed.get("code"), int) and parsed.get("code") < 0):
        # CloudFront: "Service unavailable from a restricted location" (np. serwer w USA)
        raise RelayError(451, "geo_blocked", "Binance refuses requests from this server's location.")
    if 300 <= status < 400:
        raise RelayError(502, "upstream_redirect", "Unexpected redirect from upstream.")
    if status == 429 or status == 418:
        raise RelayError(429, "binance_rate_limit", "Binance rate limit hit. Wait a few minutes.")
    if status != 200:
        if isinstance(parsed, dict) and "code" in parsed:
            return 400, {"error": "binance_error", "binance_code": parsed.get("code"),
                         "binance_msg": str(parsed.get("msg", ""))[:300]}
        raise RelayError(502, "upstream_error", "Binance API error (HTTP %d)." % status)
    if parsed is None:
        raise RelayError(502, "upstream_bad_json", "Invalid JSON from upstream.")
    return 200, {"data": parsed}
