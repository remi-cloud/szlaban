# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""Testy relay Binance Guard (bez internetu, z lokalnym udawanym API):  python3 -m unittest tests/test_relay.py"""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import binance_relay as R  # noqa: E402

SIG = "a" * 64
KEY = "TESTKEYdoNotLog" + "x" * 49


class Fake(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Fake.seen.append((self.path, self.headers.get("X-MBX-APIKEY")))
        mode = Fake.mode
        if mode == "ok":
            body, code = (b'{"serverTime": 1}' if self.path == "/api/v3/time" else b'{"ipRestrict":true,"enableWithdrawals":false}'), 200
        elif mode == "geo":
            body, code = b'{"code":0,"msg":"Service unavailable from a restricted location"}', 451
        elif mode == "badkey":
            body, code = b'{"code":-2015,"msg":"Invalid API-key, IP, or permissions for action."}', 401
        elif mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/x")
            self.end_headers()
            return
        elif mode == "big":
            body, code = b"[" + b"1," * (R.MAX_BODY) + b"1]", 200
        else:
            body, code = b"<html>", 500
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def now_ms():
    return int(time.time() * 1000)


def req(endpoint="apiRestrictions", **kw):
    d = {"endpoint": endpoint, "apiKey": KEY, "timestamp": str(now_ms()), "recvWindow": "10000", "signature": SIG}
    d.update(kw)
    return d


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.old = R.API_BASE
        R.API_BASE = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        R.API_BASE = cls.old

    def setUp(self):
        Fake.seen = []
        Fake.mode = "ok"

    def bad(self, data, code):
        with self.assertRaises(R.RelayError) as c:
            R.build_request(data)
        self.assertEqual(c.exception.code, code)

    def test_allowlist(self):
        self.assertEqual(set(R.ENDPOINTS), {"time", "apiRestrictions", "accountStatus", "apiTradingStatus", "withdrawAddressList"})
        for p, _s in R.ENDPOINTS.values():
            self.assertNotRegex(p, r"order|withdraw/apply|transfer|asset/transfer|margin/loan")
        self.bad(req("order"), "endpoint_not_allowed")
        self.bad(req("../../api/v3/order"), "endpoint_not_allowed")
        self.bad(req("__proto__"), "endpoint_not_allowed")

    def test_secret_field_rejected(self):
        self.bad(req(secret="s" * 64), "bad_field")
        self.bad(req(secretKey="s"), "bad_field")

    def test_validation(self):
        self.bad(req(apiKey="bad key!"), "bad_api_key")
        self.bad(req(timestamp="123"), "bad_timestamp")
        self.bad(req(recvWindow="70000"), "bad_recv_window")
        self.bad(req(recvWindow="0"), "bad_recv_window")
        self.bad(req(signature="zz" * 32), "bad_signature")
        self.bad(req(signature=SIG + "&symbol=BTCUSDT"), "bad_signature")
        self.bad(req(timestamp=str(now_ms() - 3600 * 1000)), "stale_timestamp")
        self.bad([], "bad_request")

    def test_query_rebuilt(self):
        url, h = R.build_request(req("withdrawAddressList", timestamp="1762761600000", signature="A" * 64), now_ms=1762761600000)
        self.assertTrue(url.endswith("/sapi/v1/capital/withdraw/address/list?timestamp=1762761600000&recvWindow=10000&signature=" + "a" * 64))
        self.assertEqual(h, {"X-MBX-APIKEY": KEY})

    def test_ok_and_time(self):
        code, body = R.call(req())
        self.assertEqual(code, 200)
        self.assertEqual(body["data"]["ipRestrict"], True)
        self.assertEqual(Fake.seen[0][1], KEY)
        code, body = R.call({"endpoint": "time"})
        self.assertEqual(body, {"data": {"serverTime": 1}})
        self.assertIsNone(Fake.seen[1][1])   # bez klucza dla endpointu publicznego

    def test_geo_blocked(self):
        Fake.mode = "geo"
        with self.assertRaises(R.RelayError) as c:
            R.call(req())
        self.assertEqual((c.exception.status, c.exception.code), (451, "geo_blocked"))

    def test_binance_error_passthrough(self):
        Fake.mode = "badkey"
        code, body = R.call(req())
        self.assertEqual(code, 400)
        self.assertEqual(body["binance_code"], -2015)

    def test_no_redirect(self):
        Fake.mode = "redirect"
        with self.assertRaises(R.RelayError) as c:
            R.call(req())
        self.assertEqual(c.exception.code, "upstream_redirect")

    def test_too_large(self):
        Fake.mode = "big"
        with self.assertRaises(R.RelayError) as c:
            R.call(req())
        self.assertEqual(c.exception.code, "upstream_too_large")

    def test_upstream_garbage(self):
        Fake.mode = "html"
        with self.assertRaises(R.RelayError) as c:
            R.call(req())
        self.assertEqual(c.exception.code, "upstream_error")


if __name__ == "__main__":
    unittest.main()
