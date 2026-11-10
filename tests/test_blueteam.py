# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""Testy Blue Team (pulapki, puste aliasy, raport):  python3 -m unittest tests/test_blueteam.py"""
import json
import os
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import blueteam as B  # noqa: E402

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "static")


class BlueTeamTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        B.DATA_DIR = self.tmp
        B.DATA_FILE = os.path.join(self.tmp, "blueteam.json")
        B._db = None
        B._rate.clear()

    def test_token_lifecycle(self):
        t = B.new_token("Notes\x00 on iPhone", "file")
        self.assertTrue(re.match(r"^[0-9a-f]{20}$", t["id"]))
        self.assertTrue(t["persistent"])
        with open(B.DATA_FILE) as f:
            raw = f.read()
        self.assertNotIn(t["key"], raw)                       # zapisany tylko skrot klucza
        self.assertIsNone(B.view_token(t["id"], "x" * 30))     # zly klucz
        B.record_hit(t["id"], "/restore", "203.0.113.7", "curl/8.0 " + "A" * 500)
        v = B.view_token(t["id"], t["key"])
        self.assertEqual(v["label"], "Notes on iPhone")
        self.assertEqual(len(v["hits"]), 1)
        h = v["hits"][0]
        self.assertEqual((h["ip"], h["path"]), ("203.0.113.7", "/restore"))
        self.assertLessEqual(len(h["ua"]), 160)
        self.assertEqual(set(h), {"ts", "ua", "ip", "path"})
        B._db = None                                           # odczyt z pliku po "restarcie"
        self.assertEqual(len(B.view_token(t["id"], t["key"])["hits"]), 1)
        self.assertTrue(B.delete_token(t["id"], t["key"]))
        self.assertIsNone(B.view_token(t["id"], t["key"]))

    def test_unknown_token_no_record(self):
        B.record_hit("0" * 20, "", "1.2.3.4", "x")
        self.assertEqual(B._load()["tokens"], {})

    def test_hit_cap_and_rate(self):
        t = B.new_token("", "url")
        for i in range(150):
            B._rate.clear()
            B.record_hit(t["id"], "/%d" % i, "198.51.100.1", "ua")
        self.assertEqual(len(B.view_token(t["id"], t["key"])["hits"]), B.MAX_HITS_PER_TOKEN)
        B._rate.clear()
        for i in range(70):
            B.record_hit(t["id"], "", "198.51.100.2", "ua")
        n = sum(1 for h in B.view_token(t["id"], t["key"])["hits"] if h["ip"] == "198.51.100.2")
        self.assertEqual(n, 60)

    def test_decoys_fake_and_aliased(self):
        base = "https://szlaban.example"
        for p in B.DECOY_PATHS:
            ctype, body, code = B.decoy_body(p, base)
            self.assertEqual(code, 200, p)
            for m in re.finditer(r"(?:KEY|SECRET|PASSWORD|key|secret|token)[^\n]{0,6}[=:]\s*\"?([A-Za-z0-9_]{16,})", body):
                self.assertIn("SZLD", m.group(1), (p, m.group(0)))
            for u in re.findall(r"https?://[^\s\"'<>]+", body):
                self.assertTrue(u.startswith(base + "/t/d-"), (p, u))   # tylko aliasy na pulapke
        self.assertIsNone(B.decoy_body("/index.html", base))
        self.assertIn("SZLD", B.decoy_body("/.env", base)[1])
        json.loads(B.decoy_body("/config.json", base)[1])

    def test_decoy_log_masks_ip(self):
        B.record_decoy("/.env", "203.0.113.99", "sqlmap/1.7")
        B.record_hit("d-env-vault", "", "2001:db8:1:2::5", "python-requests")
        d = B._load()["decoys"]
        self.assertEqual(d[0]["ip"], "203.0.113.x")
        self.assertEqual(d[1]["ip"], "2001:db8:1:…")
        self.assertTrue(d[1]["alias"])
        self.assertNotIn("203.0.113.99", json.dumps(d))

    def test_tarpit_bounded(self):
        t0 = time.monotonic()
        B.tarpit()
        self.assertLess(time.monotonic() - t0, 1.7)
        for _ in range(8):
            B._tarpit.acquire()
        try:
            t0 = time.monotonic()
            B.tarpit()                      # wszystkie miejsca zajete -> bez czekania
            self.assertLess(time.monotonic() - t0, 0.05)
        finally:
            for _ in range(8):
                B._tarpit.release()

    def test_report(self):
        B.record_decoy("/wp-login.php", "192.0.2.5", "x")
        r = B.report(STATIC)
        self.assertEqual(r["frontend"]["secrets"], 0)            # w publicznym frontendzie brak sekretow
        self.assertIn("/api/binance/relay", r["frontend"]["api_paths"])
        self.assertEqual(r["by_path"], {"/wp-login.php": 1})
        self.assertEqual(r["recent"][0]["ip"], "192.0.2.x")

    def test_bad_auth_inputs(self):
        for tid, key in ((None, None), ("../x", "k" * 30), ("0" * 20, "short"), ({}, [])):
            self.assertIsNone(B.view_token(tid, key))


if __name__ == "__main__":
    unittest.main()
