# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""re_static.py - statyczna analiza podejrzanego pliku (RE) dla modulu RE + Blue Team.

ZASADY BEZPIECZENSTWA:
  * Nic nie jest uruchamiane ani rozpakowywane na dysk. Plik jest tylko czytany jako bajty w pamieci
    i zapominany po analizie (zadnego zapisu, zadnego logowania tresci).
  * Archiwa ZIP/APK/IPA: czytamy tylko spis i kilka wybranych wpisow, z limitami (liczba wpisow,
    rozmiar po rozpakowaniu, wspolczynnik kompresji) - ochrona przed zip-bomba. Wpisy z "../" lub
    sciezka bezwzgledna sa tylko zglaszane (zip-slip), nigdy rozpakowywane.
  * Budzet czasu (domyslnie 8 s) sprawdzany w petlach.
  * Linki z pliku NIE sa otwierane (brak SSRF) - tylko wypisywane.
Tylko biblioteka standardowa Pythona.
"""
import hashlib
import io
import plistlib
import re
import struct
import time
import zipfile

MAX_FILE = 20 * 1024 * 1024
MAX_ENTRIES = 5000
MAX_ENTRY_READ = 8 * 1024 * 1024
MAX_TOTAL_READ = 40 * 1024 * 1024
MAX_RATIO = 100
SCAN_BYTES = 24 * 1024 * 1024
MAX_STRINGS = 40000
MAX_IOC = 200

DANGEROUS_PERMS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
    "android.permission.READ_SMS": "sms", "android.permission.RECEIVE_SMS": "sms", "android.permission.SEND_SMS": "sms",
    "android.permission.RECEIVE_MMS": "sms", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "notifications",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install", "android.permission.BIND_DEVICE_ADMIN": "device_admin",
    "android.permission.READ_CONTACTS": "contacts", "android.permission.READ_CALL_LOG": "calls",
    "android.permission.READ_PHONE_STATE": "phone", "android.permission.RECORD_AUDIO": "audio",
    "android.permission.QUERY_ALL_PACKAGES": "packages", "android.permission.CAMERA": "camera",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "persistence",
    "android.permission.RECEIVE_BOOT_COMPLETED": "persistence",
}
HIGH_PERM_GROUPS = {"accessibility", "overlay", "sms", "notifications", "device_admin", "install"}

R_URL = re.compile(rb"(?:https?|wss?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300}")
R_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
R_IPV4 = re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
R_DOMAIN = re.compile(rb"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:com|net|org|io|info|me|xyz|top|app|dev|vip|cc|co|ru|cn|tk|ml|ga|cf|gq|pro|site|online|live|link|click|shop|icu|support|vision|us|uk|pl|de|biz|ws|su|in|sbs|cfd|cyou|buzz|rest|lol|zip|mov)(?![A-Za-z0-9-])")
R_ETH = re.compile(rb"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])")
R_BTC_BECH = re.compile(rb"(?<![0-9a-z])bc1[02-9ac-hj-np-z]{11,71}(?![0-9a-z])")
R_BTC_B58 = re.compile(rb"(?<![0-9A-Za-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![0-9A-Za-z])")
R_TRON = re.compile(rb"(?<![0-9A-Za-z])T[1-9A-HJ-NP-Za-km-z]{33}(?![0-9A-Za-z])")
R_TG_TOKEN = re.compile(rb"(?<![0-9])\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])")
R_TG_API = re.compile(rb"api\.telegram\.org/bot", re.I)
R_WEBHOOK = re.compile(rb"(?:discord(?:app)?\.com/api/webhooks/|webhook\.site/|hooks\.slack\.com/|pipedream\.net|requestbin|ngrok(?:-free)?\.(?:io|app))", re.I)
R_SEED = re.compile(rb"seed[ _-]?phrase|recovery[ _-]?phrase|mnemonic|private[ _-]?key|secret[ _-]?recovery|bip39|wallet[ _-]?words|\x00?12[ _-]?words", re.I)
R_SEED_ZH = re.compile("助记词|私钥|恢复短语".encode("utf-8"))
R_2FA = re.compile(rb"2fa[ _-]?code|google[ _-]?auth|authenticator|otp[ _-]?code|verification[ _-]?code|sms[ _-]?code", re.I)
R_OBF_JS = re.compile(rb"eval\s*\(|atob\s*\(|String\.fromCharCode|unescape\s*\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|function\s*\(p,a,c,k,e,[dr]\)|_0x[0-9a-f]{4,6}", re.I)
R_B64BLOB = re.compile(rb"[A-Za-z0-9+/]{400,}={0,2}")
R_REMOTE = re.compile(rb"anydesk|teamviewer|rustdesk|ultraviewer|quicksupport", re.I)
R_KEYLOG = re.compile(rb"keylog|GetAsyncKeyState|SetWindowsHookEx|clipboard|wallet\.dat|Local Storage[\\/]leveldb|Login Data|metamask|nkbihfbeogaeaoehlefnkodbefgpgknn", re.I)
R_PDF_BAD = re.compile(rb"/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|RichMedia|SubmitForm|URI)\b")
R_HTML_PW = re.compile(rb"<input[^>]{0,200}type\s*=\s*[\"']?password", re.I)
R_HTML_FORM = re.compile(rb"<form[^>]{0,300}action\s*=\s*[\"']?(https?://[^\"' >]{1,200})", re.I)
R_BRAND = re.compile(rb"binance|\xe5\xb8\x81\xe5\xae\x89", re.I)


class TimeUp(Exception):
    pass


class Budget:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def check(self):
        if time.monotonic() > self.end:
            raise TimeUp()


def sniff(data, name=""):
    h = data[:16]
    n = (name or "").lower()
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        return "zip"
    if h.startswith(b"MZ"):
        return "pe"
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if h[:4] == b"\xca\xfe\xba\xbe":
        nfat = struct.unpack(">I", data[4:8])[0] if len(data) >= 8 else 0
        return "macho" if 0 < nfat < 20 else "java_class"
    if h.startswith(b"%PDF"):
        return "pdf"
    if h.startswith(b"dex\n"):
        return "dex"
    if h.startswith(b"bplist00"):
        return "plist"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"Rar!"):
        return "rar"
    if h.startswith(b"7z\xbc\xaf"):
        return "7z"
    head = data[:2048].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html") or re.search(rb"<(script|body|head|form|iframe|meta|input)\b", head) \
            or (n.endswith((".html", ".htm", ".xhtml")) and head.startswith(b"<")):
        return "html"
    try:
        data[:65536].decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        is_text = data[:4096].count(b"\x00") == 0
    if is_text:
        if n.endswith((".js", ".mjs")) or re.search(rb"\b(function|const|let|var)\b[^\n]{0,80}[=(]", data[:65536]):
            return "js"
        return "text"
    return "binary"


def strings_of(data, budget, minlen=6):
    """Napisy ASCII i UTF-16LE (jak narzedzie `strings`)."""
    out = []
    view = data[:SCAN_BYTES]
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, view):
        out.append(m.group(0)[:400])
        if len(out) >= MAX_STRINGS:
            break
        if len(out) % 2000 == 0:
            budget.check()
    if len(out) < MAX_STRINGS:
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, view):
            out.append(m.group(0)[:800].decode("utf-16le", "replace").encode("ascii", "replace"))
            if len(out) >= MAX_STRINGS:
                break
            if len(out) % 2000 == 0:
                budget.check()
    return out


# ---------- Android binary XML (AndroidManifest.xml), best effort ----------
def parse_axml(buf):
    """Zwraca (package, [uprawnienia], [wszystkie wartosci atrybutow tekstowych])."""
    if len(buf) < 8 or struct.unpack("<HH", buf[:4])[0] != 0x0003:
        raise ValueError("not axml")
    pos, strings, package, perms, values = 8, [], None, [], []
    n = len(buf)
    while pos + 8 <= n:
        ctype, hsize, csize = struct.unpack("<HHI", buf[pos:pos + 8])
        if csize < 8 or pos + csize > n:
            break
        if ctype == 0x0001:  # string pool
            cnt, _sty, flags, sstart, _ = struct.unpack("<IIIII", buf[pos + 8:pos + 28])
            utf8 = bool(flags & 0x100)
            offs = struct.unpack("<%dI" % min(cnt, 200000), buf[pos + 28:pos + 28 + 4 * min(cnt, 200000)])
            base = pos + sstart
            for o in offs:
                p = base + o
                try:
                    if utf8:
                        ln = buf[p]; p += 2 if ln & 0x80 else 1
                        ln = buf[p]
                        if ln & 0x80:
                            ln = ((ln & 0x7f) << 8) | buf[p + 1]; p += 2
                        else:
                            p += 1
                        strings.append(buf[p:p + ln].decode("utf-8", "replace"))
                    else:
                        ln = struct.unpack("<H", buf[p:p + 2])[0]; p += 2
                        if ln & 0x8000:
                            ln = ((ln & 0x7fff) << 16) | struct.unpack("<H", buf[p:p + 2])[0]; p += 2
                        strings.append(buf[p:p + 2 * ln].decode("utf-16le", "replace"))
                except (IndexError, struct.error):
                    strings.append("")
        elif ctype == 0x0102:  # start element
            _ns, name_i = struct.unpack("<iI", buf[pos + 16:pos + 24])
            astart, asize, acount = struct.unpack("<HHH", buf[pos + 24:pos + 30])
            tag = strings[name_i] if name_i < len(strings) else ""
            attrs = {}
            ap = pos + 16 + astart
            for i in range(min(acount, 500)):
                a = ap + i * (asize or 20)
                _ans, aname, araw, _sz, _r, dtype, data = struct.unpack("<iIiHBBI", buf[a:a + 20])
                key = strings[aname] if 0 <= aname < len(strings) else ""
                val = strings[araw] if 0 <= araw < len(strings) else (strings[data] if dtype == 3 and data < len(strings) else None)
                if val is not None:
                    attrs[key] = val
                    values.append(val)
            if tag == "manifest" and "package" in attrs:
                package = attrs["package"]
            if tag in ("uses-permission", "uses-permission-sdk-23") and attrs.get("name"):
                perms.append(attrs["name"])
        pos += csize
    return package, perms, values


def _read_entry(zf, info, state, budget):
    budget.check()
    if info.file_size > MAX_ENTRY_READ or state["read"] + info.file_size > MAX_TOTAL_READ:
        state["skipped"] += 1
        return None
    if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO and info.file_size > 1024 * 1024:
        state["bomb"] = True
        return None
    with zf.open(info) as f:
        data = f.read(MAX_ENTRY_READ + 1)
    if len(data) > MAX_ENTRY_READ:
        state["skipped"] += 1
        return None
    state["read"] += len(data)
    return data


def analyze(data, filename="", seconds=8.0):
    budget = Budget(seconds)
    res = {"size": len(data), "name": (filename or "")[:120]}
    res["sha256"] = hashlib.sha256(data).hexdigest()
    res["sha1"] = hashlib.sha1(data).hexdigest()
    res["md5"] = hashlib.md5(data).hexdigest()
    res["virustotal"] = "https://www.virustotal.com/gui/file/" + res["sha256"]
    kind = sniff(data, filename)
    ind = []

    def add(code, sev, **p):
        ind.append({"code": code, "severity": sev, "params": p})

    blobs = [data]   # tresci do szukania IOC
    try:
        if kind == "zip":
            kind = analyze_zip(data, res, add, blobs, budget)
        elif kind == "pdf":
            hits = sorted(set(m.group(1).decode() for m in R_PDF_BAD.finditer(data[:SCAN_BYTES])))
            risky = [h for h in hits if h in ("JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "RichMedia", "SubmitForm")]
            if risky:
                add("pdf_active", "high" if {"JavaScript", "JS", "Launch", "EmbeddedFile"} & set(risky) else "medium", items=", ".join(risky))
        elif kind in ("pe", "elf", "macho"):
            add("native_binary", "medium", kind=kind)
        elif kind == "java_class":
            add("native_binary", "low", kind=kind)
        elif kind in ("rar", "7z", "gzip"):
            add("archive_not_opened", "low", kind=kind)
        if kind == "macho" and len(data) > 0 and b"__LINKEDIT" in data[:SCAN_BYTES] and b"\xfa\xde\x0c\xc0" not in data[:SCAN_BYTES]:
            add("macho_unsigned", "medium")
        if kind == "pe" and b"UPX!" in data[:4096]:
            add("packed_upx", "medium")
        res["type"] = kind
        iocs = {"urls": [], "domains": [], "ips": [], "emails": [], "wallets": [], "telegram": [], "webhooks": []}
        seen = set()

        def put(cat, v):
            k = (cat, v if isinstance(v, str) else v["kind"] + ":" + v["value"])
            if len(iocs[cat]) < MAX_IOC and k not in seen:
                seen.add(k)
                iocs[cat].append(v)
        flags = set()
        for blob in blobs:
            budget.check()
            text_like = kind in ("html", "js", "text") or blob is not data
            src = [blob[:SCAN_BYTES]] if text_like else strings_of(blob, budget)
            for s in src:
                budget.check()
                for m in R_URL.finditer(s):
                    put("urls", m.group(0).decode("ascii", "replace").rstrip(".,;)'\""))
                for m in R_EMAIL.finditer(s):
                    put("emails", m.group(0).decode("ascii", "replace"))
                for m in R_IPV4.finditer(s):
                    ip = m.group(0).decode()
                    if not ip.startswith(("0.", "127.", "255.")) and ip.count(".") == 3 and not re.match(r"^\d+\.0\.0\.0$", ip):
                        put("ips", ip)
                for m in R_DOMAIN.finditer(s):
                    put("domains", m.group(0).decode("ascii", "replace").lower())
                for r, k in ((R_ETH, "eth"), (R_BTC_BECH, "btc"), (R_TRON, "tron")):
                    for m in r.finditer(s):
                        put("wallets", {"kind": k, "value": m.group(0).decode()})
                if text_like:
                    for m in R_BTC_B58.finditer(s):
                        put("wallets", {"kind": "btc", "value": m.group(0).decode()})
                for m in R_TG_TOKEN.finditer(s):
                    tok = m.group(0).decode()
                    put("telegram", tok.split(":")[0] + ":" + tok.split(":")[1][:4] + "…")
                if R_TG_API.search(s):
                    flags.add("tg_api")
                for m in R_WEBHOOK.finditer(s):
                    put("webhooks", m.group(0).decode("ascii", "replace").lower())
                for r, f in ((R_SEED, "seed"), (R_SEED_ZH, "seed"), (R_2FA, "codes"), (R_REMOTE, "remote"), (R_KEYLOG, "stealer"), (R_BRAND, "brand")):
                    if r.search(s):
                        flags.add(f)
                if kind in ("html", "js", "text") or text_like:
                    if R_OBF_JS.search(s):
                        flags.add("obfuscation")
                    if R_B64BLOB.search(s[:4 * 1024 * 1024]):
                        flags.add("b64blob")
        if kind == "html":
            if R_HTML_PW.search(data):
                add("html_password_form", "medium")
            for m in R_HTML_FORM.finditer(data[:SCAN_BYTES]):
                add("html_external_form", "high", url=m.group(1).decode("ascii", "replace")[:200])
                break
        if iocs["telegram"] or "tg_api" in flags:
            add("telegram_exfil", "high", count=len(iocs["telegram"]))
        if iocs["webhooks"]:
            add("webhook_exfil", "high", items=", ".join(iocs["webhooks"][:5]))
        if "seed" in flags:
            add("seed_harvest", "high")
        if "codes" in flags:
            add("code_harvest", "medium")
        if "remote" in flags:
            add("remote_access", "high")
        if "stealer" in flags:
            add("stealer_strings", "high")
        if "obfuscation" in flags:
            add("obfuscation", "medium")
        if "b64blob" in flags:
            add("encoded_blob", "low")
        if "brand" in flags:
            add("brand_mention", "low")
        if iocs["ips"]:
            add("hardcoded_ip", "low", count=len(iocs["ips"]))
        if iocs["wallets"]:
            add("wallet_addresses", "medium", count=len(iocs["wallets"]))
        res["iocs"] = iocs
    except TimeUp:
        res.setdefault("type", kind)
        res.setdefault("iocs", {"urls": [], "domains": [], "ips": [], "emails": [], "wallets": [], "telegram": [], "webhooks": []})
        add("timeout_partial", "low")
    res["indicators"] = ind
    w = {"high": 30, "medium": 12, "low": 3}
    res["score"] = min(100, sum(w.get(i["severity"], 0) for i in ind))
    return res


def analyze_zip(data, res, add, blobs, budget):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        add("zip_corrupt", "medium")
        return "zip"
    if len(infos) > MAX_ENTRIES:
        add("zip_too_many", "medium", count=len(infos))
        infos = infos[:MAX_ENTRIES]
    names = [i.filename for i in infos]
    state = {"read": 0, "skipped": 0, "bomb": False}
    slip = [n for n in names if n.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", n) or re.match(r"^[A-Za-z]:", n)]
    if slip:
        add("zip_slip", "high", items=", ".join(slip[:5]))
    total_unc = sum(i.file_size for i in infos)
    total_c = sum(i.compress_size for i in infos) or 1
    if total_unc > 1024 * 1024 * 1024 or (total_unc / total_c > MAX_RATIO and total_unc > 50 * 1024 * 1024):
        state["bomb"] = True
    if any(i.flag_bits & 0x1 for i in infos):
        add("zip_encrypted", "medium")
    nested = [n for n in names if n.lower().endswith((".zip", ".apk", ".jar", ".rar", ".7z"))]
    if nested:
        add("zip_nested", "low", count=len(nested))
    res["zip"] = {"entries": len(names), "uncompressed": total_unc, "sample": names[:30]}
    lower = {n.lower(): i for n, i in zip(names, infos)}
    kind = "zip"
    if "androidmanifest.xml" in lower and any(n.startswith("classes") and n.endswith(".dex") for n in lower):
        kind = "apk"
        man = _read_entry(zf, lower["androidmanifest.xml"], state, budget) if not state["bomb"] else None
        if man:
            try:
                pkg, perms, values = parse_axml(man)
                groups = sorted(set(DANGEROUS_PERMS[p] for p in perms if p in DANGEROUS_PERMS) |
                                set(DANGEROUS_PERMS[v] for v in values if v in DANGEROUS_PERMS and DANGEROUS_PERMS[v] == "accessibility"))
                res["apk"] = {"package": pkg, "permissions": perms[:200], "dangerous": groups}
                hi = [g for g in groups if g in HIGH_PERM_GROUPS]
                if hi:
                    add("apk_dangerous_perms", "high", items=", ".join(hi))
                elif groups:
                    add("apk_sensitive_perms", "medium", items=", ".join(groups))
                if pkg and re.search(r"binance|bnb", pkg, re.I):
                    add("apk_brand_package", "medium", package=pkg)
            except (ValueError, struct.error, IndexError):
                add("apk_manifest_unparsed", "low")
        for n in sorted(lower):
            if n.startswith("classes") and n.endswith(".dex") and not state["bomb"]:
                d = _read_entry(zf, lower[n], state, budget)
                if d:
                    blobs.append(b"\n".join(strings_of(d, budget, 5)))
        add("apk_sideload", "medium")
    elif any(re.match(r"^payload/[^/]+\.app/info\.plist$", n) for n in lower):
        kind = "ipa"
        n = next(n for n in lower if re.match(r"^payload/[^/]+\.app/info\.plist$", n))
        d = _read_entry(zf, lower[n], state, budget) if not state["bomb"] else None
        if d:
            try:
                pl = plistlib.loads(d)
                res["ipa"] = {"bundle_id": str(pl.get("CFBundleIdentifier", ""))[:200], "name": str(pl.get("CFBundleName", ""))[:200]}
                if re.search(r"binance|bnb", res["ipa"]["bundle_id"], re.I):
                    add("ipa_brand_bundle", "medium", bundle=res["ipa"]["bundle_id"])
            except Exception:  # plist moze byc uszkodzony - to tylko analiza best effort
                add("ipa_plist_unparsed", "low")
        add("ipa_sideload", "medium")
    exe_flagged = False
    if not state["bomb"]:
        for n, i in zip(names, infos):
            if re.search(r"\.(html?|js|json|txt|xml|plist|sh|bat|ps1|vbs|py)$", n, re.I) and len(blobs) < 60:
                d = _read_entry(zf, i, state, budget)
                if d:
                    blobs.append(d)
            if not exe_flagged and kind == "zip" and re.search(r"\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|lnk|msi|dmg|pkg|command)$", n, re.I):
                add("zip_executable", "high", name=n[:120])
                exe_flagged = True
    if state["bomb"]:
        add("zip_bomb", "high")
    if state["skipped"]:
        add("zip_partial", "low", count=state["skipped"])
    return kind
