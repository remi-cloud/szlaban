# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""blueteam.py - Blue Team (tylko obrona): pulapki-wabiki (honeytokens/canary) i puste aliasy (decoys).

* Pulapki uzytkownika: losowy identyfikator + klucz podgladu. Na serwerze trzymamy tylko skrot SHA-256
  klucza. Trafienie zapisuje: czas, User-Agent (max 160 znakow), IP i sciezke (max 100 znakow).
* Puste aliasy (decoys) Szlabanu: typowo skanowane sciezki (/.env, /.git/config, /wp-login.php ...)
  zwracaja wiarygodna, ale PUSTA/falszywa tresc. Wszystkie wartosci zawieraja znacznik "SZLD"
  (szlaban decoy) i nic nie otwieraja. Klucze/adresy w wabikach to aliasy na /t/d-<nazwa>, wiec ich
  uzycie tez jest odnotowane. Dla decoys zapisujemy IP tylko w postaci zamaskowanej (np. 203.0.113.x).
* Tarpit-lite: male, ograniczone opoznienie (max 1,5 s, max 8 naraz), nigdy nie blokuje serwera.
* Zapis: jeden plik JSON w DATA_DIR (zapis atomowy). Na darmowym Renderze dysk jest ulotny - dane
  znikaja po restarcie/wdrozeniu (opisane w README).
"""
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import string
import tempfile
import threading
import time
from collections import deque

DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(tempfile.gettempdir(), "szlaban-data")
DATA_FILE = os.path.join(DATA_DIR, "blueteam.json")
MAX_TOKENS = 5000
MAX_HITS_PER_TOKEN = 100
MAX_DECOY_LOG = 500
TOKEN_RE = re.compile(r"^[0-9a-f]{20}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")

_lock = threading.Lock()
_tarpit = threading.BoundedSemaphore(8)
_rate = {}   # (kategoria, ip) -> deque[czas]
_db = None
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
       b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")


def _load():
    global _db
    if _db is None:
        try:
            with open(DATA_FILE, encoding="utf-8") as f:
                _db = json.load(f)
            if not isinstance(_db, dict):
                raise ValueError
        except (OSError, ValueError):
            _db = {}
        _db.setdefault("tokens", {})
        _db.setdefault("decoys", [])
    return _db


def _save():
    try:
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=DATA_DIR, prefix=".bt-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_db, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, DATA_FILE)
        return True
    except OSError:
        return False


def persistent():
    return os.access(DATA_DIR, os.W_OK) or os.access(os.path.dirname(DATA_DIR) or "/", os.W_OK)


def rate_ok(cat, ip, maxn, window=600):
    now = time.time()
    with _lock:
        if len(_rate) > 20000:
            _rate.clear()
        q = _rate.setdefault((cat, ip), deque())
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= maxn:
            return False
        q.append(now)
        return True


def mask_ip(ip):
    ip = str(ip or "")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return ".".join(ip.split(".")[:3]) + ".x"
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + ":…"
    return "?"


def clean(s, n):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(s or ""))[:n]


def _khash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------- pulapki uzytkownika ----------
def new_token(label, kind):
    with _lock:
        db = _load()
        if len(db["tokens"]) >= MAX_TOKENS:
            return None
        tid = secrets.token_hex(10)
        key = secrets.token_urlsafe(24)
        db["tokens"][tid] = {"kh": _khash(key), "created": int(time.time()), "label": clean(label, 60),
                             "kind": clean(kind, 20), "hits": []}
        saved = _save()
    return {"id": tid, "key": key, "persistent": saved}


def _auth(tid, key):
    if not (isinstance(tid, str) and TOKEN_RE.match(tid) and isinstance(key, str) and KEY_RE.match(key)):
        return None
    t = _load()["tokens"].get(tid)
    if not t or not hmac.compare_digest(t["kh"], _khash(key)):
        return None
    return t


def view_token(tid, key):
    with _lock:
        t = _auth(tid, key)
        if not t:
            return None
        return {"id": tid, "label": t["label"], "kind": t["kind"], "created": t["created"], "hits": list(reversed(t["hits"]))}


def delete_token(tid, key):
    with _lock:
        if not _auth(tid, key):
            return False
        del _load()["tokens"][tid]
        _save()
        return True


def record_hit(tid, rest, ip, ua):
    """Zapisuje trafienie (jesli pulapka istnieje). Wynik nie zdradza, czy istnieje."""
    if tid.startswith("d-"):
        return record_decoy("/t/" + tid + rest, ip, ua, alias=True)
    if not TOKEN_RE.match(tid) or not rate_ok("hit", ip, 60):
        return
    with _lock:
        t = _load()["tokens"].get(tid)
        if not t:
            return
        t["hits"].append({"ts": int(time.time()), "ua": clean(ua, 160), "ip": clean(ip, 64), "path": clean(rest, 100)})
        del t["hits"][:-MAX_HITS_PER_TOKEN]
        _save()


# ---------- puste aliasy (decoys) ----------
def record_decoy(path, ip, ua, alias=False):
    if not rate_ok("decoy", ip, 30):
        return
    with _lock:
        db = _load()
        db["decoys"].append({"ts": int(time.time()), "path": clean(path, 100), "ua": clean(ua, 160),
                             "ip": mask_ip(ip), "alias": bool(alias)})
        del db["decoys"][:-MAX_DECOY_LOG]
        _save()


def tarpit():
    """Male opoznienie dla skanerow. Nigdy nie czeka na wolne miejsce - jak 8 zajetych, bez opoznienia."""
    if _tarpit.acquire(blocking=False):
        try:
            time.sleep(random.uniform(0.3, 1.5))
        finally:
            _tarpit.release()


def _fake(n, alphabet=string.ascii_letters + string.digits, prefix=""):
    return prefix + "".join(secrets.choice(alphabet) for _ in range(max(0, n - len(prefix))))


def decoy_body(path, base):
    """Zwraca (content_type, body, status) dla sciezki-wabika albo None."""
    A = base.rstrip("/") + "/t/d-"
    up = string.ascii_uppercase + string.digits
    if path in ("/.env", "/.env.local", "/.env.production", "/config.env"):
        body = ("APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=10.0.3.12\nDB_USER=szlaban\nDB_PASSWORD=%s\n"
                "BINANCE_API_KEY=%s\nBINANCE_API_SECRET=%s\nAWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n"
                "WALLET_RECOVERY_URL=%senv-recovery\nKEY_VAULT=%senv-vault\n") % (
            _fake(20, prefix="SZLD"), _fake(64, prefix="SZLD"), _fake(64, prefix="SZLD"), _fake(20, up, "AKIASZLD"),
            _fake(40, prefix="SZLD"), A, A)
        return "text/plain; charset=utf-8", body, 200
    if path in ("/config.json", "/api/config", "/api/keys", "/api/v1/secrets", "/secrets.json"):
        body = json.dumps({"env": "production", "api": {"binance": {"key": _fake(64, prefix="SZLD"), "secret": _fake(64, prefix="SZLD"),
                           "endpoint": A + "api"}}, "wallet": {"hot": A + "wallet", "withdraw_alias": A + "withdraw"},
                           "admin": A + "admin"}, indent=2)
        return "application/json; charset=utf-8", body, 200
    if path in ("/.git/config",):
        body = ('[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = %sgit\n'
                '\tfetch = +refs/heads/*:refs/remotes/origin/*\n[user]\n\ttoken = ghp_%s\n') % (A, _fake(36, prefix="SZLD"))
        return "text/plain; charset=utf-8", body, 200
    if path in ("/.git/HEAD",):
        return "text/plain; charset=utf-8", "ref: refs/heads/main\n", 200
    if path in ("/.aws/credentials",):
        return "text/plain; charset=utf-8", "[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n# console: %saws\n" % (
            _fake(20, up, "AKIASZLD"), _fake(40, prefix="SZLD"), A), 200
    if path in ("/admin", "/admin/", "/wp-login.php", "/wp-admin/", "/administrator/", "/phpmyadmin/", "/login.php"):
        body = ("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Admin login</title></head><body>"
                "<h1>Administration</h1><p>Session expired. Please sign in again.</p>"
                "<p><a href=\"%sadmin-login\">Sign in</a></p></body></html>") % A
        return "text/html; charset=utf-8", body, 200
    if path in ("/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/backup.tar.gz", "/site.zip"):
        # pusty alias: wyglada jak eksport, ale zawiera tylko naglowek i link-alias
        return "text/plain; charset=utf-8", "-- MySQL dump 10.13 (SZLD)\n-- Export incomplete. Download full archive: %sbackup\n" % A, 200
    if path in ("/phpinfo.php", "/server-status", "/actuator/env", "/debug", "/.DS_Store", "/id_rsa", "/.ssh/id_rsa", "/.npmrc", "/config.php"):
        return "text/plain; charset=utf-8", "", 200   # pusty alias
    return None


DECOY_PATHS = ["/.env", "/.env.local", "/.env.production", "/config.env", "/config.json", "/api/config", "/api/keys",
               "/api/v1/secrets", "/secrets.json", "/.git/config", "/.git/HEAD", "/.aws/credentials", "/admin", "/admin/",
               "/wp-login.php", "/wp-admin/", "/administrator/", "/phpmyadmin/", "/login.php", "/backup.zip", "/backup.sql",
               "/db.sql", "/dump.sql", "/backup.tar.gz", "/site.zip", "/phpinfo.php", "/server-status", "/actuator/env",
               "/debug", "/.DS_Store", "/id_rsa", "/.ssh/id_rsa", "/.npmrc", "/config.php"]
DECOY_SET = frozenset(DECOY_PATHS)

ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\nDisallow: /api/keys\n"


# ---------- raport utwardzenia ----------
R_URL = re.compile(r"https?://[A-Za-z0-9.-]+")
R_API = re.compile(r"[\"'`](/api/[a-z0-9/_-]+)")
R_SECRET = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|xox[bp]-[A-Za-z0-9-]{10,}|\d{8,10}:AA[A-Za-z0-9_-]{33}")
_scan_cache = {}


def frontend_scan(static_dir):
    """Co widzi statyczny skaner frontendu Szlabanu (kod jest jawny - AGPL)."""
    if "r" in _scan_cache:
        return _scan_cache["r"]
    files, hosts, apis, secrets_found = 0, set(), set(), 0
    for name in sorted(os.listdir(static_dir)):
        if not name.endswith((".html", ".js", ".css")):
            continue
        files += 1
        with open(os.path.join(static_dir, name), encoding="utf-8", errors="replace") as f:
            txt = f.read()
        hosts.update(m.group(0).split("//", 1)[1].lower() for m in R_URL.finditer(txt))
        apis.update(m.group(1) for m in R_API.finditer(txt))
        secrets_found += len(R_SECRET.findall(txt))
    _scan_cache["r"] = {"files": files, "external_hosts": sorted(hosts)[:80], "api_paths": sorted(apis),
                        "secrets": secrets_found}
    return _scan_cache["r"]


def report(static_dir):
    with _lock:
        d = list(_load()["decoys"])
    by_path = {}
    for h in d:
        by_path[h["path"]] = by_path.get(h["path"], 0) + 1
    return {"frontend": frontend_scan(static_dir), "decoy_paths": DECOY_PATHS, "hits_total": len(d),
            "by_path": dict(sorted(by_path.items(), key=lambda kv: -kv[1])[:40]), "recent": list(reversed(d[-25:])),
            "storage": "ephemeral" if os.environ.get("RENDER") else "file", "since": d[0]["ts"] if d else None}
