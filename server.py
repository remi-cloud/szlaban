#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
"""server.py - serwer www Szlaban (audyt zgod ERC-20) (tylko biblioteka standardowa Pythona 3).

TYLKO ODCZYT: serwer nie zna kluczy, nie laczy sie z portfelem i nie wysyla transakcji.
Uruchomienie:  python3 server.py            (domyslnie 0.0.0.0:8080, zmienna PORT)

API:
  POST /api/scan   body JSON {"address":"0x..","range":"year|all|OD-DO"} -> 202 {"job_id":..}
  GET  /api/scan?address=0x..&range=..  -> czeka do ~20 s; 200 wynik albo 202 {"job_id":..}
  GET  /api/job/<id>  -> {"status":"running|done|error","progress":0-100,"message":..,"result"|"error"}
  GET  /healthz       -> {"ok":true}
  GET  /r/<adres>     -> raport do udostepnienia (ta sama strona, skan uruchamia sie sam)
  GET  /whitepaper    -> WHITEPAPER.md jako HTML;  /LICENSE, /NOTICE, /TRADEMARK
  GET  /source.tar.gz -> pelny kod zrodlowy tej instancji (AGPL-3.0, sekcja 13)
  GET  /binance       -> Binance Guard (audyt klucza API, strażnik adresów, wykrywacz phishingu; EN/PL/ZH)
  POST /api/binance/relay -> przekaznik TYLKO DO ODCZYTU: przyjmuje gotowy podpis, nigdy sekret
  POST /api/re/analyze     -> statyczna analiza pliku (RE), w pamieci, bez uruchamiania i zapisu
  POST /api/trap/new|hits|delete, GET /t/<id>[...] -> pulapki Blue Team (honeytokens)
  GET  /api/blueteam/report -> raport utwardzenia (skan frontendu + trafienia w puste aliasy)
"""
import json
import os
import re
import sys
import threading
import time
import io
import tarfile
import uuid
from collections import deque
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner  # noqa: E402
import forensics  # noqa: E402
import mdlite  # noqa: E402
import binance_relay  # noqa: E402
import re_static  # noqa: E402
import blueteam  # noqa: E402

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DOC_DIRS = [os.path.join(APP_DIR, "docs"), APP_DIR]
SOURCE_URL = os.environ.get("SOURCE_URL", "/source.tar.gz")
# Pliki wchodzace do /source.tar.gz (AGPL sekcja 13 - kod tej instancji dla uzytkownikow sieci)
SOURCE_FILES = ["server.py", "scanner.py", "forensics.py", "mdlite.py", "zgody.py", "binance_relay.py", "re_static.py", "blueteam.py", "Dockerfile",
                ".dockerignore", ".gitignore", "README.md", "WHITEPAPER.md", "LICENSE", "NOTICE",
                "TRADEMARK.md", "AUTHORS", "static/index.html", "static/app.js", "static/style.css",
                "static/favicon.svg", "tests/e2e.js", "tests/shots.js", "tests/sample.txt", "tests/package.json", "tests/run_e2e.sh",
                "tests/test_api.sh", "static/binance.html", "static/binance.js", "static/binance.css",
                "static/bg-i18n.js", "static/bg-detector.js", "static/bg-core.js", "tests/test_detector.js",
                "tests/test_bg_core.js", "tests/test_relay.py", "tests/test_worker.mjs", "tests/e2e_binance.js",
                "tests/test_re.py", "tests/test_blueteam.py", "static/bg-blue.js",
                "cloudflare/worker.js", "cloudflare/wrangler.toml", "cloudflare/README.md"]
_src_cache = {}

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
CACHE_TTL = int(os.environ.get("CACHE_TTL", "600"))          # 10 min
RATE_MAX = int(os.environ.get("RATE_MAX", "10"))             # nowych skanow na IP
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", "600"))      # w oknie 10 min
MAX_RUNNING = int(os.environ.get("MAX_RUNNING", "4"))        # rownoczesnych skanow na serwer
JOB_MAX_SECONDS = int(os.environ.get("JOB_MAX_SECONDS", "600"))
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"      # X-Forwarded-For tylko za proxy chmury
BG_RATE_MAX = int(os.environ.get("BG_RATE_MAX", "40"))       # zapytan relay Binance na IP
BG_RATE_WINDOW = int(os.environ.get("BG_RATE_WINDOW", "600"))  # w oknie 10 min
RE_RATE_MAX = int(os.environ.get("RE_RATE_MAX", "10"))       # analiz plikow na IP / 10 min
re_slots = threading.BoundedSemaphore(int(os.environ.get("RE_MAX_RUNNING", "2")))
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
RANGE_RE = re.compile(r"^(all|year|\d{1,9}-(\d{1,9}|latest)?)$")
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".png": "image/png", ".svg": "image/svg+xml",
        ".ico": "image/x-icon"}
SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY", "Permissions-Policy": "interest-cohort=()",
}

lock = threading.Lock()
jobs = {}          # id -> dict
cache = {}         # (address, range) -> (time, job_id)
hits = {}          # ip -> deque[time]
bg_hits = {}       # ip -> deque[time]  (relay Binance Guard; tylko licznik, bez tresci)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, file=sys.stderr, flush=True)


def cleanup():
    now = time.time()
    with lock:
        for k in [k for k, (t, _j) in cache.items() if now - t > CACHE_TTL]:
            del cache[k]
        live = {j for _t, j in cache.values()}
        for ip in [ip for ip, q in hits.items() if not q or now - q[-1] > RATE_WINDOW]:
            del hits[ip]   # IP trzymamy w pamieci tylko na czas okna limitu
        for ip in [ip for ip, q in bg_hits.items() if not q or now - q[-1] > BG_RATE_WINDOW]:
            del bg_hits[ip]
        for jid in [j for j, d in jobs.items()
                    if j not in live and d["status"] != "running" and now - d["created"] > CACHE_TTL]:
            del jobs[jid]


def validate(address, rng):
    address = (address or "").strip()
    rng = (rng or "year").strip().lower()
    if address.lower().endswith(".eth"):
        return None, None, "Nazwy ENS (np. vitalik.eth) nie są obsługiwane. Wklej adres zaczynający się od 0x (40 znaków)."
    if not ADDR_RE.match(address):
        return None, None, "To nie jest poprawny adres Ethereum. Adres ma postać 0x + 40 znaków (cyfry 0–9 i litery a–f)."
    if not RANGE_RE.match(rng):
        return None, None, "Zły zakres. Dozwolone: all, year albo OD-DO (numery bloków)."
    if "-" in rng:
        a, _, b = rng.partition("-")
        if b not in ("", "latest") and int(a) > int(b):
            return None, None, "Blok początkowy jest większy niż końcowy."
    return address.lower(), rng, None


def run_job(jid):
    job = jobs[jid]

    def progress(pct, msg):
        if pct is not None:
            job["progress"] = pct
        job["message"] = msg
        job["updated"] = time.time()
    try:
        res = scanner.scan(job["address"], job["range"], progress)
        try:
            forensics.enrich(res, progress)
        except Exception as e:  # analiza dodatkowa nie moze zepsuc wyniku skanu
            log("job %s enrich blad: %s" % (jid[:8], type(e).__name__))
            res["analysis_error"] = "Nie udało się wykonać części analizy (ceny/wiek kontraktów). Tabela zgód jest kompletna."
        job["result"] = res
        job["status"] = "done"
        job["progress"] = 100
        job["message"] = "Gotowe."
    except scanner.ScanError as e:
        job["status"], job["error"] = "error", str(e)
    except Exception as e:  # nie pokazujemy stack trace uzytkownikowi
        log("job %s blad: %s" % (jid[:8], type(e).__name__))
        job["status"], job["error"] = "error", "Błąd wewnętrzny serwera. Spróbuj ponownie."
    job["finished"] = time.time()
    if job["status"] == "error":
        with lock:   # bledow nie cache'ujemy
            if cache.get(job["key"], (0, None))[1] == jid:
                del cache[job["key"]]
    log("job %s %s %s %.1fs" % (jid[:8], job["range"], job["status"], job["finished"] - job["created"]))


def start_or_reuse(address, rng, ip):
    """Zwraca (job_id, kod_bledu, komunikat)."""
    cleanup()
    key = (address, rng)
    now = time.time()
    with lock:
        c = cache.get(key)
        if c and c[1] in jobs:
            return c[1], None, None                  # cache albo trwajacy skan - bez limitu
        q = hits.setdefault(ip, deque())
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_MAX:
            wait = int(RATE_WINDOW - (now - q[0])) + 1
            return None, 429, "Za dużo skanów z Twojego adresu IP. Spróbuj za %d s." % wait
        running = sum(1 for j in jobs.values() if j["status"] == "running")
        if running >= MAX_RUNNING:
            return None, 503, "Serwer jest zajęty innymi skanami. Spróbuj za minutę."
        q.append(now)
        jid = uuid.uuid4().hex
        jobs[jid] = {"id": jid, "key": key, "address": address, "range": rng, "status": "running",
                     "progress": 0, "message": "Start...", "created": now, "updated": now}
        cache[key] = (now, jid)
    t = threading.Thread(target=run_job, args=(jid,), daemon=True)
    t.start()
    return jid, None, None


def job_view(job):
    now = time.time()
    if job["status"] == "running" and now - job["created"] > JOB_MAX_SECONDS:
        job["status"], job["error"] = "error", "Skan trwa za długo (limit czasu). Spróbuj krótszego zakresu."
    out = {"job_id": job["id"], "status": job["status"], "progress": job["progress"],
           "message": job["message"], "address": job["address"], "range": job["range"],
           "cached": job["status"] == "done" and now - job.get("finished", now) > 1}
    if job["status"] == "done":
        out["result"] = job["result"]
    if job["status"] == "error":
        out["error"] = job["error"]
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "zgody-web/1.0"
    sys_version = ""
    timeout = 30   # timeout gniazda klienta (ochrona przed wolnymi polaczeniami)

    def log_message(self, fmt, *args):
        # Prywatnosc: bez IP, bez query stringow i bez adresow portfeli w logach.
        if os.environ.get("ACCESS_LOG", "1") != "1":
            return
        path = re.sub(r"0x[0-9a-fA-F]{40}", "0x…", urlparse(self.path).path)
        log("%s %s -> %s" % (self.command, path, args[1] if len(args) > 1 else ""))

    def client_ip(self):
        if TRUST_PROXY:
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store" if ctype.startswith("application/json") else "no-cache")
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def err(self, code, msg):
        self.send(code, {"error": msg})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path == "/healthz":
            return self.send(200, {"ok": True, "running_jobs": sum(1 for j in jobs.values() if j["status"] == "running"),
                                   "blacklist_entries": len(forensics._bl["index"])})
        if path == "/api/scan":
            q = parse_qs(u.query)
            return self.api_scan(q.get("address", [""])[0], q.get("range", ["year"])[0], wait=20)
        m = re.match(r"^/api/job/([0-9a-f]{32})$", path)
        if m:
            job = jobs.get(m.group(1))
            if not job:
                return self.err(404, "Nie ma takiego zadania (wygasło po 10 min?). Uruchom skan ponownie.")
            return self.send(200, job_view(job))
        if path == "/whitepaper":
            return self.doc_page("WHITEPAPER.md", "Szlaban – whitepaper")
        if path in ("/LICENSE", "/NOTICE", "/TRADEMARK"):
            name = {"/LICENSE": "LICENSE", "/NOTICE": "NOTICE", "/TRADEMARK": "TRADEMARK.md"}[path]
            fp = self.doc_path(name)
            if not fp:
                return self.err(404, "Nie znaleziono.")
            with open(fp, "rb") as f:
                return self.send(200, f.read(), "text/plain; charset=utf-8")
        if path == "/source.tar.gz":
            return self.send(200, source_tarball(), "application/gzip",
                             {"Content-Disposition": 'attachment; filename="szlaban-source.tar.gz"'})
        if re.match(r"^/r/0x[0-9a-fA-F]{40}/?$", path):
            return self.static("/index.html")
        if path in ("/binance", "/binance/"):
            return self.static("/binance.html")
        if path == "/robots.txt":
            return self.send(200, blueteam.ROBOTS.encode(), "text/plain; charset=utf-8")
        if path == "/api/blueteam/report":
            return self.send(200, blueteam.report(STATIC_DIR))
        m = re.match(r"^/t/((?:d-)?[0-9a-z-]{1,40})((?:\.gif|/[\w./-]{0,100})?)$", path)
        if m:
            return self.trap_hit(m.group(1), m.group(2))
        if path in blueteam.DECOY_SET:
            return self.decoy(path)
        if path.startswith("/api/"):
            return self.err(404, "Nieznany adres API.")
        return self.static(path)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/binance/relay":
            return self.binance_relay()
        if u.path == "/api/re/analyze":
            return self.re_analyze()
        if u.path in ("/api/trap/new", "/api/trap/hits", "/api/trap/delete"):
            return self.trap_api(u.path.rsplit("/", 1)[1])
        if u.path != "/api/scan":
            return self.err(404, "Nieznany adres API.")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > 2048:
            return self.err(413, "Za duże zapytanie.")
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return self.err(400, "Niepoprawny JSON.")
        return self.api_scan(str(data.get("address", "")), str(data.get("range", "year")), wait=0)

    def api_scan(self, address, rng, wait):
        addr, rng, e = validate(address, rng)
        if e:
            return self.err(400, e)
        jid, code, msg = start_or_reuse(addr, rng, self.client_ip())
        if code:
            return self.send(code, {"error": msg}, extra={"Retry-After": "60"})
        end = time.time() + wait
        while wait and jobs[jid]["status"] == "running" and time.time() < end:
            time.sleep(0.25)
        v = job_view(jobs[jid])
        if v["status"] == "running":
            v["poll"] = "/api/job/" + jid
            return self.send(202, v)
        return self.send(200 if v["status"] == "done" else 502, v)

    def binance_relay(self):
        """Relay Binance Guard. Bez logowania tresci: log_message zapisuje tylko sciezke i kod."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > 2048:
            return self.send(413, {"error": "too_large"})
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            return self.send(415, {"error": "json_required"})
        ip, now = self.client_ip(), time.time()
        cleanup()
        with lock:
            q = bg_hits.setdefault(ip, deque())
            while q and now - q[0] > BG_RATE_WINDOW:
                q.popleft()
            limited = len(q) >= BG_RATE_MAX
            if not limited:
                q.append(now)
        if limited:
            return self.send(429, {"error": "rate_limited"}, extra={"Retry-After": "60"})
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return self.send(400, {"error": "bad_json"})
        try:
            code, body = binance_relay.call(data)
        except binance_relay.RelayError as e:
            code, body = e.status, {"error": e.code, "message": e.msg}
        except Exception as e:  # nigdy nie logujemy danych wejsciowych, tylko typ bledu
            log("binance relay blad: %s" % type(e).__name__)
            code, body = 500, {"error": "internal"}
        return self.send(code, body, extra={"X-Robots-Tag": "noindex", "X-BG-Relay": "server"})

    def base_url(self):
        host = self.headers.get("X-Forwarded-Host") if TRUST_PROXY else None
        host = host or self.headers.get("Host") or "127.0.0.1"
        if not re.match(r"^[A-Za-z0-9.-]{1,200}(:\d{1,5})?$", host):
            host = "127.0.0.1"
        proto = "https" if (TRUST_PROXY and self.headers.get("X-Forwarded-Proto", "") == "https") or not re.match(r"^(127\.|localhost)", host) else "http"
        return "%s://%s" % (proto, host)

    def decoy(self, path):
        """Pusty alias dla skanerow: wiarygodna, falszywa tresc + wpis w raporcie Blue Team."""
        blueteam.record_decoy(path, self.client_ip(), self.headers.get("User-Agent", ""))
        blueteam.tarpit()
        ctype, body, code = blueteam.decoy_body(path, self.base_url())
        return self.send(code, body.encode("utf-8"), ctype, extra={"X-Robots-Tag": "noindex", "Cache-Control": "no-store"})

    def trap_hit(self, tid, rest):
        blueteam.record_hit(tid, rest, self.client_ip(), self.headers.get("User-Agent", ""))
        if rest.endswith(".gif"):
            return self.send(200, blueteam.GIF, "image/gif", extra={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"})
        if "/api" in rest or rest.endswith(".json"):
            return self.send(401, {"code": -2015, "msg": "Invalid API-key, IP, or permissions for action."})
        page = ("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\">"
                "<title>Link expired</title></head><body><p>This link has expired.</p></body></html>")
        return self.send(404, page.encode("utf-8"), "text/html; charset=utf-8", extra={"Cache-Control": "no-store"})

    def read_json(self, limit=2048):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > limit:
            return None, (413, "too_large")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
            return None, (415, "json_required")
        try:
            d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return None, (400, "bad_json")
        if not isinstance(d, dict):
            return None, (400, "bad_json")
        return d, None

    def trap_api(self, action):
        d, e = self.read_json()
        if e:
            return self.send(e[0], {"error": e[1]})
        ip = self.client_ip()
        if action == "new":
            if not blueteam.rate_ok("new", ip, 10):
                return self.send(429, {"error": "rate_limited"}, extra={"Retry-After": "60"})
            t = blueteam.new_token(str(d.get("label", "")), str(d.get("kind", "file")))
            if not t:
                return self.send(503, {"error": "full"})
            base = self.base_url()
            t["base"] = base
            t["urls"] = {"page": base + "/t/" + t["id"], "gif": base + "/t/" + t["id"] + ".gif",
                         "api": base + "/t/" + t["id"] + "/api/v3/account", "restore": base + "/t/" + t["id"] + "/restore",
                         "wallet": base + "/t/" + t["id"] + "/wallet"}
            t["ephemeral"] = bool(os.environ.get("RENDER"))
            return self.send(200, t)
        if not blueteam.rate_ok("view", ip, 60):
            return self.send(429, {"error": "rate_limited"}, extra={"Retry-After": "60"})
        tid, key = d.get("id"), d.get("key")
        if action == "hits":
            v = blueteam.view_token(tid, key)
            return self.send(200, v) if v else self.send(404, {"error": "not_found"})
        return self.send(200, {"ok": True}) if blueteam.delete_token(tid, key) else self.send(404, {"error": "not_found"})

    def re_analyze(self):
        """Statyczna analiza pliku. Tresc tylko w pamieci; nie logujemy nazwy ani zawartosci."""
        try:
            n = int(self.headers.get("Content-Length") or -1)
        except ValueError:
            n = -1
        if n < 1:
            return self.send(411, {"error": "length_required"})
        if n > re_static.MAX_FILE:
            return self.send(413, {"error": "too_large", "max": re_static.MAX_FILE})
        if not blueteam.rate_ok("re", self.client_ip(), RE_RATE_MAX):
            return self.send(429, {"error": "rate_limited"}, extra={"Retry-After": "60"})
        if not re_slots.acquire(blocking=False):
            return self.send(503, {"error": "busy"}, extra={"Retry-After": "10"})
        try:
            buf, left = bytearray(), n
            while left > 0:
                chunk = self.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                buf += chunk
                left -= len(chunk)
            if left:
                return self.send(400, {"error": "incomplete"})
            from urllib.parse import unquote
            name = unquote(self.headers.get("X-Filename", ""))[:200]
            try:
                res = re_static.analyze(bytes(buf), name)
            except Exception as e:  # analiza best effort; bez tresci w logu
                log("re blad: %s" % type(e).__name__)
                return self.send(500, {"error": "internal"})
            finally:
                del buf
            return self.send(200, res, extra={"X-Robots-Tag": "noindex"})
        finally:
            re_slots.release()

    def doc_path(self, name):
        for d in DOC_DIRS:
            fp = os.path.join(d, name)
            if os.path.isfile(fp):
                return fp
        return None

    def doc_page(self, name, title):
        fp = self.doc_path(name)
        if not fp:
            return self.err(404, "Nie znaleziono.")
        with open(fp, encoding="utf-8") as f:
            body = mdlite.render(f.read())
        page = ("<!DOCTYPE html><html lang=\"pl\"><head><meta charset=\"utf-8\">"
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                "<title>%s</title><link rel=\"icon\" href=\"/favicon.svg\"><link rel=\"stylesheet\" href=\"/style.css\"></head>"
                "<body><header class=\"top\"><div class=\"stripe\"></div><div class=\"wrap brand\"><a href=\"/\" class=\"name\">SZLABAN</a></div></header>"
                "<main class=\"wrap\"><article class=\"panel doc\">%s</article>"
                "<footer class=\"small\"><a href=\"/\">← Szlaban</a> · <a href=\"%s\">Kod źródłowy (AGPL-3.0)</a> · <a href=\"/LICENSE\">Licencja</a> · <a href=\"/NOTICE\">NOTICE</a> · <a href=\"/TRADEMARK\">Znak</a></footer>"
                "</main></body></html>") % (title, body, SOURCE_URL)
        return self.send(200, page.encode("utf-8"), "text/html; charset=utf-8")

    def static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        name = os.path.basename(path)
        if path != "/" + name or name.startswith(".") or not re.match(r"^[\w.-]+$", name):
            return self.err(404, "Nie znaleziono.")
        fp = os.path.join(STATIC_DIR, name)
        ext = os.path.splitext(name)[1]
        if not os.path.isfile(fp) or ext not in MIME:
            return self.send(404, "Nie znaleziono".encode(), "text/plain; charset=utf-8")
        with open(fp, "rb") as f:
            return self.send(200, f.read(), MIME[ext])


def source_tarball():
    if "tgz" in _src_cache:
        return _src_cache["tgz"]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in SOURCE_FILES:
            fp = os.path.join(APP_DIR, rel)
            if not os.path.isfile(fp):
                fp = os.path.join(APP_DIR, "docs", os.path.basename(rel))
            if os.path.isfile(fp):
                info = tar.gettarinfo(fp, arcname="szlaban/" + rel)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(fp, "rb") as f:
                    tar.addfile(info, f)
    _src_cache["tgz"] = buf.getvalue()
    return _src_cache["tgz"]


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    threading.Thread(target=forensics.load_blacklists, daemon=True).start()  # czarne listy w tle
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    log("Skaner zgod ERC-20 (tylko odczyt) na http://%s:%d" % (host, port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
