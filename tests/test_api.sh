#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
# Szybki test API: BASE=http://127.0.0.1:8080 bash tests/test_api.sh
set -u
BASE="${BASE:-http://127.0.0.1:8080}"
A=0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
ok=0; bad=0
check() { if [ "$2" = "$3" ]; then echo "OK   $1 ($2)"; ok=$((ok+1)); else echo "FAIL $1: oczekiwano $3, jest $2"; bad=$((bad+1)); fi; }
check healthz "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz")" 200
check "zly adres" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/scan?address=0x123")" 400
check "ENS" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/scan?address=vitalik.eth")" 400
check "zly zakres" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/scan?address=$A&range=20000000-15000000")" 400
check "zly JSON" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -d 'x{' "$BASE/api/scan")" 400
check "path traversal" "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "$BASE/../server.py")" 404
check whitepaper "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/whitepaper")" 200
check source "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/source.tar.gz")" 200
check "raport /r/" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/r/$A")" 200
code=$(curl -s -o /tmp/szlaban_api.json -w '%{http_code}' "$BASE/api/scan?address=$A&range=15000000-20000000")
if [ "$code" = 202 ]; then
  jid=$(python3 -c "import json;print(json.load(open('/tmp/szlaban_api.json'))['job_id'])")
  for i in $(seq 1 120); do sleep 2; curl -s "$BASE/api/job/$jid" -o /tmp/szlaban_api.json
    python3 -c "import json,sys;sys.exit(0 if json.load(open('/tmp/szlaban_api.json'))['status']!='running' else 1)" && break; done
fi
check "skan 15M-20M podsumowanie" "$(python3 -c "import json;r=json.load(open('/tmp/szlaban_api.json'))['result'];print(r['summary'])")" "{'WYSOKIE': 14, 'SREDNIE': 2, 'NISKIE': 3}"
# --- Binance Guard ---
check "binance strona" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/binance")" 200
check "binance strona /" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/binance/")" 200
for f in binance.js binance.css bg-i18n.js bg-core.js bg-detector.js; do
  check "binance plik $f" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$f")" 200
done
check "binance zastrzezenie w HTML" "$(curl -s "$BASE/binance" | grep -c 'Not affiliated with, endorsed by or sponsored by Binance')" 1
check "binance CSP" "$(curl -sI "$BASE/binance" | grep -ci "^content-security-policy: default-src 'self'")" 1
check "link w nawigacji Szlabanu" "$(curl -s "$BASE/" | grep -c 'href="/binance"')" 1
R="$BASE/api/binance/relay"; J='Content-Type: application/json'
K=TESTKEYneverLOGGED0000000000000000000000000000000000000000000000
TS=$(python3 -c 'import time;print(int(time.time()*1000))'); SG=$(printf 'a%.0s' $(seq 1 64))
check "relay endpoint spoza listy" "$(curl -s -o /dev/null -w '%{http_code}' -H "$J" -d '{"endpoint":"order"}' "$R")" 400
check "relay pole secret odrzucone" "$(curl -s -H "$J" -d '{"endpoint":"apiRestrictions","secret":"x"}' "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin)["error"])')" bad_field
check "relay zly podpis" "$(curl -s -H "$J" -d "{\"endpoint\":\"apiRestrictions\",\"apiKey\":\"$K\",\"timestamp\":\"$TS\",\"recvWindow\":\"5000\",\"signature\":\"zz\"}" "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin)["error"])')" bad_signature
check "relay wymaga JSON" "$(curl -s -o /dev/null -w '%{http_code}' -d 'a=1' "$R")" 415
check "relay za duze" "$(head -c 5000 /dev/zero | tr '\0' a | curl -s -o /dev/null -w '%{http_code}' -H "$J" --data-binary @- "$R")" 413
check "relay no-store" "$(curl -s -D - -o /dev/null -H "$J" -d '{}' "$R" | grep -ci '^cache-control: no-store')" 1
# Prawdziwe zapytanie do Binance (podpis falszywy): 400 (Binance odrzuca klucz), albo 451 jesli serwer stoi w regionie zablokowanym
code=$(curl -s -o /tmp/bg_relay.json -w '%{http_code}' -H "$J" -d "{\"endpoint\":\"apiRestrictions\",\"apiKey\":\"$K\",\"timestamp\":\"$TS\",\"recvWindow\":\"5000\",\"signature\":\"$SG\"}" "$R")
case "$code" in 400|451|502) check "relay do Binance ($(cat /tmp/bg_relay.json | head -c 120))" ok ok;; *) check "relay do Binance" "$code" "400|451|502";; esac
code=$(curl -s -o /tmp/bg_time.json -w '%{http_code}' -H "$J" -d '{"endpoint":"time"}' "$R")
case "$code" in 200|451|502) check "relay time ($code)" ok ok;; *) check "relay time" "$code" "200|451|502";; esac
# --- RE + Blue Team ---
check "plik bg-blue.js" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/bg-blue.js")" 200
printf 'Binance: send your seed phrase to https://binance-help.top/x 1234567890:AA%s' "$(printf 'b%.0s' $(seq 1 33))" > /tmp/bt_sample.txt
check "RE analiza tekstu" "$(curl -s -H 'Content-Type: application/octet-stream' -H 'X-Filename: sample.txt' --data-binary @/tmp/bt_sample.txt "$BASE/api/re/analyze" | python3 -c 'import json,sys;r=json.load(sys.stdin);c={i["code"] for i in r["indicators"]};print(int({"seed_harvest","telegram_exfil"}<=c and r["type"]=="text"))')" 1
head -c 21000000 /dev/zero > /tmp/bt_big.bin
check "RE limit 20 MB" "$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/octet-stream' --data-binary @/tmp/bt_big.bin "$BASE/api/re/analyze")" 413
check "RE bez tresci" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/re/analyze")" 411
check "decoy /.env" "$(curl -s "$BASE/.env" | grep -c 'BINANCE_API_KEY=SZLD')" 1
check "decoy /.git/config alias" "$(curl -s "$BASE/.git/config" | grep -c '/t/d-git')" 1
check "decoy /wp-login.php" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/wp-login.php")" 200
check "robots.txt" "$(curl -s "$BASE/robots.txt" | grep -c 'Disallow: /admin/')" 1
check "raport blueteam" "$(curl -s "$BASE/api/blueteam/report" | python3 -c 'import json,sys;r=json.load(sys.stdin);print(int(r["hits_total"]>=3 and r["frontend"]["secrets"]==0 and "/.env" in r["by_path"]))')" 1
T=$(curl -s -H "$J" -d '{"label":"ci","kind":"file"}' "$BASE/api/trap/new")
TID=$(echo "$T" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])'); TK=$(echo "$T" | python3 -c 'import json,sys;print(json.load(sys.stdin)["key"])')
check "pulapka gif" "$(curl -s -o /dev/null -w '%{http_code} %{content_type}' -A 'CI-UA' "$BASE/t/$TID.gif")" "200 image/gif"
check "pulapka strona" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/t/$TID/restore")" 404
check "nieznana pulapka wyglada tak samo" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/t/00000000000000000000/restore")" 404
check "panel: trafienia" "$(curl -s -H "$J" -d "{\"id\":\"$TID\",\"key\":\"$TK\"}" "$BASE/api/trap/hits" | python3 -c 'import json,sys;h=json.load(sys.stdin)["hits"];print(len(h), h[-1]["ua"])')" "2 CI-UA"
check "panel: zly klucz" "$(curl -s -o /dev/null -w '%{http_code}' -H "$J" -d "{\"id\":\"$TID\",\"key\":\"xxxxxxxxxxxxxxxxxxxxxxxx\"}" "$BASE/api/trap/hits")" 404
check "panel: usun" "$(curl -s -o /dev/null -w '%{http_code}' -H "$J" -d "{\"id\":\"$TID\",\"key\":\"$TK\"}" "$BASE/api/trap/delete")" 200
echo "wynik: $ok OK, $bad FAIL"; [ $bad = 0 ]
