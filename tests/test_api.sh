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
echo "wynik: $ok OK, $bad FAIL"; [ $bad = 0 ]
