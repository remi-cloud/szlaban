#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Robi (@robi44610)
# Test e2e w przegladarce bez okna. Wymaga: node, Chrome/Chromium (CHROME=/sciezka).
# BASE = dzialajacy Szlaban, FAILBASE = Szlaban uruchomiony z ZGODY_RPC=http://127.0.0.1:9 (test awarii wezlow).
set -eu
cd "$(dirname "$0")"
[ -d node_modules/playwright-core ] || npm install --no-audit --no-fund
BASE="${BASE:-http://127.0.0.1:8765}" FAILBASE="${FAILBASE:-http://127.0.0.1:8766}" OUT="${OUT:-../docs/screenshots/}" node e2e.js
