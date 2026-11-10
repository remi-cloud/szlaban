<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 Robi (@robi44610) -->
# Szlaban

**Kto ma klucz do Twoich tokenów?** Szlaban to audyt zgód ERC-20 (approvals) na Ethereum. Pokazuje,
ile dolarów z Twojego salda mogą dziś zabrać kontrakty, którym kiedyś dałeś zgodę. Liczy też
Wskaźnik odporności 0–100 według jawnego wzoru i układa plan sprzątania.
**Tylko odczyt:** bez łączenia portfela, bez kluczy i bez transakcji.

![Szlaban – widok komputera](docs/screenshots/screenshot.png)

[English below](#english)

## Funkcje

- **Kwota zagrożona (USD)**: min(zgoda, saldo) × cena z DefiLlama. W sumie każdy token liczony jest raz.
- **Wskaźnik odporności 0–100**: każde potrącenie jest pokazane i opisane (wzór w [WHITEPAPER.md](WHITEPAPER.md)).
- **Kartoteka spendera**: kontrakt, EOA albo EOA z delegacją EIP-7702, wiek kontraktu (blok utworzenia)
  i trafienia na publicznych czarnych listach.
- **Oś czasu**: kiedy ustawiono każdą zgodę. Zapomniane zgody bez limitu (ponad rok bez zmian) pulsują.
- **Plan sprzątania**: kolejność cofania, linki do Etherscan i revoke.cash, przycisk „Skopiuj plan”.
- **Raport do udostępnienia**: `/r/<adres>?range=year|all|OD-DO`.
- Polski interfejs, ciemny motyw, działa na iPhonie (Safari) i na komputerze.

## Uruchomienie

### Python (bez instalowania czegokolwiek, wystarczy Python ≥ 3.9)

```
python3 server.py              # http://127.0.0.1:8080
PORT=9000 python3 server.py    # inny port
```

### Docker

```
docker build -t szlaban .
docker run --rm -p 8080:8080 --name szlaban szlaban
```

Potem otwórz http://127.0.0.1:8080. Obraz bazuje na oficjalnym `python:3-slim`, działa jako
użytkownik bez uprawnień i ma HEALTHCHECK na `/healthz`.

### Zmienne środowiskowe

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | adres nasłuchu |
| `CACHE_TTL` | `600` | ile sekund trzymać wynik w RAM |
| `RATE_MAX` / `RATE_WINDOW` | `10` / `600` | nowe skany na IP w oknie (s) |
| `MAX_RUNNING` | `4` | równoczesne skany |
| `JOB_MAX_SECONDS` | `600` | limit czasu skanu |
| `TRUST_PROXY` | `0` | `1` = ufaj `X-Forwarded-For` (tylko za proxy chmury) |
| `ZGODY_RPC` | – | własne węzły RPC, oddzielone przecinkami (zastępują wbudowane) |
| `ACCESS_LOG` | `1` | `0` wyłącza log żądań (i tak bez adresów i IP) |
| `SOURCE_URL` | `/source.tar.gz` | link do kodu w stopce (np. repozytorium) |

## API

| Metoda | Ścieżka | Opis |
|---|---|---|
| `POST` | `/api/scan` | body `{"address":"0x…","range":"year"\|"all"\|"OD-DO"}` → `202 {"job_id":…}` |
| `GET` | `/api/scan?address=0x…&range=…` | czeka do 20 s; `200` z wynikiem albo `202` z `job_id` |
| `GET` | `/api/job/<id>` | `{"status":"running\|done\|error","progress":0–100,"message":…,"result"\|"error"}` |
| `GET` | `/healthz` | `{"ok":true,…}` |
| `GET` | `/r/<adres>` | raport do udostępnienia |
| `GET` | `/whitepaper`, `/LICENSE`, `/NOTICE`, `/TRADEMARK` | dokumenty |
| `GET` | `/source.tar.gz` | kod źródłowy tej instancji (AGPL §13) |

Błędy: `400` (zły adres, zakres albo JSON), `429` (limit na IP), `503` (serwer zajęty),
`502` (wszystkie węzły zawiodły). Treść błędu jest po polsku w polu `error`.

`result` zawiera m.in.: `summary`, `usd_at_risk_total`, `score{value,grade,deductions[]}`, `plan[]`,
`rows[]` (token, spender, allowance, risk, notes, usd_at_risk, spender_kind,
spender_created_block, spender_age_days, blacklist[], approval_ts, days_since_approval, forgotten,
hidden_unknown, hidden_foreign), `blacklist_sources[]`, `price_source`.

## Testy

```
BASE=http://127.0.0.1:8080 bash tests/test_api.sh     # API (curl)
bash tests/run_e2e.sh                                  # przeglądarka bez okna (node + Chrome)
```

## Licencja

**GNU AGPL-3.0-only**, © 2026 Robi (@robi44610), patrz [LICENSE](LICENSE). Kto uruchamia
**zmodyfikowaną** wersję jako usługę sieciową, musi udostępnić jej kod użytkownikom (AGPL, sekcja 13).
Nazwa i logo „Szlaban” nie są licencjonowane dla forków ([TRADEMARK.md](TRADEMARK.md)).
Licencja komercyjna lub zamknięta jest dostępna u autora na prośbę. Źródła danych zewnętrznych są
opisane w [NOTICE](NOTICE).

> Tylko informacje, nie porada finansowa ani usługa bezpieczeństwa. Brak gwarancji. Szlaban nigdy
> nie wykonuje transakcji.

---

## English

**Szlaban** ("boom barrier") audits ERC-20 approvals on Ethereum. It shows how many dollars of your
*current* balance approved spenders could take today, computes a 0–100 resilience score with a
published formula, profiles every spender (contract/EOA/EIP-7702, contract age, public blocklists),
draws a timeline of forgotten unlimited approvals and builds an ordered cleanup plan.
**Read-only:** no wallet connection, no keys, no transactions.

Run with `python3 server.py` (Python ≥ 3.9, standard library only) or with Docker:
`docker build -t szlaban . && docker run --rm -p 8080:8080 szlaban`, then open http://127.0.0.1:8080.
The API is described above, and the method, formula, data sources, threat model and limitations are
in [WHITEPAPER.md](WHITEPAPER.md).

Licence: **AGPL-3.0-only**, © 2026 Robi (@robi44610). If you run a modified version as a network
service you must offer its source to users (AGPL §13). The name and logo are not licensed to forks.
Commercial or closed licensing is available from the author on request. Information only, no warranty.

| Desktop | Mobile (390 px) |
|---|---|
| ![](docs/screenshots/hero.png) | ![](docs/screenshots/screenshot-mobile.png) |
