<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 Robi (@robi44610) -->
# Szlaban – whitepaper

**Audyt zgód ERC-20 na Ethereum: ile realnie możesz stracić, jak odporny jest portfel i co cofnąć najpierw.**
Wersja 1.0 · 10 listopada 2026 · autor: Robi (@robi44610) · licencja kodu: AGPL-3.0-only

> Dokument w dwóch językach: najpierw polski, potem angielski ([English version](#english-version)).

---

## 1. Problem

Gdy w aplikacji DeFi klikasz „Approve”, wywołujesz w kontrakcie tokena funkcję `approve(spender, kwota)`.
Od tej chwili `spender` może sam wywołać `transferFrom` i zabrać tokeny do ustalonej kwoty, bez kolejnego
podpisu. Aplikacje często proszą o zgodę „bez limitu” (2²⁵⁶−1), a zgoda nie wygasa sama. Te same
uprawnienia można też nadać podpisem poza siecią (`permit`, EIP-2612, albo Uniswap Permit2).

Udokumentowane, publiczne przykłady:

- **LI.FI, 16.07.2024**: błąd w nowo dodanym module kontraktu pozwolił napastnikowi wywołać `transferFrom`
  na portfelach z **nielimitowaną** zgodą dla LI.FI. Skradziono ok. 11,6 mln USD ze 153 portfeli.
  Według LI.FI zgody ograniczone nie zostały dotknięte.
  Źródło: [LI.FI Incident Report](https://li.fi/knowledge-hub/incident-report-16th-july).
- **Socket / Bungee, 16.01.2024**: nowa „trasa” w SocketGateway wykonywała niezweryfikowane dane wejściowe.
  Napastnik użył istniejących zgód użytkowników i zabrał ok. 3,3 mln USD z ok. 230 portfeli.
  Źródła: [CertiK](https://www.certik.com/blog/socket-tech-incident-analysis),
  [Halborn](https://www.halborn.com/blog/post/explained-the-socket-protocol-hack-january-2024).
- **Phishing podpisów**: ScamSniffer szacuje straty z „wallet drainerów” na EVM na 494 mln USD w 2024 r.
  i 83,85 mln USD w 2025 r. Wśród przypadków powyżej 1 mln USD w 2025 r. dominowały podpisy
  Permit/Permit2 (8,72 mln USD) oraz approve/increaseApproval (5,62 mln USD).
  Źródło: [ScamSniffer 2025 report](https://drops.scamsniffer.io/scam-sniffer-2025-crypto-phishing-losses-fall-83-to-84-million/).

Wniosek: stara, zapomniana zgoda bez limitu to **odroczone ryzyko**. Nic się nie dzieje, dopóki
kontrakt nie zostanie zhakowany albo nie okaże się złośliwy.

## 2. Co robi Szlaban

Szlaban to aplikacja www (backend w Pythonie, przeglądarkowy frontend), która dla podanego adresu:

1. odtwarza listę zgód ERC-20 z blockchaina i sprawdza ich **aktualny** stan;
2. liczy **kwotę zagrożoną w USD**;
3. prześwietla każdego spendera (kontrakt, EOA, EOA z delegacją EIP-7702, wiek kontraktu, czarne listy);
4. pokazuje **oś czasu** zgód z wyróżnieniem zapomnianych;
5. wylicza **Wskaźnik odporności 0–100** według jawnego wzoru;
6. układa **plan sprzątania**, czyli kolejność cofania zgód.

Szlaban **nie łączy się z portfelem, nie zna kluczy i nie wysyła transakcji**. Cofanie robisz sam,
w portfelu, przez wybrane narzędzie (linki do revoke.cash i Etherscan).

## 3. Metoda

### 3.1 Odtworzenie zgód (logika z `zgody.py`)

1. `eth_getLogs` dla zdarzenia `Approval(address indexed owner, address indexed spender, uint256 value)`
   (temat `0x8c5be1e5…b925`), filtrowanego po `topic1 = owner`. Przy limitach zakresu węzła zakres
   jest dzielony na kawałki, a przy kolejnych błędach aplikacja przełącza się na inny węzeł.
2. Zdarzenia z 4 tematami (ERC-721, `tokenId` indeksowany) są pomijane. Zostaje tylko ERC-20.
3. Dla każdej pary (token, spender) liczy się tylko ostatnie zdarzenie (blok, `logIndex`).
4. **Aktualna** zgoda: `allowance(owner, spender)` przez `eth_call`. Wartości 0, czyli cofnięte, są pomijane.
5. Metadane: `symbol()` (string ABI albo `bytes32`), `decimals()` (> 77 traktowane jako błąd),
   `eth_getCode` spendera, nadawca transakcji ze zgodą (`eth_getTransactionByHash`).
6. Ukrywane domyślnie, tak jak w CLI: tokeny bez symbolu lub `decimals` (zwykle spam) oraz zgody
   dla znanych routerów ustawione cudzą transakcją (typowy spam memecoinów). Można je włączyć filtrem.

**Ocena ryzyka wiersza:** WYSOKIE, gdy zgoda ≥ 2²⁵⁵ (traktowana jak nielimitowana). NISKIE, gdy zgoda
jest ograniczona, a spender jest na liście znanych kontraktów. ŚREDNIE we wszystkich pozostałych
przypadkach.

### 3.2 Kwota zagrożona (USD)

Dla każdej aktywnej zgody:

```
zagrożone_token = min(allowance, balanceOf(owner))           // w jednostkach tokena
zagrożone_usd   = zagrożone_token / 10^decimals × cena_usd
```

- `balanceOf` przez `eth_call` w bloku `latest`.
- Cena: [DefiLlama coins API](https://defillama.com/docs/api) (`coins.llama.fi/prices/current`). Ceny
  z polem `confidence` < **0,9** są pomijane (wartość „–”, nie zero).
- **Suma dla portfela** liczy każdy token raz. Saldo da się ukraść tylko raz, więc dla tokena bierzemy
  największą ekspozycję spośród jego zgód: `Σ_token max_spender(zagrożone_usd)`.
- To górna granica tego, co spenderzy mogą zabrać **z obecnego salda**. Nie obejmuje tokenów, które
  kupisz w przyszłości, choć zgoda bez limitu obejmie również je.

### 3.3 Kryminalistyka spendera

- **Rodzaj adresu**: `eth_getCode(latest)`. Pusty kod oznacza EOA, czyli zwykłe konto. Kod
  `0xef0100‖adres` (23 bajty) oznacza EOA z delegacją **EIP-7702** i pokazujemy adres delegata.
  Każdy inny kod to kontrakt.
- **Wiek kontraktu**: wyszukiwanie binarne najniższego bloku, w którym `eth_getCode(adres, blok)` nie jest
  pusty. Robimy to na węzłach archiwalnych, w około 25 rundach paczek zapytań. Data pochodzi z
  `eth_getBlockByNumber`. Ograniczenie: przy kontraktach usuniętych i ponownie wdrożonych pod tym samym
  adresem (CREATE2) wynik może wskazać inne wdrożenie.
- **Czarne listy**: dopasowanie adresu spendera do publicznych list z GitHuba (szczegóły w p. 5).
  Listy są pobierane na serwer i odświeżane co 24 h. **Wszystkie są historyczne.** Brak trafienia
  nie oznacza, że spender jest bezpieczny.
- **„NIE Twoja tx”**: zgodę ustawiła transakcja wysłana przez inny adres niż właściciel. To podpis
  `permit` (możliwy phishing) albo fałszywe zdarzenie wyemitowane przez spam-token.

### 3.4 Oś czasu i zgody „zapomniane”

Data zgody to znacznik czasu bloku z ostatnim zdarzeniem `Approval` dla pary. Zgoda jest
**zapomniana**, gdy jest nielimitowana i od ustawienia minęło ≥ **365 dni**.
Uwaga: Szlaban nie analizuje `transferFrom`, więc nie wie, czy spender korzystał ze zgody. Wie tylko,
że jej nie zmieniano.

### 3.5 Wskaźnik odporności portfela (0–100), dokładny wzór

Liczony z widocznych zgód w wybranym zakresie bloków:

```
wynik = max(0, 100 − Σ potrąceń)
```

| Zasada | Za sztukę | Limit |
|---|---|---|
| spender na publicznej czarnej liście | −25 | −50 |
| zgoda dla EOA (także z delegacją EIP-7702) | −10 | −20 |
| zgoda nielimitowana (≥ 2²⁵⁵) | −4 | −24 |
| zgoda zapomniana (nielimitowana, ≥ 365 dni bez zmian) | −2 | −10 |
| zgoda ustawiona cudzą transakcją (permit/spam) | −3 | −9 |
| łączna kwota zagrożona: ≥10 $ −5 · ≥100 $ −10 · ≥1 000 $ −15 · ≥10 000 $ −20 · ≥100 000 $ −25 | progi | −25 |

Maksymalna suma potrąceń to 138 punktów, ale wynik nie spada poniżej 0.
Progi opisowe: 80–100 *Twierdza*, 60–79 *Solidnie*, 40–59 *Do sprzątania*, 0–39 *Alarm*.
Wagi są decyzją projektową autora (nie pochodzą z badań statystycznych). Aplikacja pokazuje każde
potrącenie, więc użytkownik widzi, skąd się wziął wynik.

### 3.6 Plan sprzątania

Lista zgód o ryzyku WYSOKIE lub ŚREDNIE, a także każdej zgody na czarnej liście albo z kwotą zagrożoną > 0.
Kolejność sortowania:

1. najpierw spender na czarnej liście,
2. potem malejąco kwota zagrożona (USD),
3. potem zgoda nielimitowana dla EOA,
4. potem zgoda nielimitowana dla nieznanego kontraktu,
5. potem dowolna zgoda nielimitowana,
6. na końcu najstarsze.

Każda pozycja ma linki do tokena i spendera w Etherscan. Cofasz w swoim portfelu, np. w revoke.cash
albo w Etherscan Token Approval Checker.

## 4. Porównanie z istniejącymi narzędziami (stan: 10.11.2026)

Takie narzędzia już istnieją i są dojrzałe. Szlaban nie twierdzi, że jest pierwszy. Poniżej tylko
różnice, które da się sprawdzić w kodzie albo w publicznej dokumentacji tych produktów.

| Narzędzie | Co publicznie oferuje (wg źródła) |
|---|---|
| [Revoke.cash](https://revoke.cash/blog/2026/update-q3) | lista i cofanie zgód na wielu sieciach, „Value at Risk” w USD (od 09.2023), płatne plany Premium/Ultimate z automatycznym cofaniem |
| [De.Fi Shield](https://docs.de.fi/security-toolkit/shield) | skan zgód i tokenów, „Wallet Health Score” 0–100, cofanie zgód |
| Rabby Wallet | strona „Approvals” w portfelu z flagami ryzyka i cofaniem ([rabby.is](https://www.rabby.is/en/security.html)) |
| Etherscan Token Approval Checker | lista zgód adresu i cofanie po połączeniu portfela |

**Sprawdzalne różnice Szlabanu:**

- **Zero kodu transakcyjnego.** W kodzie nie ma integracji z portfelem ani podpisywania. Serwer wysyła
  wyłącznie metody odczytu (`eth_getLogs`, `eth_call`, `eth_getCode`, `eth_getBlockByNumber`,
  `eth_getTransactionByHash`, `eth_blockNumber`). Cofanie zostaje po stronie wybranego przez Ciebie narzędzia.
- **Jawny wzór wyniku.** Każda waga i każdy limit są opisane tutaj i pokazane w aplikacji przy każdym
  potrąceniu. W publicznych materiałach De.Fi i Revoke.cash nie znaleźliśmy pełnego wzoru ich wyników
  (to stwierdzenie dotyczy tylko tego, co znaleźliśmy).
- **Wiek kontraktu spendera** z wyszukiwania binarnego `eth_getCode` i **oznaczanie EOA z delegacją EIP-7702**.
- **Suma bez podwójnego liczenia** (każdy token raz) z opisaną metodą.
- **Oś czasu ze strefą „zapomnianych” zgód.**
- **Samodzielny hosting**: jeden kontener, tylko biblioteka standardowa Pythona, bez kluczy API i bez bazy
  danych. Licencja AGPL-3.0, polski interfejs.

Szlaban obsługuje **mniej** niż te narzędzia: tylko Ethereum mainnet, tylko ERC-20, bez NFT, bez rozpisywania
zgód wewnątrz Permit2, bez symulacji transakcji i bez monitoringu.

## 5. Źródła danych

| Dane | Źródło | Uwagi |
|---|---|---|
| zgody, salda, kod, bloki | publiczne węzły JSON-RPC: Tenderly, MEV Blocker, Flashbots, PublicNode, dRPC | bez klucza, z limitami; węzły archiwalne: Tenderly, MEV Blocker, dRPC |
| ceny | [DefiLlama coins API](https://defillama.com/docs/api) | bez klucza; `confidence` ≥ 0,9 |
| czarna lista | [ScamSniffer scam-database](https://github.com/scamsniffer/scam-database) `address.json` (GPL-3.0) | wg README nieaktualizowana od 02.2024 |
| czarna lista | [Forta labelled-datasets](https://github.com/forta-network/labelled-datasets) (MIT): `phishing_scams.csv`, `malicious_smart_contracts.csv`, `etherscan_malicious_labels.csv` | stan z 01.2023 |
| czarna lista | [MyEtherWallet ethereum-lists](https://github.com/MyEtherWallet/ethereum-lists) `addresses-darklist.json` (MIT) | ostatnia zmiana 2020 |
| znane kontrakty | lista marek w `zgody.py` (Uniswap, 1inch, CoW, 0x, ParaSwap, Balancer, Aave, Compound, KyberSwap, MetaMask Swap) | „znany” to marka, a nie audyt |

## 6. Model bezpieczeństwa i zagrożeń

**Założenia:** Szlaban tylko czyta dane. Nie przyjmuje kluczy, fraz seed ani podpisów i nie ma czego ukraść
poza wynikiem skanu publicznego adresu.

| Zagrożenie | Środek zaradczy |
|---|---|
| złośliwe dane z łańcucha (np. symbol tokena z HTML/JS) | frontend wstawia tekst przez `textContent`, nigdy `innerHTML`; nagłówek CSP `default-src 'self'` bez inline-skryptów |
| nadużycie serwera (DoS, koszt RPC) | limit skanów na IP (domyślnie 10/10 min), limit równoczesnych skanów (4), cache wyników 10 min, limit czasu zadania 600 s, limit ciała POST 2 KB, timeout gniazda 30 s |
| path traversal przy plikach statycznych | biała lista nazw plików, tylko katalog `static/` |
| nieuczciwy lub awaryjny węzeł RPC | kilka niezależnych węzłów z przełączaniem; dane łańcucha można zweryfikować linkami do Etherscan |
| fałszywe ceny | tylko DefiLlama z progiem `confidence`; brak ceny = „–” |
| podszywanie się pod Szlaban (phishing) | Szlaban **nigdy** nie prosi o połączenie portfela. Strona, która o to prosi, nie jest Szlabanem |
| clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |

Kontener działa jako użytkownik bez uprawnień (UID 10001).

## 7. Prywatność

- Brak kont, ciasteczek, analityki i zewnętrznych skryptów. Frontend łączy się tylko z własnym serwerem.
- Wyniki skanu (z adresem) są trzymane **tylko w pamięci RAM** przez czas cache (domyślnie 10 min),
  potem usuwane. Nie ma bazy danych.
- Logi serwera **nie zawierają adresów portfeli, IP ani query stringów**: adresy w ścieżkach są
  maskowane jako `0x…`. Adres IP jest trzymany w pamięci tylko na czas okna limitu (10 min).
- Serwer, wykonując skan, ujawnia sprawdzany adres publicznym węzłom RPC i (przez listę tokenów)
  DefiLlama, tak jak każdy portfel czy eksplorator. Te usługi mają własne zasady prywatności.
- Link `/r/<adres>` zawiera adres. Udostępniaj go świadomie: adresy i zgody są publiczne na blockchainie,
  ale link łączy adres z Tobą.

## 8. Ograniczenia

- Tylko Ethereum mainnet i tokeny ERC-20. Bez NFT (`setApprovalForAll`), bez rozpisywania zgód wewnątrz Permit2.
- Nieobsługiwane: ENS, podpisy poza siecią, które nie zostały jeszcze użyte (nie ma ich w łańcuchu).
- Zależność od darmowych węzłów i API, które mają limity i mogą się zmienić.
- Czarne listy są historyczne. „Znany kontrakt” to nie audyt. Nawet znane kontrakty bywały hakowane
  (patrz LI.FI, Socket).
- Wiek kontraktu jest przybliżony przy wdrożeniach CREATE2 i po `selfdestruct`.
- Wskaźnik odporności to heurystyka z arbitralnymi wagami, a nie miara prawdopodobieństwa straty.

## 9. Licencja

Kod: **GNU AGPL-3.0-only**. Każdy, kto uruchamia **zmodyfikowaną** wersję jako usługę sieciową, musi
udostępnić jej użytkownikom kod źródłowy (AGPL, sekcja 13). Szlaban robi to sam pod `/source.tar.gz`.
Nazwa i logo nie są licencjonowane dla forków (patrz `TRADEMARK.md`). **Licencja komercyjna lub
zamknięta** jest dostępna u autora na prośbę.

## 10. Zastrzeżenia prawne

Szlaban służy **wyłącznie celom informacyjnym**. Nie jest poradą finansową, inwestycyjną, prawną ani
usługą bezpieczeństwa. Oprogramowanie jest dostarczane **„tak jak jest”, bez żadnej gwarancji**
(patrz sekcje 15–16 AGPL-3.0). Autor nie odpowiada za straty wynikające z użycia lub braku użycia
narzędzia, z błędnych danych zewnętrznych (węzły, ceny, listy) ani z decyzji podjętych na podstawie wyniku.
Szlaban **nie wykonuje żadnych transakcji** i nie ma dostępu do środków użytkownika.

---

## English version

**Szlaban** (Polish for "boom barrier") audits ERC-20 approvals on Ethereum. It shows how much you could
actually lose, how resilient the wallet is, and what to revoke first.
Version 1.0 · 10 November 2026 · author: Robi (@robi44610) · code licence: AGPL-3.0-only

### 1. Problem

`approve(spender, amount)` lets `spender` call `transferFrom` later, without another signature. dApps
often request unlimited allowances (2²⁵⁶−1) that never expire. The same rights can be granted off-chain
with `permit` (EIP-2612) or Uniswap Permit2. Documented public cases:

- **LI.FI, 16 Jul 2024**: a newly deployed facet allowed arbitrary calls. About $11.6M was taken from
  153 wallets that had set *infinite* approvals; LI.FI states that finite approvals were not affected.
  [LI.FI incident report](https://li.fi/knowledge-hub/incident-report-16th-july).
- **Socket/Bungee, 16 Jan 2024**: unvalidated input in a new route. About $3.3M was taken from about
  230 wallets through existing approvals. [CertiK](https://www.certik.com/blog/socket-tech-incident-analysis),
  [Halborn](https://www.halborn.com/blog/post/explained-the-socket-protocol-hack-january-2024).
- **Signature phishing**: ScamSniffer reports $494M (2024) and $83.85M (2025) of EVM wallet-drainer
  losses. Among 2025 cases over $1M, Permit/Permit2 accounted for $8.72M and approve/increaseApproval for $5.62M.
  [ScamSniffer 2025](https://drops.scamsniffer.io/scam-sniffer-2025-crypto-phishing-losses-fall-83-to-84-million/).

### 2. What it does

For a given address Szlaban:

1. rebuilds the current ERC-20 allowances;
2. computes the **USD at risk**;
3. profiles each spender (contract, EOA or EIP-7702-delegated EOA, contract age, blocklists);
4. draws a **timeline** that highlights forgotten approvals;
5. computes a **0–100 resilience score** with a published formula;
6. produces an ordered **cleanup plan**.

It never connects to a wallet, never handles keys and never sends transactions.

### 3. Method

- **Approvals** (same logic as `zgody.py`): `eth_getLogs` for `Approval` with `topic1 = owner`, with
  range chunking and endpoint failover. ERC-721 logs (4 topics) are skipped. Only the latest event per
  (token, spender) counts. The current `allowance()` comes from `eth_call` and zero allowances are dropped.
  Metadata comes from `symbol()`, `decimals()`, `eth_getCode` and the tx sender. Tokens without
  symbol/decimals and foreign-tx approvals to known routers are hidden by default, as in the CLI.
  Risk is HIGH if the allowance is ≥ 2²⁵⁵, LOW if it is limited and the spender is on the known list,
  and MEDIUM otherwise.
- **USD at risk** = `min(allowance, balanceOf(owner)) / 10^decimals × price`. The price comes from
  DefiLlama, and prices with confidence < 0.9 are ignored. The wallet total counts each token once:
  `Σ_token max_spender(usd)`. It is an upper bound on what can be taken from the *current* balance.
- **Spender forensics**: an empty code means EOA. A code of `0xef0100‖address` means an EIP-7702
  delegated EOA. Contract age is found by binary search for the lowest block with non-empty
  `eth_getCode` on archive nodes, which can be approximate for CREATE2 redeploys. Blocklists are matched
  as described in section 5; they are historical, so no match does not mean safe.
- **Forgotten** = unlimited and unchanged for ≥ 365 days. Szlaban does not analyse `transferFrom`
  usage.
- **Resilience score** = `max(0, 100 − Σ deductions)`:

  | Rule | Per item | Cap |
  |---|---|---|
  | spender on a public blocklist | −25 | −50 |
  | spender is an EOA (incl. EIP-7702) | −10 | −20 |
  | unlimited allowance | −4 | −24 |
  | forgotten unlimited allowance | −2 | −10 |
  | approval set by someone else's tx | −3 | −9 |
  | total USD at risk ≥$10/100/1k/10k/100k | −5/−10/−15/−20/−25 | −25 |

  Grades: 80–100 *Fortress*, 60–79 *Solid*, 40–59 *Needs cleanup*, 0–39 *Alarm*. The weights are the
  author's design choice, and every deduction is shown in the UI.
- **Cleanup plan** order: blocklisted spenders first, then USD at risk (descending), then unlimited
  approvals to EOAs, then unlimited approvals to unknown contracts, then any unlimited approval, then
  the oldest.

### 4. Prior art (as of 10 Nov 2026)

Mature tools already exist, and Szlaban does not claim to be first.
[Revoke.cash](https://revoke.cash/blog/2026/update-q3) offers multichain approval management,
"Value at Risk" (since Sep 2023) and paid auto-revoking.
[De.Fi Shield](https://docs.de.fi/security-toolkit/shield) offers a 0–100 "Wallet Health Score".
Rabby Wallet has an Approvals page, and Etherscan has a Token Approval Checker.

Verifiable differences:

- the code contains no transaction or wallet code at all;
- the score formula is fully published (we did not find full formulas in the public materials of
  De.Fi or Revoke.cash);
- contract age is found via `eth_getCode` binary search, and EIP-7702 delegated EOAs are flagged;
- the per-token de-duplicated USD total uses a documented method;
- the timeline has a "forgotten" zone;
- it is a single self-hostable container using only the Python standard library, with no API keys
  and no database;
- AGPL-3.0, Polish UI.

Szlaban also covers **less** than those tools: Ethereum mainnet only, ERC-20 only, no NFTs, no Permit2
sub-allowances, no simulation and no monitoring.

### 5. Data sources

| Data | Source |
|---|---|
| chain data | public JSON-RPC: Tenderly, MEV Blocker, Flashbots, PublicNode, dRPC |
| prices | [DefiLlama](https://defillama.com/docs/api) |
| blocklists | [ScamSniffer](https://github.com/scamsniffer/scam-database) (GPL-3.0, not updated since Feb 2024); [Forta labelled-datasets](https://github.com/forta-network/labelled-datasets) (MIT, Jan 2023); [MEW darklist](https://github.com/MyEtherWallet/ethereum-lists) (MIT, 2020) |

### 6. Security and threat model

The app is read-only and accepts no keys, seed phrases or signatures. Controls:

- **Untrusted chain strings**: rendered via `textContent`, with a strict CSP (`default-src 'self'`) and
  no inline scripts.
- **Server abuse**: rate limiting per IP (10 per 10 min), at most 4 concurrent scans, a 10-min cache,
  a 600 s job timeout, a 2 KB POST limit and a 30 s socket timeout.
- **Static files**: served from a whitelist only.
- **RPC**: multi-endpoint failover.
- **Prices**: a confidence threshold.
- **Framing**: `X-Frame-Options: DENY`.
- **Container**: runs as non-root UID 10001.
- **Phishing**: Szlaban never asks you to connect a wallet, so any site that does is not Szlaban.

### 7. Privacy

- No accounts, cookies, analytics or third-party scripts.
- Scan results are kept **in RAM only** for the cache TTL (10 min). There is no database.
- Logs contain **no wallet addresses, IPs or query strings**. IPs are kept in memory only for the
  rate-limit window.
- The scanned address is necessarily disclosed to the RPC providers and, through token lists, to DefiLlama.
- A `/r/<address>` link contains the address.

### 8. Limitations

- Mainnet ERC-20 only. No NFTs, no Permit2 sub-allowances and no ENS. Unused off-chain signatures are
  not on chain, so they cannot be seen.
- Relies on free endpoints that have limits.
- The blocklists are historical, and "known" does not mean audited.
- Contract age is approximate for CREATE2 redeploys.
- The score is a heuristic, not a probability of loss.

### 9. Licence

**AGPL-3.0-only.** Anyone who runs a **modified** version as a network service must offer its source to
its users (AGPL §13). Szlaban serves its own source at `/source.tar.gz`. The name and logo are not
licensed to forks (see `TRADEMARK.md`). **Commercial or closed-source licensing** is available from the
author on request.

### 10. Legal disclaimer

For **information only**. This is not financial, investment, legal or security advice. It is provided
**"as is", without warranty of any kind** (AGPL-3.0 §§15–16). The author is not liable for losses
arising from use or non-use of the tool, from incorrect third-party data, or from decisions based on its
output. Szlaban **never transacts** and has no access to user funds.
