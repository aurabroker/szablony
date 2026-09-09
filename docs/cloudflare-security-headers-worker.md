# Cloudflare Worker `security-headers` — analiza i proponowane działania

- **Status:** analiza wejściowa, **nic nie wdrożone**, czekam na instrukcje.
- **Data:** 2026-09-09
- **Repo:** `aurabroker/szablony`, branch `claude/clever-shannon-30pmsy`
- **Źródło:** kod Workera wklejony w rozmowie (Załącznik A) oraz pliki
  `promptyclaudecode.md` i `CLAUDE.md` przesłane do oceny (Załącznik B).
  W repo nie ma żadnego z nich.

Ten plik jest dokumentem roboczym — dopisujemy do niego decyzje i kolejne kroki.

---

## 1. Co ten Worker robi

Jeden Worker wpięty w `routes` kilku hostów, działa jako proxy przed originem:

1. Przechwytuje `POST /__csp-report` i zapisuje naruszenia do Analytics Engine (`csp_reports`), zwraca 204.
2. Dla pozostałych żądań czyta politykę z KV (`policy:<hostname>`), scala ją z `DEFAULT_POLICY`.
3. Generuje nonce (16 losowych bajtów, base64) i wstawia go do żądania jako `x-csp-nonce` (kasując wartość przysłaną przez klienta).
4. Pobiera odpowiedź z originu, usuwa nagłówki zdradzające stack, dokłada zestaw nagłówków bezpieczeństwa. HSTS/`nosniff`/`Referrer-Policy`/CORP na wszystkim, CSP/`Permissions-Policy`/COOP tylko na `text/html`.
5. W trybie `auto` lub `placeholder` przepuszcza HTML przez `HTMLRewriter`, żeby dokleić nonce do `<script>`, `<style>`, `<link rel=stylesheet>`.

Model polityki: default w kodzie, nadpisania per host w KV, więc zmiana polityki nie wymaga deployu.

## 2. Ocena ogólna

Architektura jest dobra i to jest właściwy sposób robienia tego na Cloudflare: jedno miejsce, polityka danych a nie kodu, start w `report-only`, `strict-dynamic` zamiast utrzymywania listy domen, HSTS bez `preload` do czasu audytu. Rozsądne domyślne: `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `preload: false`.

Problemy są w dwóch obszarach: **odporność na awarię** (jeden wyjątek kładzie wszystkie hosty) oraz **tryb `nonce: 'auto'`**, który w typowym scenariuszu zabiera CSP całą wartość ochronną. Reszta to dopracowanie.

---

## 3. Ustalenia

### P0 — blokery, do zrobienia przed jakimkolwiek `enforce`

**B1. Tryb `nonce: 'auto'` unieważnia ochronę przed XSS**

`HTMLRewriter` dokleja nonce do *każdego* elementu `<script>` w odpowiedzi originu. Jeśli origin gdziekolwiek odbija dane użytkownika w HTML (a to jest dokładnie ta klasa błędów, przed którą CSP ma chronić), wstrzyknięty `<script>` również dostanie ważny nonce. CSP przepuści go, bo nie odróżnia skryptu aplikacji od skryptu atakującego — decyduje wyłącznie obecność atrybutu.

Efekt: `enforce` + `auto` daje poczucie ochrony przy realnej ochronie bliskiej zeru (zostaje tylko `object-src`, `base-uri`, `frame-ancestors`).

Propozycja: `auto` traktować jako tryb wyłącznie diagnostyczny (`report-only`, do inwentaryzacji skryptów). Do `enforce` dopuszczać tylko `placeholder` (szablon świadomie oznacza swoje skrypty) albo `origin` (nonce generuje aplikacja). Twardo blokować w kodzie kombinację `mode: 'enforce'` + `nonce: 'auto'` — logować i degradować do `report-only`.

**B2. Brak globalnego `try/catch` — dowolny wyjątek kładzie wszystkie hosty**

`fetch()` nie ma zabezpieczenia. Każdy nieprzewidziany błąd (zły wpis w KV, nietypowa odpowiedź originu, błąd `HTMLRewriter`) kończy się błędem 1101 zamiast strony. Worker siedzi na ścieżce krytycznej kilku aplikacji naraz.

Propozycja: cały handler w `try/catch`, w `catch` zwracamy `fetch(request)` bez modyfikacji (fail-open na nagłówkach, nigdy na dostępności) plus wpis do Analytics Engine z powodem awarii.

**B3. Zła wartość w KV wywala Workera**

`mergePolicy` przypisuje `result[key] = value` dla wartości, które nie są zwykłym obiektem. Wpis `{"csp": null}` daje `policy.csp = null`, a następna linia czyta `policy.csp.enabled` → `TypeError` → 500 na całym hoście. Podobnie `"scriptSrc": "https://x.pl"` (string zamiast tablicy) rozjedzie się na znaki w spreadzie i wyprodukuje bezsensowną dyrektywę.

Propozycja: `sanitizePolicy()` po odczycie z KV — wymuszenie typów (tablice zostają tablicami, enumy `mode`/`nonce` walidowane do znanych wartości, liczby do liczb), odrzucanie nieznanych kluczy, przy błędzie walidacji cofnięcie do `DEFAULT_POLICY` i zapis incydentu. Do tego zestaw testów na złośliwe/zepsute wpisy KV.

**B4. Tryb `nonce: 'origin'` rozjedzie się z cache**

W trybie `origin` nonce trafia do HTML renderowanego przez aplikację, a nagłówek CSP generuje Worker przy każdym żądaniu. Jeśli ten HTML zostanie gdziekolwiek zbuforowany (cache Cloudflare, cache przeglądarki, cache po stronie aplikacji), body niesie nonce ze starego żądania, a nagłówek nowy. Wszystkie skrypty na stronie zostają zablokowane. `x-csp-nonce` nie wchodzi domyślnie do klucza cache, więc trafienie w cache jest realne.

Propozycja: przy `nonce: 'origin'` Worker wymusza `Cache-Control: private, no-store` na dokumentach HTML albo dokłada `Vary: x-csp-nonce`, i zapisujemy w dokumentacji, że ten tryb wyklucza cache HTML.

### P1 — ważne, przed produkcją

**W1. `Cross-Origin-Resource-Policy: same-origin` na *wszystkich* odpowiedziach**

CORP leci również na obrazki, fonty i pliki JS. Jeżeli którykolwiek z tych hostów serwuje zasoby używane z innej domeny (font dla drugiej aplikacji, logo w mailingu, widget osadzany u klienta), przeglądarka je zablokuje. To najbardziej prawdopodobne źródło cichej awarii po wdrożeniu.

Propozycja: domyślnie `same-origin` dla HTML, `cross-origin` dla zasobów statycznych, z możliwością nadpisania per host i per prefiks ścieżki w KV.

**W2. Publiczny endpoint raportów bez żadnych limitów**

`/__csp-report` przyjmuje dowolny POST od kogokolwiek i zapisuje punkt danych. Da się zaśmiecić dataset i wygenerować koszt. `request.json()` bez limitu rozmiaru to dodatkowo ryzyko CPU.

Propozycja: sprawdzenie `content-type` (`application/csp-report`, `application/reports+json`), limit `content-length` (np. 64 KB), limit liczby wpisów w jednej paczce (np. 50), próbkowanie (`sampleRate` w polityce, np. 10% przy dużym ruchu), odrzucanie raportów, których `documentURL` nie pasuje do hosta. Zapis przez `ctx.waitUntil`.

**W3. Funkcje Cloudflare wstrzykują skrypty *po* Workerze**

Rocket Loader, Email Address Obfuscation, Bot Fight Mode i Mirage dokładają własne skrypty do HTML po wyjściu z Workera, więc nie dostaną nonce'a. Przy `enforce` zostaną zablokowane, a w `report-only` zaleją dataset fałszywymi naruszeniami.

Propozycja: audyt ustawień Speed/Scrape Shield na zonie, wyłączenie Rocket Loadera i obfuskacji maili na hostach objętych Workerem, albo dopisanie oficjalnych hashy Cloudflare do `scriptSrc`. Do sprawdzenia również Response Header Transform Rules — wykonują się po Workerze i mogą nadpisać nasze nagłówki.

**W4. Brak wyłącznika awaryjnego**

Nie ma sposobu na szybkie wyłączenie polityki bez deployu. `POLICY_CACHE_TTL = 300` plus propagacja KV to do kilku minut opóźnienia — na incydencie to dużo.

Propozycja: klucz `policy:__global` z flagą `disabled` czytany obok polityki hosta oraz `csp.enabled: false` jako szybka ścieżka. Rozważyć skrócenie `cacheTtl` do 60 s (to minimum KV) w zamian za więcej odczytów.

**W5. `HTMLRewriter` zakłada UTF-8**

`HTMLRewriter` obsługuje wyłącznie dokumenty w UTF-8. Strona w `windows-1250` czy `iso-8859-2` (a to realne przy starszych aplikacjach i polskich znakach) zostanie przepuszczona przez rewriter i rozsypie się znakowo.

Propozycja: przepisywać tylko gdy `content-type` nie deklaruje innego charsetu niż UTF-8. Przy braku deklaracji — decyzja per host w KV.

**W6. Odpowiedzi częściowe i puste**

Odpowiedź 206 (Range) z `content-type: text/html` trafi do rewritera jako fragment HTML i zostanie uszkodzona. Dla 204/304 kasujemy `content-length` bez potrzeby.

Propozycja: przepisywać wyłącznie dla statusu 200 z niepustym body.

**W7. `Permissions-Policy` — brak normalizacji `self`**

`buildPermissionsPolicy` cytuje wszystko poza dosłownym `self`. Wpis `"'self'"` (naturalna pomyłka, bo tak zapisuje się to w CSP i tak wygląda w przykładach obok) wyprodukuje `payment=("'self'")` — nagłówek niepoprawny, cała lista dla tej funkcji odpada.

Propozycja: normalizacja `'self'` → `self`, walidacja pozostałych wpisów jako origin URL, pominięcie i zalogowanie tego, co nie przechodzi.

**W8. Usunięcie `X-Frame-Options` bez zamiennika dla starych klientów**

`frame-ancestors` pokrywa nowoczesne przeglądarki, ale nagłówek kasujemy dla wszystkich. Koszt utrzymania XFO jest zerowy.

Propozycja: gdy `frameAncestors` to `'none'` → `X-Frame-Options: DENY`, gdy tylko `'self'` → `SAMEORIGIN`, przy liście domen — kasować (XFO nie ma odpowiednika).

### P2 — drobne i usprawnienia

- **D1.** `ctx` nieużywany; zapisy do Analytics Engine powinny iść przez `ctx.waitUntil`.
- **D2.** Brak wsparcia dla dwóch nagłówków naraz. Docelowy tryb rolloutu to `enforce` luźnej polityki + `report-only` ostrzejszej. Warto dodać `csp.reportOnlyExtra`.
- **D3.** `connect-src 'self'` i `default-src 'self'` zablokują beacony analityczne, Sentry i webhooki — to jest oczekiwane, ale trzeba to policzyć na etapie `report-only`, zanim ktokolwiek włączy `enforce`.
- **D4.** Brak `worker-src`/`manifest-src`/`media-src`. Pokrywa je `default-src 'self'`, ale aplikacje używające Web Workerów z `blob:` polegną — częsty przypadek.
- **D5.** `base-uri 'none'` zepsuje strony używające `<base href>`. Do sprawdzenia w szablonach.
- **D6.** `'unsafe-eval'` nieobecne — GTM z custom templates, część bibliotek wykresów i n8n go potrzebują. Per host w KV, świadomie.
- **D7.** `strict-dynamic` nie działa ze skryptami wstawianymi przez `document.write` — starsze integracje reklamowe/analityczne to lubią.
- **D8.** Brak wersjonowania polityki. Warto dodać `policyVersion` do wpisu KV i wypuszczać go nagłówkiem debugowym (tylko poza produkcją) — inaczej diagnostyka „która polityka faktycznie zadziałała" jest zgadywanką.
- **D9.** `Reporting-Endpoints` ustawiany tylko dla HTML — poprawnie, ale wtedy `report-to` nie ma zastosowania do naruszeń na zasobach niebędących dokumentem. Do świadomego zaakceptowania.
- **D10.** Brak `Origin-Agent-Cluster: ?1` i `X-Permitted-Cross-Domain-Policies: none`. Tanie, opcjonalne.
- **D11.** Nie dodawać `X-XSS-Protection` — nagłówek jest wycofany i bywa szkodliwy. Odnotowane, żeby nikt go nie dopisał „dla kompletu".
- **D12.** Do zweryfikowania w praktyce: zachowanie `content-encoding` przy `HTMLRewriter` oraz to, że `fetch(upstream)` do hosta objętego tą samą trasą nie zapętla Workera.

---

## 4. Proponowane działania — kolejność

**Etap A — odporność (zanim cokolwiek pojedzie na ruch)**
1. Globalny `try/catch` z fail-open na `fetch(request)` (B2).
2. `sanitizePolicy()` + walidacja wpisów KV (B3).
3. Blokada kombinacji `enforce` + `auto`, degradacja do `report-only` (B1).
4. Wyłącznik `policy:__global` (W4).

**Etap B — poprawność nagłówków**
5. CORP rozdzielone HTML vs. zasoby (W1).
6. Normalizacja `Permissions-Policy` (W7).
7. `X-Frame-Options` wyliczany z `frame-ancestors` (W8).
8. Warunki przepisywania: tylko 200, tylko UTF-8, tylko HTML (W5, W6).

**Etap C — endpoint raportów**
9. Walidacja `content-type`, limity rozmiaru i liczby wpisów, próbkowanie, `waitUntil` (W2).

**Etap D — testy i CI**
10. `vitest` + `@cloudflare/vitest-pool-workers`: testy jednostkowe `buildCsp`, `buildPermissionsPolicy`, `mergePolicy`, `sanitizePolicy`; testy integracyjne przez `SELF.fetch` z atrapą originu; fixture'y zepsutych polityk KV.
11. GitHub Actions: testy + `wrangler deploy --dry-run` na każdym PR.

**Etap E — wdrożenie**
12. Audyt zony (Rocket Loader, obfuskacja maili, Transform Rules) — W3.
13. Rollout wg punktu 5.

## 5. Plan wdrożenia

1. **Jeden host, najmniejszy ruch, `report-only`.** Bez `enforce`, bez wyjątków. 7–14 dni zbierania.
2. **Analiza naruszeń** zapytaniem z komentarza w kodzie. Rozdzielić: własny kod, integracje zewnętrzne, śmieci od rozszerzeń przeglądarki i skryptów Cloudflare (te ostatnie odfiltrować, nie dopisywać do allowlisty).
3. **Domknięcie list** per host w KV: `connectSrc`, `frameSrc`, `imgSrc`, `formAction`.
4. **Zmiana trybu nonce na `placeholder`** tam, gdzie kontrolujemy szablony. `auto` nie idzie do `enforce` (B1).
5. **`enforce` per host**, zaczynając od tego samego najmniejszego hosta. Równolegle `report-only` z ostrzejszą wersją, jeśli wejdzie D2.
6. **HSTS `preload` dopiero na końcu**, po inwentaryzacji wszystkich subdomen. Praktycznie nieodwracalne — usunięcie z listy trwa miesiącami.
7. Na każdym etapie: gotowa procedura wycofania (`csp.enabled: false` w KV) i osoba, która wie, że ma ją odpalić.

## 6. Sprawy do decyzji

1. **Gdzie ma mieszkać ten kod?** To repo (`aurabroker/szablony`) trzyma szablony n8n. Worker to inna klasa artefaktu. Opcje: osobne repo, katalog `workers/security-headers/` tutaj, albo tylko dokumentacja tutaj a kod gdzie indziej.
2. **Jakie to realnie hosty?** `app1/app2/sklep.example.com` to placeholdery. Bez listy prawdziwych hostów i tego, co na nich stoi (n8n? WordPress? aplikacja własna? sklep?), nie da się dobrać `nonce` ani list źródeł.
3. **Czy któryś z hostów to n8n?** Jeśli tak: interfejs n8n potrzebuje `'unsafe-eval'`, WebSocketów w `connect-src` (`wss:`), a Code Node i podglądy iframe mają własne wymagania. n8n dostaje wtedy osobną, luźniejszą politykę.
4. **Czy któryś host serwuje zasoby dla innych domen?** Decyduje o W1.
5. **Kto ma prawo zapisu do KV z politykami?** Wpis w KV może wyłączyć CSP albo dopuścić dowolną domenę w `frame-ancestors`. Token API do tego namespace'u powinien być osobny i wąski, a zmiany logowane.
6. **Zakres pierwszej iteracji** — całość etapów A–D, czy tylko A (odporność) i wdrożenie w `report-only`?

## 7. Log decyzji

| Data | Decyzja | Kto |
|------|---------|-----|
| 2026-09-09 | Analiza kodu Workera zapisana, wdrożenie wstrzymane do instrukcji | — |
| 2026-09-09 | Ocena pakietu promptów i `CLAUDE.md` (sekcja 8), rekomendacja: PROMPT 0 przed PROMPT 1 | — |
| 2026-09-09 | Zakres szerszego „Workera bezpieczeństwa" (sekcja 9), rekomendacja: zacząć od warstwy cron | — |

---

---

## 8. Ocena pakietu promptów i `CLAUDE.md`

Ocenione pliki: `promptyclaudecode.md` (4 prompty wdrożeniowe) oraz `CLAUDE.md`
(kontekst projektu dla agenta). Snapshot obu w Załączniku B.

### 8.1 Werdykt

Warsztatowo to jest bardzo dobry materiał: podział na etapy rozłożone w czasie,
człowiek w pętli przed każdą nieodwracalną operacją, zasady sformułowane
negatywnie („NIE ustawiaj", „NIE dodawaj"), rollback pokazany **przed** ryzykowną
zmianą, osobna lista rzeczy, których w ogóle nie zleca się agentowi. Tego się
zwykle w takich pakietach nie znajduje.

Problem jest jeden i systemowy: **cały proces stoi na założeniu, że tryb
`report-only` jest bezpieczny, a to założenie jest fałszywe dla tego Workera.**
Do tego dochodzi zakaz naprawiania kodu, który ma znane błędy P0 z sekcji 3.
W obecnej formie PROMPT 1 wdraża na produkcję kod, którego agent nie może
poprawić, i robi to w trybie, który mimo nazwy zmienia zachowanie przeglądarki
od pierwszej sekundy.

Ocena: dobra robota procesowa, do użycia po naprawie czterech rzeczy krytycznych.

### 8.2 Co jest dobre i zostaje bez zmian

- Rozbicie na 4 prompty zamiast jednego wielkiego. Każdy ma jeden cel.
- „Zasady bezwzględne" w PROMPT 1 i „Zasady, których nie łamiemy" w `CLAUDE.md`.
- Wymóg pokazania diffa i czekania na potwierdzenie przed `wrangler deploy`.
- PROMPT 3 punkt 3: komenda rollbacku wypisana **zanim** cokolwiek się przełączy.
- PROMPT 2: podział naruszeń na SZUM / DO POLITYKI / DO POPRAWKI W KODZIE oraz
  zakaz dopisywania domen bez potwierdzenia człowieka. To jest sedno tej pracy.
- PROMPT 2: polecenie oznaczania nierozpoznanych domen jako podejrzanych.
- Sekcja „Czego nie zlecać agentowi" — logowanie, `preload`, decyzja o domenach.
- Rozgałęzienie Workers Paid / Free dla Analytics Engine.
- Świadomość konfliktu frameworkowych nonce'ów z trybem `auto` (Faza 4).
- `CLAUDE.md`: mapowanie `blob1..blob6`, tabela stanu wdrożenia, znane pułapki.

### 8.3 Błędy krytyczne

**K1. „W trybie obserwacji nic się nie zepsuje" — to nieprawda.**

PROMPT 1 deklaruje: „Na produkcji nic nie może zostać zablokowane". Tryb
`report-only` dotyczy **wyłącznie CSP**. Pozostałe nagłówki Worker ustawia
w formie egzekwowanej od pierwszego żądania:

| Nagłówek | Co realnie robi w dniu wdrożenia |
|---|---|
| `Cross-Origin-Opener-Policy: same-origin` | zrywa `window.opener`, psuje logowanie OAuth i płatności w popupie |
| `Cross-Origin-Resource-Policy: same-origin` | blokuje użycie naszych fontów/obrazków/JS na innych domenach |
| `Permissions-Policy` | wyłącza kamerę, mikrofon, geolokalizację i `payment` (Stripe!) |
| `Strict-Transport-Security` | 2 lata + `includeSubDomains`, zapisuje się w przeglądarce natychmiast |
| `X-Content-Type-Options: nosniff` | psuje zasoby serwowane z błędnym `content-type` |

Konsekwencja: PROMPT 1 nie ma ani jednego zadania weryfikującego te nagłówki
w praktyce. Faza 5 sprawdza tylko, czy nagłówki *są*, a nie czy aplikacja nadal
działa. Pilotaż na „najmniej krytycznym" hoście tego nie wyłapie, jeśli
krytyczna jest inna aplikacja korzystająca z jego zasobów.

**K2. Faza obserwacji obniża bezpieczeństwo, zamiast je podnosić.**

Worker bezwarunkowo kasuje `X-Frame-Options` (bo „zastępuje je
`frame-ancestors`"), ale w `report-only` `frame-ancestors` **nie jest
egzekwowane**. Przez całe 7–14 dni obserwacji host pilotażowy nie ma ani XFO,
ani działającego `frame-ancestors` — czyli traci ochronę przed clickjackingiem,
którą miał wcześniej. Żaden z promptów tego nie zauważa.

**K3. `auto` jako domyślny plus PROMPT 3 to prosta droga do CSP bez wartości.**

`CLAUDE.md` opisuje `auto` jako tryb domyślny („aplikacja niezmieniona"),
a PROMPT 3 przełącza host na `enforce` bez wymogu zmiany trybu nonce'a. To jest
dokładnie scenariusz B1 z sekcji 3: nonce doklejany do każdego skryptu, więc
także do wstrzykniętego. Gorzej: w trybie `auto` raporty **będą czyste**,
bo wszystko dostaje ważny nonce. PROMPT 3 czyta czyste raporty jako zielone
światło, choć są one wyłącznie skutkiem tego, że polityka nic nie sprawdza.

Warunek z PROMPT 3 („jeśli cokolwiek poza szumem, zatrzymaj się") w trybie
`auto` jest więc spełniony zawsze, niezależnie od stanu aplikacji.

**K4. Zakaz zmiany kodu przy kodzie z otwartymi błędami P0.**

PROMPT 1 zasada 5 i `CLAUDE.md` zasada 6 zabraniają agentowi ruszać logiki.
Sama zasada jest słuszna, ale wchodzi w życie na kodzie, w którym brakuje
globalnego `try/catch` (B2) i walidacji wpisów KV (B3). Efekt: świadomie
stawiamy na ścieżce krytycznej kilku aplikacji komponent, o którym wiemy,
że pojedynczy zły wpis w KV zamienia w błąd 1101, i jednocześnie zakazujemy
jego naprawy.

Rozwiązanie: **PROMPT 0** przed PROMPT 1 (punkt 8.6). Zasada 5 zaczyna
obowiązywać po utwardzeniu, nie przed.

**K5. Udokumentowany rollback kasuje politykę hosta.**

Komenda z `CLAUDE.md`:

```bash
npx wrangler kv key put --binding SECURITY_POLICIES "policy:HOST" \
  '{"csp":{"mode":"report-only"}}' --remote
```

`mergePolicy` scala tylko jeden poziom, więc ten zapis **podmienia cały obiekt
`csp`**. Znikają `connectSrc`, `frameSrc`, `formAction`, `imgSrc` wypracowane
w PROMPT 2, a `nonce` wraca na domyślne `auto` — również na hoście, który
działał w trybie `origin` (Next.js). W `report-only` nie jest to natychmiastowa
awaria, ale traci się konfigurację, zmienia tryb nonce'a pod spodem i zalewa
dataset raportami z polityki domyślnej. Ten sam kształt komendy w PROMPT 3
punkt 2 („nadpisujesz tylko tryb") jest z tym sprzeczny — przy płytkim merge'u
nie da się nadpisać samego trybu.

Poprawnie: przed przełączeniem zrzucić aktualny JSON do pliku i rollbackiem
przywracać **cały** ten plik. Do tego jedno zdanie o czasie propagacji:
`cacheTtl` 300 s plus propagacja KV, więc rollback działa do kilku minut, a nie
natychmiast. Prawdziwe wyjście awaryjne to usunięcie trasy Workera, nie KV.

### 8.4 Błędy w konkretnych komendach i zapytaniach

- **M1.** Zapytanie SQL w `CLAUDE.md` nie filtruje po hoście, mimo że `blob1`
  to host. Przy dwóch i więcej hostach PROMPT 2 analizuje wymieszane dane.
  Dodać `WHERE blob1 = 'HOST'`.
- **M2.** `count() AS ile` zaniża wyniki. Analytics Engine przy większym
  wolumenie próbkuje; poprawnie `sum(_sample_interval) AS ile`. Inaczej
  „mało wystąpień" może znaczyć „bardzo dużo wystąpień, mocno spróbkowanych".
- **M3.** W mapowaniu pól brakuje `index1` (Worker zapisuje tam dyrektywę).
- **M4.** PROMPT 4 ma odwróconą kolejność: zadanie 1 dopisuje host do `routes`,
  zadanie 2 tworzy wpis w KV. Między jednym a drugim host jedzie na polityce
  domyślnej, czyli bez wyjątków dla Stripe'a i z `connect-src 'self'`.
  Najpierw KV, potem trasa.
- **M5.** Faza 4 (test lokalny) nie odtworzy sytuacji produkcyjnej: w
  `wrangler dev` `url.hostname` to `localhost`, więc Worker szuka klucza
  `policy:localhost`, `fetch(upstream)` idzie do nieistniejącego originu,
  a HSTS nie wyjdzie, bo protokół to `http:`. Potrzebny `--remote` albo atrapa
  originu, plus jawna lista nagłówków, których lokalnie **nie** będzie.
- **M6.** Faza 2 dla planu Free każe podmienić `writeDataPoint` na `console.log`,
  co łamie zasadę 5 z tego samego promptu. Rozwiązać flagą w konfiguracji
  (`reporter: 'analytics' | 'log'`), a nie edycją logiki.
- **M7.** PROMPT 2 nie obsługuje najczęstszego wyniku pierwszego podejścia:
  **zero raportów**. To prawie zawsze znaczy, że pipeline nie działa
  (zła trasa, `Reporting-Endpoints` nie dociera, endpoint przykryty przez
  aplikację), a nie że aplikacja jest czysta. Potrzebny test syntetyczny:
  celowe naruszenie na stronie testowej i potwierdzenie, że wpis dotarł
  do datasetu, zanim ktokolwiek zinterpretuje ciszę jako sukces.
- **M8.** PROMPT 2 prosi o wklejenie tokenu API do rozmowy. Lepiej zmienna
  środowiskowa, token wąski (`Account Analytics: Read`), do skasowania po etapie.
- **M9.** `CLAUDE.md` przewiduje wpisanie Account ID i id namespace'u KV do
  pliku w repo. Jeśli repo jest publiczne, to niepotrzebna ekspozycja — lepiej
  plik nieśledzony albo odsyłacz do menedżera haseł.

### 8.5 Braki procesowe

- **Brak testów i CI.** Deploy na produkcję po jednym `curl -sI`. Dla kodu na
  ścieżce krytycznej kilku aplikacji to za mało — patrz etap D w sekcji 4.
- **Brak alertu na błędy Workera.** Nikt nie pilnuje wskaźnika błędów; o 1101
  dowiemy się od użytkowników.
- **Brak inwentaryzacji strefy przed startem.** Rocket Loader, Email
  Obfuscation, Bot Fight Mode, Response Header Transform Rules i `_headers`
  z Pages potrafią wywrócić wynik. `CLAUDE.md` wspomina tylko o `_headers`.
- **HSTS bez schodków.** Prompty pilnują `preload`, ale `max-age` 2 lata
  z `includeSubDomains` też jest trudno odwracalny. Standard to 300 s → 1 dzień
  → 7 dni → docelowo, z weryfikacją wszystkich subdomen na każdym stopniu.
- **Brak kryterium „gotowe" i ram czasowych.** „7–14 dni" bez warunku
  wyjścia (ile ruchu, ile unikalnych naruszeń, czy pipeline potwierdzony).
- **Brak roli i osoby dyżurnej.** Kto dostaje alert i kto ma prawo odpalić
  rollback o 23:00.

### 8.6 Proponowany PROMPT 0 — utwardzenie przed wdrożeniem

Wstawiany przed obecnym PROMPT 1. Zakres pokrywa etapy A–D z sekcji 4:

1. Globalny `try/catch` z fail-open na `fetch(request)` (B2).
2. `sanitizePolicy()` i walidacja wpisów KV, z testami na zepsute wpisy (B3).
3. Twarda blokada `enforce` + `nonce: auto`, z degradacją do `report-only` (B1).
4. Rozdzielenie CORP: `same-origin` dla HTML, `cross-origin` dla zasobów (W1).
5. `X-Frame-Options` wyliczany z `frame-ancestors` zamiast bezwarunkowego
   kasowania — usuwa regresję K2 na czas obserwacji.
6. Warunki przepisywania HTML: tylko status 200, tylko UTF-8 (W5, W6).
7. Limity i próbkowanie na `/__csp-report` (W2).
8. Wyłącznik globalny `policy:__global` (W4).
9. `vitest` + `@cloudflare/vitest-pool-workers` i GitHub Actions.

Dopiero po tym PROMPT 1, a zasada „nie zmieniaj logiki" wchodzi w życie
od tego momentu.

### 8.7 Poprawki do `CLAUDE.md`

Do dopisania w „Zasady, których nie łamiemy":

> 8. **`enforce` nigdy razem z `nonce: auto`.** W trybie `auto` Worker nadaje
>    nonce każdemu skryptowi w odpowiedzi, także wstrzykniętemu. `auto` służy
>    wyłącznie do inwentaryzacji w `report-only`.
> 9. **`report-only` dotyczy wyłącznie CSP.** COOP, CORP, `Permissions-Policy`,
>    HSTS i `nosniff` działają w pełni od pierwszego żądania. Każdy nowy host
>    wymaga sprawdzenia logowania, płatności i uprawnień urządzeń.
> 10. **Rollback to przywrócenie pełnego JSON-a z kopii**, nie fragmentu.
>     Merge jest płytki, fragment kasuje resztę polityki.
> 11. **HSTS wprowadzamy schodkowo.** Docelowy `max-age` dopiero po
>     potwierdzeniu, że wszystkie subdomeny działają po https.

Do zmiany w tabeli trybów nonce'a: `auto` opisany jako **tryb diagnostyczny**,
nie domyślny do produkcji; `placeholder` i `origin` jako jedyne dopuszczalne
przy `enforce`.

Do tabeli „Stan wdrożenia" dołożyć kolumny: `HSTS max-age`, `CORP`, `COOP`,
`data ostatniego przeglądu raportów`.

Do „Przydatne komendy" dołożyć zrzut polityki przed zmianą:

```bash
npx wrangler kv key get --binding SECURITY_POLICIES "policy:HOST" --remote \
  > backup-HOST-$(date +%F).json
```

### 8.8 Poprawki do promptów

- **PROMPT 1:** dodać Fazę -1 (inwentaryzacja strefy: Rocket Loader, Email
  Obfuscation, Transform Rules, Pages `_headers`, inne Workery na trasie).
  W Fazie 5 dopisać weryfikację funkcjonalną, nie tylko obecność nagłówków:
  logowanie, popup OAuth, płatność, upload, wszystko co używa uprawnień
  urządzeń. Rozwiązać sprzeczność M6. W Fazie 4 uwzględnić M5.
- **PROMPT 2:** filtr po hoście i `sum(_sample_interval)` (M1, M2), obsługa
  wyniku „zero raportów" wraz z testem syntetycznym (M7), token przez zmienną
  środowiskową (M8).
- **PROMPT 3:** dodać warunek wstępny „`nonce` tego hosta nie jest `auto`" —
  bez tego cały etap jest pozorny (K3). Zrzut polityki do pliku przed zmianą
  i rollback z pliku (K5). Dopisać oczekiwany czas propagacji rollbacku
  i procedurę awaryjną przez usunięcie trasy.
- **PROMPT 4:** odwrócić kolejność (najpierw KV, potem `routes`) — M4.
  Dopisać pytanie o to, czy host serwuje zasoby dla innych domen (CORP).

### 8.9 Do decyzji

Do listy z sekcji 6 dochodzą trzy pytania:

7. Czy przed PROMPT 1 robimy PROMPT 0 (utwardzenie), czy świadomie wdrażamy
   kod w obecnej postaci i przyjmujemy ryzyko z K4?
8. Czy host pilotażowy serwuje jakiekolwiek zasoby dla innych domen i czy ma
   logowanie przez popup? To decyduje, czy K1 dotyczy nas w praktyce.
9. Czy `CLAUDE.md` z Account ID trafia do repozytorium publicznego?


---

## 9. Czy da się zrobić Workera pilnującego bezpieczeństwa stron i aplikacji?

### 9.1 Krótka odpowiedź

Da się, ale nie jako jeden Worker. „Pilnowanie bezpieczeństwa" to trzy różne
zadania o różnym profilu ryzyka i tylko pierwsze z nich należy do kodu
stojącego na ścieżce żądania:

1. **Prewencja w locie** — nagłówki, CSP, flagi ciasteczek, blokada wrażliwych
   ścieżek. Musi być inline, przy każdym żądaniu.
2. **Detekcja** — rozpoznawanie, że na stronie pojawiło się coś, czego nie
   powinno być. Częściowo inline (pasywnie, bez blokowania), częściowo poza
   ścieżką żądania.
3. **Dozór okresowy** — cykliczny audyt stanu wszystkich hostów i alert, gdy
   coś się rozjedzie. Zero powodu, żeby to było na ścieżce żądania.

Kluczowa zasada: **każda funkcja dołożona do Workera inline zwiększa opóźnienie
i promień rażenia awarii dla wszystkich aplikacji naraz.** Worker nagłówkowy już
dziś jest pojedynczym punktem awarii dla kilku hostów. Dokładanie do niego
skanowania, liczników i integracji to prosta droga do sytuacji, w której błąd
w module antyfraudowym kładzie sklep. Stąd podział na cienki Worker inline
i gruby Worker cron poza ruchem.

### 9.2 Co należy do Workera, a co do innych warstw

| Zadanie | Gdzie to robić | Uzasadnienie |
|---|---|---|
| Nagłówki bezpieczeństwa, CSP, nonce | **Worker inline** | jedno miejsce zamiast konfiguracji w każdym frameworku |
| Wymuszenie flag ciasteczek (`Secure`, `HttpOnly`, `SameSite`) | **Worker inline** | przepisanie `Set-Cookie` z originu, ratuje starsze aplikacje bez ich zmiany |
| Blokada wrażliwych ścieżek (`/.env`, `/.git/`, `.bak`, mapy źródeł na produkcji) | **Worker inline** | tanie, jedna lista dla wszystkich hostów |
| Blokada metod (`TRACE`, `TRACK`) | **Worker inline** | dwie linijki |
| Raporty CSP jako sygnał włamania | **Worker inline (zapis) + cron (analiza)** | zapis musi być przy żądaniu, analiza nie |
| Wykrywanie obcych skryptów w HTML | **Worker inline, pasywnie** | `HTMLRewriter` i tak przechodzi po HTML, dokładamy odczyt `src` bez blokowania |
| Kontrola integralności plików JS (dryf hashy) | **Worker cron** | pobranie i zhashowanie pliku na ścieżce żądania to zbędne opóźnienie |
| Audyt nagłówków na wszystkich hostach | **Worker cron** | z definicji cykliczny |
| Wygasanie certyfikatów, dryf DNS | **Worker cron + API Cloudflare** | dane są w API, nie w ruchu |
| Rate limiting, blokada skanerów, geoblokada | **Reguły WAF w panelu** | działają przed Workerem, nie kosztują CPU i nie da się ich zepsuć deployem |
| Boty, spam w formularzach | **Turnstile / Bot Management** | osobny produkt, nie do pisania samemu |
| Podatności w zależnościach | **CI (npm audit, Dependabot)** | to problem builda, nie ruchu |
| Sekrety w repozytorium | **GitHub secret scanning** | jw. |

Jedno zdanie o tym, czego nie budować: rate limiting i blokowanie skanerów
w kodzie Workera to klasyczny błąd. Reguły WAF działają wcześniej, są
zmienialne bez deployu i nie mogą wywalić aplikacji błędem w kodzie.

### 9.3 Proponowana architektura

```
                    ┌─ Worker inline (cienki, na trasie hostów) ─┐
przeglądarka → CF → │  nagłówki + CSP + ciasteczka + blokady      │ → origin
                    │  pasywna obserwacja HTML → Analytics Engine │
                    └────────────────────────────────────────────┘
                                        │
                                        ▼
                              Analytics Engine / KV
                                        ▲
                    ┌─ Worker cron (gruby, poza ruchem) ─────────┐
                    │  audyt hostów, hashe JS, certyfikaty, DNS  │
                    │  analiza raportów CSP, wykrywanie dryfu    │
                    └────────────────────────────────────────────┘
                                        │
                                        ▼
                            webhook → n8n → Slack / mail
```

Warstwa alertów trafia do n8n, które i tak jest w tej organizacji używane
(to repozytorium trzyma jego szablony). Worker nie powinien znać Slacka ani
skrzynki pocztowej — wysyła jeden webhook, resztą zajmuje się workflow. Dzięki
temu zmiana adresata alertu nie wymaga deployu Workera.

### 9.4 Zakres pierwszej wersji

Sensowny MVP, do zrobienia po utwardzeniu istniejącego kodu (PROMPT 0 z sekcji 8.6):

**Worker inline — dołożyć do obecnego:**

- Normalizacja `Set-Cookie`: dopisanie `Secure`, `HttpOnly` tam, gdzie brak,
  i `SameSite=Lax` jako domyślnej. Wyjątki per host w KV, bo `HttpOnly` zepsuje
  ciasteczka czytane z JavaScriptu.
- Lista ścieżek zwracających 404 zamiast trafiać do originu: `/.env`,
  `/.git/`, `/.svn/`, `/wp-config.php.bak`, `*.sql`, `*.map` na produkcji.
  Każde trafienie to wpis do Analytics Engine — sama lista prób jest sygnałem.
- Odrzucanie `TRACE` i `TRACK`.
- Pasywna obserwacja HTML w `HTMLRewriter`: zapis hostów wszystkich
  `<script src>` oraz `action` formularzy wychodzących poza domenę. Bez
  blokowania. Po tygodniu mamy listę tego, co realnie na stronach jest.

**Worker cron — nowy, uruchamiany co godzinę:**

- Dla każdego hosta: `curl` własnych nagłówków i porównanie z oczekiwaną
  polityką. Alert, gdy nagłówek zniknął albo ktoś zmienił go w panelu.
- Hash plików JS z listy krytycznej, porównanie z wartością w KV. Zmiana bez
  zapowiedzi to sygnał podmiany. To jest tania wersja tego, co robi Page Shield.
- Dni do wygaśnięcia certyfikatu, stan proxy DNS (pomarańczowa chmurka),
  obecność `security.txt`.
- Podsumowanie naruszeń CSP z ostatniej doby: nowe domeny, których wcześniej
  nie było w raportach. Nowa domena w `blockedURL` to najwcześniejszy sygnał
  wstrzyknięcia, jaki ta warstwa jest w stanie dać.
- Jeden webhook do n8n z wynikiem. Cisza, gdy wszystko się zgadza.

**Czego świadomie nie robimy w pierwszej wersji:** blokowania czegokolwiek
na podstawie detekcji. Najpierw obserwacja, potem reguły. Dokładnie ta sama
zasada, co przy CSP w trybie `report-only`.

### 9.5 Ograniczenia, o których trzeba wiedzieć zawczasu

- **Promień rażenia.** Worker inline na trasie kilku hostów to jeden punkt
  awarii dla wszystkich. Każda nowa funkcja musi mieć fail-open i test.
- **Budżet CPU.** Skanowanie treści inline'owych skryptów w `HTMLRewriter`
  kosztuje CPU przy każdym żądaniu HTML. Odczyt atrybutów jest tani, analiza
  treści już nie. Stąd hashowanie w cronie, nie inline.
- **Detekcja to nie ochrona.** Ten zestaw wykryje podmieniony skrypt i obcą
  domenę, ale nie zatrzyma ataku, który nie dotyka HTML-a: przejętego konta
  administratora, podatności w API, wycieku bazy. Tego pilnuje się gdzie indziej.
- **Fałszywe alarmy niszczą proces.** Alert, który odzywa się codziennie bez
  powodu, po tygodniu jest ignorowany. Dlatego cisza jako stan domyślny
  i próg, zanim cokolwiek zawoła.
- **Koszty.** Workers Paid, Analytics Engine, ewentualnie Durable Objects,
  jeśli kiedykolwiek dojdzie stan współdzielony. Cron Triggers działają
  także na planie darmowym.
- **Zgodność z tym, co już kupione.** Jeśli strefa jest na planie Business
  lub wyżej, Page Shield robi monitoring skryptów natywnie i lepiej. Wtedy
  własny cron ma sens tylko dla nagłówków, certyfikatów i raportów CSP.
  Do sprawdzenia przed pisaniem kodu.

### 9.6 Pytania do decyzji

Do listy z sekcji 6 i 8.9:

10. Jaki plan ma strefa? Business i wyżej zmienia rachunek build vs buy
    (Page Shield, WAF, rate limiting).
11. Ile jest hostów i czy istnieje ich aktualna lista? Bez inwentarza dozór
    okresowy nie ma czego pilnować.
12. Gdzie mają trafiać alerty i kto na nie reaguje? Bez odpowiedzi na drugą
    część nie warto budować pierwszej.
13. Czy zaczynamy od warstwy inline (rozszerzenie obecnego Workera), czy od
    crona (dozór, zero ryzyka dla ruchu produkcyjnego)? Rekomendacja: od crona,
    bo nie dotyka ruchu i od razu daje obraz stanu wszystkich hostów.


---

## 10. Zrealizowane: `workers/security-monitor`

Warstwa dozoru okresowego z sekcji 9 jest zbudowana i leży w
`workers/security-monitor/`. Nie stoi na ścieżce żądań produkcyjnych, więc jej
wdrożenie nie może wpłynąć na działanie monitorowanych stron.

Zakres n8n odpadł — organizacja go nie używa. Alerty idą jednym webhookiem
o treści zgodnej naraz ze Slackiem (`text`) i Discordem (`content`), a bez
skonfigurowanego webhooka monitor działa cicho: raport i tak leży w KV
i jest widoczny pod chronionym tokenem adresem HTTP.

### Co sprawdza

Dwanaście sond na host: nagłówki bezpieczeństwa, ochrona przed ramkowaniem,
`'strict-dynamic'` bez nonce'a, flagi ciasteczek, przekierowanie z portu 80,
wrażliwe ścieżki (`/.env`, `/.git/config`), metody z nagłówka `Allow`,
`security.txt`, kanał raportów CSP, dryf hashy plików JS, termin ważności
certyfikatu i nowe domeny w raportach CSP. Dwie ostatnie wymagają tokenu API
i bez niego po prostu się pomijają.

Trzy sondy powstały wprost z ustaleń tego dokumentu:

- `frame` wykrywa lukę K2: `frame-ancestors` w trybie report-only przy usuniętym
  `X-Frame-Options` to brak jakiejkolwiek ochrony przed clickjackingiem.
- `csp-nonce` wykrywa scenariusz B1 po stronie efektu: polityka z
  `'strict-dynamic'`, ale bez nonce'a w nagłówku, nie chroni niczego.
- `csp-pipeline` odpowiada na M7: wysyła syntetyczny raport i sprawdza, czy
  endpoint zwraca 204. Cisza w datasecie prawie zawsze znaczy zepsuty kanał,
  a nie czystą aplikację.

### Decyzje projektowe

- **Alarm tylko przy zmianie stanu.** Nowy problem, pogorszenie albo naprawa.
  Ostrzeżenie trwające tydzień nie odzywa się co godzinę. Raz na dobę idzie
  pełne podsumowanie niezależnie od zmian.
- **Budżet podżądań.** Plan darmowy daje 50 na wywołanie. Po wyczerpaniu
  budżetu pozostałe sondy dostają status `skip` widoczny w raporcie, zamiast
  cichego ucięcia przebiegu.
- **Walidacja konfiguracji.** Wpis z KV przechodzi przez `sanitizeConfig`. Zły
  cel jest pomijany z notatką w raporcie. To wniosek z ustalenia B3, gdzie
  `{"csp": null}` w KV wywracało hosta.
- **Endpoint HTTP wymaga tokenu**, porównywanego w czasie stałym, a bez sekretu
  `MONITOR_TOKEN` zwraca 503 i nie wydaje żadnych danych. Raport wymienia hosty
  i ich słabe punkty, więc nie może wisieć otwarty.
- **Podział na moduły** oddziela funkcje czyste od wejścia/wyjścia, dzięki czemu
  testy nie potrzebują wranglera ani sieci.

### Testy

32 testy uruchamiane przez `npm test`, bez `npm install` — wystarczy wbudowany
`node --test`. Jednostkowe pokrywają ocenę nagłówków, ciasteczek i walidację
konfiguracji. Integracyjne podstawiają `fetch` i KV, więc cały przebieg audytu
jest sprawdzany bez ruchu sieciowego: host zdrowy, host z odsłoniętym `.env`,
host nieosiągalny, wyczerpany budżet i wykrycie podmiany pliku JS.

`npx wrangler deploy --dry-run` przechodzi.

### Czego brakuje do wdrożenia

Same dane, nie kod: identyfikator namespace'u KV w `wrangler.jsonc`, lista
hostów w `monitor:config`, sekret `MONITOR_TOKEN` i opcjonalnie `ALERT_WEBHOOK`.
Instrukcja krok po kroku jest w `workers/security-monitor/README.md`.


## Załącznik A — snapshot kodu wejściowego (v0, niewdrożony)

```js
/**
 * Centralna warstwa nagłówków bezpieczeństwa dla wszystkich aplikacji.
 *
 * Jeden Worker wpięty w routes kilku hostów. Polityka domyślna w kodzie,
 * nadpisania per host w KV, więc zmiana polityki nie wymaga deployu.
 *
 * wrangler.toml:
 *
 *   name = "security-headers"
 *   main = "src/index.js"
 *   compatibility_date = "2026-05-01"
 *
 *   kv_namespaces = [
 *     { binding = "SECURITY_POLICIES", id = "<id-namespace'u>" }
 *   ]
 *
 *   [[analytics_engine_datasets]]
 *   binding = "CSP_REPORTS"
 *   dataset = "csp_reports"
 *
 *   routes = [
 *     { pattern = "app1.example.com/*", zone_name = "example.com" },
 *     { pattern = "app2.example.com/*", zone_name = "example.com" },
 *     { pattern = "sklep.example.com/*", zone_name = "example.com" },
 *   ]
 */

const REPORT_PATH = '/__csp-report';
const NONCE_PLACEHOLDER = '__CSP_NONCE__';
const POLICY_CACHE_TTL = 300; // sekundy, cache odczytu z KV na brzegu

/** Nagłówki zdradzające stack — usuwamy je z każdej odpowiedzi. */
const LEAKY_HEADERS = [
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
  'x-turbo-charged-by',
];

/**
 * Polityka domyślna. Per host nadpisujesz w KV tylko to, co się różni.
 *
 * csp.mode:  'report-only' | 'enforce'
 * csp.nonce: 'auto'        — Worker dokleja nonce do każdego <script>/<style>
 *            'placeholder' — Worker podmienia nonce="__CSP_NONCE__" (cache'owalne)
 *            'origin'      — Worker wysyła nonce nagłówkiem x-csp-nonce, nic nie przepisuje
 *            'off'         — CSP bez nonce'a
 */
const DEFAULT_POLICY = {
  csp: {
    enabled: true,
    mode: 'report-only',
    nonce: 'auto',
    // listy dopisywane do dyrektyw bazowych
    scriptSrc: [],
    styleSrc: [],
    connectSrc: [],
    imgSrc: [],
    fontSrc: [],
    frameSrc: [],
    formAction: [],
    frameAncestors: ["'none'"],
    // nonce w style-src łamie każdy atrybut style="" — włączaj świadomie
    nonceOnStyles: false,
    upgradeInsecureRequests: true,
  },
  hsts: {
    maxAge: 63072000, // 2 lata
    includeSubDomains: true,
    preload: false, // praktycznie nieodwracalne, włączaj dopiero po audycie subdomen
  },
  referrerPolicy: 'strict-origin-when-cross-origin',
  coop: 'same-origin',
  corp: 'same-origin',
  permissions: {
    accelerometer: [],
    autoplay: [],
    camera: [],
    'display-capture': [],
    'encrypted-media': [],
    fullscreen: ['self'],
    geolocation: [],
    gyroscope: [],
    magnetometer: [],
    microphone: [],
    midi: [],
    payment: [],
    'picture-in-picture': [],
    'publickey-credentials-get': ['self'],
    'screen-wake-lock': [],
    'sync-xhr': [],
    usb: [],
    'xr-spatial-tracking': [],
  },
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === REPORT_PATH) {
      return handleCspReport(request, env);
    }

    const policy = await loadPolicy(url.hostname, env);
    const nonce =
      policy.csp.enabled && policy.csp.nonce !== 'off' ? generateNonce() : null;

    // Kopia requestu z mutowalnymi nagłówkami. Nadpisujemy x-csp-nonce,
    // żeby klient nie mógł go podstawić z zewnątrz.
    const upstream = new Request(request);
    upstream.headers.delete('x-csp-nonce');
    if (nonce) upstream.headers.set('x-csp-nonce', nonce);

    const originResponse = await fetch(upstream);

    const contentType = (originResponse.headers.get('content-type') ?? '').toLowerCase();
    const isHtml = contentType.includes('text/html');

    const response = new Response(originResponse.body, originResponse);
    applySecurityHeaders(response.headers, { policy, nonce, isHtml, url });

    const needsRewrite =
      isHtml && nonce && (policy.csp.nonce === 'auto' || policy.csp.nonce === 'placeholder');

    if (!needsRewrite) return response;

    // HTMLRewriter zmienia długość body, więc Content-Length przestaje być prawdziwy
    response.headers.delete('content-length');
    return nonceRewriter(nonce, policy.csp.nonce).transform(response);
  },
};

/* ------------------------------------------------------------------ */
/* Polityka                                                            */
/* ------------------------------------------------------------------ */

async function loadPolicy(hostname, env) {
  let override = null;

  if (env.SECURITY_POLICIES) {
    try {
      override = await env.SECURITY_POLICIES.get(`policy:${hostname}`, {
        type: 'json',
        cacheTtl: POLICY_CACHE_TTL,
      });
    } catch {
      // awaria KV nie może wywalić strony — lecimy na domyślnej polityce
    }
  }

  return mergePolicy(DEFAULT_POLICY, override);
}

/** Płytki merge z jednym poziomem zagnieżdżenia — wystarczający dla tej struktury. */
function mergePolicy(base, override) {
  if (!override || typeof override !== 'object') return base;

  const result = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const isPlainObject = value && typeof value === 'object' && !Array.isArray(value);
    result[key] = isPlainObject ? { ...(base[key] ?? {}), ...value } : value;
  }
  return result;
}

/* ------------------------------------------------------------------ */
/* Nagłówki                                                            */
/* ------------------------------------------------------------------ */

function applySecurityHeaders(headers, { policy, nonce, isHtml, url }) {
  for (const name of LEAKY_HEADERS) headers.delete(name);

  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', policy.referrerPolicy);
  if (policy.corp) headers.set('Cross-Origin-Resource-Policy', policy.corp);

  if (url.protocol === 'https:' && policy.hsts) {
    let value = `max-age=${policy.hsts.maxAge}`;
    if (policy.hsts.includeSubDomains) value += '; includeSubDomains';
    if (policy.hsts.preload) value += '; preload';
    headers.set('Strict-Transport-Security', value);
  }

  // Reszta ma sens tylko dla dokumentów HTML. Na JSON to zmarnowane bajty.
  if (!isHtml) return;

  headers.set('Permissions-Policy', buildPermissionsPolicy(policy.permissions));
  if (policy.coop) headers.set('Cross-Origin-Opener-Policy', policy.coop);

  if (!policy.csp.enabled) return;

  const reportEndpoint = `https://${url.hostname}${REPORT_PATH}`;
  headers.set('Reporting-Endpoints', `csp="${reportEndpoint}"`);

  // Origin mógł ustawić własne CSP — nasze jest źródłem prawdy
  headers.delete('Content-Security-Policy');
  headers.delete('Content-Security-Policy-Report-Only');
  headers.delete('X-Frame-Options'); // zastępuje je frame-ancestors

  const headerName =
    policy.csp.mode === 'enforce'
      ? 'Content-Security-Policy'
      : 'Content-Security-Policy-Report-Only';

  headers.set(headerName, buildCsp(policy.csp, nonce, reportEndpoint));
}

function buildCsp(csp, nonce, reportEndpoint) {
  const nonceToken = nonce ? `'nonce-${nonce}'` : null;

  const directives = {
    'default-src': ["'self'"],

    // Klasyczna strict CSP. Nowoczesne przeglądarki widzą nonce i ignorują
    // 'unsafe-inline' oraz https:. Stare spadają na https: zamiast na nic.
    // 'strict-dynamic' pozwala zaufanemu skryptowi ładować kolejne, więc
    // GTM i analytics działają bez utrzymywania listy domen.
    'script-src': [
      nonceToken,
      "'strict-dynamic'",
      'https:',
      "'unsafe-inline'",
      ...csp.scriptSrc,
    ],

    'style-src': csp.nonceOnStyles
      ? ["'self'", nonceToken, ...csp.styleSrc]
      : ["'self'", "'unsafe-inline'", ...csp.styleSrc],

    'img-src': ["'self'", 'data:', 'blob:', 'https:', ...csp.imgSrc],
    'font-src': ["'self'", 'data:', ...csp.fontSrc],
    'connect-src': ["'self'", ...csp.connectSrc],
    'frame-src': ["'self'", ...csp.frameSrc],
    'form-action': ["'self'", ...csp.formAction],
    'frame-ancestors': csp.frameAncestors,
    'object-src': ["'none'"],
    'base-uri': ["'none'"],
    'report-to': ['csp'],
    'report-uri': [reportEndpoint], // legacy, dla starszych przeglądarek
  };

  if (csp.upgradeInsecureRequests) {
    directives['upgrade-insecure-requests'] = [];
  }

  return Object.entries(directives)
    .map(([name, values]) => {
      const cleaned = values.filter(Boolean);
      return cleaned.length ? `${name} ${cleaned.join(' ')}` : name;
    })
    .join('; ');
}

function buildPermissionsPolicy(features) {
  return Object.entries(features)
    .map(([name, allowList]) => {
      if (!allowList || allowList.length === 0) return `${name}=()`;
      const origins = allowList
        .map((origin) => (origin === 'self' ? 'self' : `"${origin}"`))
        .join(' ');
      return `${name}=(${origins})`;
    })
    .join(', ');
}

/* ------------------------------------------------------------------ */
/* Nonce                                                               */
/* ------------------------------------------------------------------ */

function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

function nonceRewriter(nonce, mode) {
  const handler =
    mode === 'placeholder'
      ? {
          element(element) {
            if (element.getAttribute('nonce') === NONCE_PLACEHOLDER) {
              element.setAttribute('nonce', nonce);
            }
          },
        }
      : {
          element(element) {
            element.setAttribute('nonce', nonce);
          },
        };

  return new HTMLRewriter()
    .on('script', handler)
    .on('style', handler)
    .on('link[rel="stylesheet"]', handler);
}

/* ------------------------------------------------------------------ */
/* Raporty CSP                                                         */
/* ------------------------------------------------------------------ */

async function handleCspReport(request, env) {
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { allow: 'POST' } });
  }

  try {
    const payload = await request.json();
    const entries = Array.isArray(payload) ? payload : [payload];

    for (const entry of entries) {
      // Reporting API v1 używa .body, stary format .csp-report
      const r = entry.body ?? entry['csp-report'] ?? entry;
      const directive = String(
        r.effectiveDirective ?? r['effective-directive'] ?? r['violated-directive'] ?? 'unknown',
      );

      env.CSP_REPORTS?.writeDataPoint({
        indexes: [directive.slice(0, 32)],
        blobs: [
          String(request.headers.get('host') ?? '').slice(0, 256),
          String(r.documentURL ?? r['document-uri'] ?? '').slice(0, 512),
          String(r.blockedURL ?? r['blocked-uri'] ?? '').slice(0, 512),
          directive,
          String(r.sourceFile ?? r['source-file'] ?? '').slice(0, 512),
          String(r.disposition ?? '').slice(0, 32),
        ],
        doubles: [Number(r.lineNumber ?? r['line-number'] ?? 0)],
      });
    }
  } catch {
    // Błędny raport nie może niczego zepsuć ani zwrócić błędu przeglądarce
  }

  return new Response(null, { status: 204 });
}

/* ------------------------------------------------------------------ */
/* Przykładowa konfiguracja w KV                                       */
/* ------------------------------------------------------------------ */
/*

Klucz: policy:sklep.example.com

{
  "csp": {
    "mode": "enforce",
    "nonce": "placeholder",
    "connectSrc": ["https://api.stripe.com", "https://*.ingest.sentry.io"],
    "frameSrc": ["https://js.stripe.com", "https://hooks.stripe.com"],
    "formAction": ["'self'", "https://checkout.stripe.com"],
    "imgSrc": ["https://*.stripe.com"]
  },
  "permissions": {
    "payment": ["self", "https://js.stripe.com"]
  }
}

Klucz: policy:panel.example.com — aplikacja osadzana w iframe klienta

{
  "csp": {
    "mode": "enforce",
    "nonce": "origin",
    "frameAncestors": ["https://klient1.pl", "https://klient2.pl"]
  },
  "coop": "unsafe-none"
}

Zapytanie o naruszenia (Analytics Engine SQL API):

  SELECT blob4 AS directive, blob3 AS blocked, count() AS hits
  FROM csp_reports
  WHERE timestamp > now() - INTERVAL '7' DAY
  GROUP BY directive, blocked
  ORDER BY hits DESC
  LIMIT 50

*/
```

---

## Załącznik B — oceniane pliki (snapshot)

### B.1 `promptyclaudecode.md`

````markdown
# Wdrożenie warstwy nagłówków bezpieczeństwa — prompty dla Claude Code

Cztery prompty do wklejenia w kolejnych momentach wdrożenia. Nie wklejaj ich
wszystkich naraz — każdy dotyczy innego etapu, rozłożonego w czasie.

**Przed pierwszym uruchomieniem:**

1. Utwórz pusty katalog i wejdź do niego w terminalu.
2. Wrzuć do niego plik `security-headers-worker.js`.
3. Wrzuć plik `CLAUDE.md`.
4. Odpal `claude` i wklej PROMPT 1.

---

## Uzupełnij to przed wklejeniem PROMPTU 1

Podmień wartości w sekcji „Kontekst" pierwszego promptu:

| Zmienna | Co wpisać | Przykład |
|---|---|---|
| `DOMENA` | wasza strefa w Cloudflare | `example.com` |
| `HOST_PILOTAZOWY` | jeden host, najlepiej testowy lub najmniej krytyczny | `test.example.com` |
| `POZOSTALE_HOSTY` | reszta aplikacji, na razie tylko do wiadomości | `app.example.com, sklep.example.com` |
| `PLAN` | `Workers Paid` albo `Free` | `Workers Paid` |
| `STACK` | na czym stoi host pilotażowy | `Next.js 15 (SSR)` |

---

# PROMPT 1 — Setup i wdrożenie w trybie obserwacji

```
Wdrażamy centralną warstwę nagłówków bezpieczeństwa na Cloudflare Workers.
Przeczytaj CLAUDE.md w katalogu — jest tam pełny kontekst projektu i zasady.

## Kontekst

DOMENA:            example.com
HOST_PILOTAZOWY:   test.example.com
POZOSTALE_HOSTY:   app.example.com, sklep.example.com
PLAN:              Workers Paid
STACK:             Next.js 15 (SSR)

## Cel tej sesji

Doprowadzić do stanu, w którym Worker działa na HOST_PILOTAZOWY wyłącznie
w trybie obserwacyjnym (nagłówek Content-Security-Policy-Report-Only) i zbiera
raporty o naruszeniach. Na produkcji nic nie może zostać zablokowane.

## Zasady bezwzględne

1. NIE ustawiaj csp.mode na "enforce". W tej sesji zostaje "report-only".
2. NIE dodawaj żadnego hosta poza HOST_PILOTAZOWY do sekcji routes.
3. NIE włączaj hsts.preload. Jest praktycznie nieodwracalne.
4. Przed każdym `wrangler deploy` pokaż mi, co dokładnie się zmieni,
   i poczekaj na moje potwierdzenie.
5. Nie modyfikuj logiki w security-headers-worker.js. Jeśli uważasz, że coś
   trzeba zmienić, powiedz mi to i uzasadnij, zamiast zmieniać samodzielnie.
6. Nie zgaduj account ID ani zone ID. Odczytaj je narzędziami albo mnie zapytaj.

## Zadania

### Faza 0 — weryfikacja środowiska
- Sprawdź wersję Node (wymagane 20+) i czy npx działa.
- Sprawdź, czy jestem zalogowany: `npx wrangler whoami`. Jeśli nie, powiedz mi,
  żebym uruchomił `npx wrangler login` — nie rób tego za mnie.
- Potwierdź, że plik security-headers-worker.js istnieje w katalogu.
  Jeśli go nie ma, zatrzymaj się i powiedz mi o tym.
- Sprawdź, czy DOMENA jest widoczna na koncie jako strefa.

### Faza 1 — projekt
- Zainicjuj projekt Workers (JavaScript, bez szablonu frameworkowego).
- Przenieś security-headers-worker.js do src/index.js. Zawartość bez zmian.
- Ustaw compatibility_date na dzisiejszą datę.

### Faza 2 — zasoby
- Utwórz namespace KV o nazwie SECURITY_POLICIES i zapisz zwrócone id.
- Jeśli PLAN to "Workers Paid": dodaj binding Analytics Engine
  CSP_REPORTS do datasetu csp_reports.
- Jeśli PLAN to "Free": Analytics Engine nie jest dostępny. Zamiast tego
  podmień w kodzie wywołanie env.CSP_REPORTS?.writeDataPoint(...) na
  console.log(JSON.stringify(...)) z tymi samymi polami i powiedz mi,
  że raporty będę oglądał przez `npx wrangler tail`.

### Faza 3 — konfiguracja
Utwórz wrangler.jsonc z:
- workers_dev ustawionym na false,
- bindingami z fazy 2,
- routes zawierającym WYŁĄCZNIE HOST_PILOTAZOWY.
Pokaż mi gotowy plik przed przejściem dalej.

### Faza 4 — test lokalny
- Uruchom `npx wrangler dev`.
- Sprawdź nagłówki odpowiedzi, np. przez curl na localhost.
- Potwierdź obecność: Content-Security-Policy-Report-Only,
  Permissions-Policy, Referrer-Policy, X-Content-Type-Options,
  Reporting-Endpoints.
- Potwierdź BRAK nagłówka Content-Security-Policy bez sufiksu Report-Only.
- Jeśli STACK to Next.js, Nuxt albo SvelteKit: sprawdź, czy framework sam nie
  wstawia własnego nonce'a. Jeśli tak, zaproponuj mi ustawienie
  csp.nonce na "origin" i wyjaśnij dlaczego.

### Faza 5 — wdrożenie
- Pokaż mi podsumowanie tego, co zostanie wdrożone.
- Po moim potwierdzeniu uruchom `npx wrangler deploy`.
- Zweryfikuj produkcję: curl -sI na HOST_PILOTAZOWY, wypisz same nagłówki
  bezpieczeństwa.
- Jeśli nagłówków nie ma, zdiagnozuj: dopasowanie trasy, proxy DNS
  (pomarańczowa chmurka), kolejność Workerów na tej strefie.

### Faza 6 — domknięcie
- Zaktualizuj sekcję "Stan wdrożenia" w CLAUDE.md: host, tryb, data.
- Dopisz do CLAUDE.md id namespace'u KV i account ID.
- Napisz mi krótkie podsumowanie: co jest wdrożone, co obserwować
  i kiedy wrócić po PROMPT 2.

Zacznij od Fazy 0 i raportuj mi wynik każdej fazy zanim przejdziesz do następnej.
```

---

# PROMPT 2 — Analiza raportów (po 7–14 dniach)

```
Przeczytaj CLAUDE.md. Wracamy do wdrożenia nagłówków bezpieczeństwa,
etap analizy raportów CSP.

## Cel
Przejrzeć zebrane naruszenia i przygotować listę decyzji: co dopisać do
polityki, co poprawić w kodzie aplikacji, co zignorować.

## Zadania

1. Pobierz raporty z ostatnich 14 dni.
   - Workers Paid: zapytanie SQL do Analytics Engine przez API. Poproś mnie
     o token API z uprawnieniem Account Analytics: Read, jeśli go nie masz.
     Grupuj po effectiveDirective i blockedURL, sortuj po liczbie wystąpień.
   - Free: poproś mnie o wklejenie outputu z `npx wrangler tail`.

2. Podziel wyniki na trzy kubełki i przedstaw jako tabelę:

   SZUM — zablokowane adresy zaczynające się od chrome-extension://,
   moz-extension://, safari-web-extension:// oraz wszystko, co ewidentnie
   pochodzi z rozszerzeń przeglądarki. Tego nie ruszamy.

   DO POLITYKI — zewnętrzne usługi, których faktycznie używamy. Przy każdej
   podaj, do której dyrektywy trafia i dlaczego. Zapytaj mnie o potwierdzenie,
   czy dana usługa jest nasza — nie zakładaj tego sam.

   DO POPRAWKI W KODZIE — głównie script-src-attr, czyli inline'owe handlery
   typu onclick="". Wypisz konkretne pliki i linie, jeśli da się je ustalić
   z pola sourceFile. Zaproponuj, jak je przepisać.

3. Dla kubełka DO POLITYKI przygotuj gotową komendę
   `npx wrangler kv key put` z docelowym JSON-em, ale JEJ NIE URUCHAMIAJ.
   Pokaż mi ją do zatwierdzenia.

4. Powiedz wprost, czy twoim zdaniem jesteśmy gotowi na tryb ostry,
   czy potrzeba jeszcze jednej rundy obserwacji. Uzasadnij.

## Zasady
- Nie przełączaj niczego na "enforce" w tej sesji.
- Nie dopisuj domen do polityki bez mojego potwierdzenia, że są nasze.
  Domena w raporcie nie oznacza, że ma tam być.
- Jeśli w raportach widać domenę, której nie rozpoznajesz, oznacz ją jako
  podejrzaną i wypisz osobno. Może to być realne wstrzyknięcie.
```

---

# PROMPT 3 — Włączenie trybu ostrego

```
Przeczytaj CLAUDE.md. Przełączamy HOST_PILOTAZOWY z trybu obserwacji
na tryb egzekwowania.

## Zadania

1. Pokaż mi aktualną politykę tego hosta z KV oraz raporty z ostatnich
   3 dni. Chcę zobaczyć, że jest czysto, zanim cokolwiek zmienimy.

2. Przygotuj komendę przełączającą csp.mode na "enforce" dla tego hosta.
   Zachowaj wszystkie pozostałe pola polityki bez zmian — nadpisujesz
   tylko tryb.

3. Zanim ją uruchomisz, wypisz mi w jednej linijce komendę ROLLBACKU,
   czyli powrotu do "report-only". Chcę ją mieć przed oczami.

4. Po moim potwierdzeniu wykonaj przełączenie.

5. Zweryfikuj: curl -sI powinien teraz zwracać Content-Security-Policy
   bez sufiksu Report-Only. Potwierdź też, że strona nadal się ładuje.

6. Zaktualizuj CLAUDE.md: tryb i data przełączenia.

## Zasady
- Jeżeli w raportach z ostatnich 3 dni jest cokolwiek poza szumem
  z rozszerzeń, zatrzymaj się i powiedz mi o tym zamiast przełączać.
- Nie dotykaj przy okazji żadnych innych hostów.
```

---

# PROMPT 4 — Dołożenie kolejnej aplikacji

```
Przeczytaj CLAUDE.md. Dokładamy kolejny host do warstwy nagłówków.

HOST: sklep.example.com
STACK: Laravel 11, front w Blade + trochę Vue
ZEWNĘTRZNE USŁUGI, których jestem świadomy: Stripe, Google Analytics

## Zadania

1. Dopisz HOST do routes w wrangler.jsonc. Nie ruszaj istniejących wpisów.
2. Utwórz dla niego wpis w KV z trybem "report-only" i wstępną listą
   wyjątków dla usług, które wymieniłem powyżej. Pokaż mi JSON
   przed zapisem.
3. Pokaż mi diff konfiguracji, poczekaj na potwierdzenie, wdróż.
4. Zweryfikuj nagłówki curlem.
5. Dopisz host do tabeli stanu w CLAUDE.md z trybem report-only
   i dzisiejszą datą.

## Zasady
- Nowy host ZAWSZE zaczyna od "report-only", nawet jeśli wygląda prosto.
- Nie kopiuj polityki z innego hosta w całości. Każda aplikacja ma
  inne zależności.
- Nie zmieniaj konfiguracji hostów już wdrożonych.
```

---

## Czego nie zlecać agentowi

Trzy rzeczy zrób sam, ręcznie:

- **Logowanie do Cloudflare.** `wrangler login` otwiera przeglądarkę i przyznaje
  dostęp do całego konta. To twoja decyzja, nie agenta.
- **Włączenie `hsts.preload`.** Trafienie na globalną listę preload jest
  praktycznie nieodwracalne i wymaga świadomego audytu wszystkich subdomen.
- **Decyzja, czy zewnętrzna domena z raportu jest wasza.** Agent nie ma jak
  tego wiedzieć, a wpisanie obcej domeny do polityki wywraca sens całej pracy.
````

### B.2 `CLAUDE.md`

````markdown
# Centralna warstwa nagłówków bezpieczeństwa

Ten projekt to jeden Cloudflare Worker wpięty przed wszystkie nasze aplikacje
webowe. Dokłada do każdej odpowiedzi nagłówki bezpieczeństwa, w szczególności
Content Security Policy z nonce'em generowanym per request.

Powód istnienia: zamiast konfigurować te nagłówki osobno w każdej aplikacji
i w każdym frameworku, mamy jedno miejsce i jedną politykę.

## Architektura

```
przeglądarka → Cloudflare → [ten Worker] → origin aplikacji
```

- `src/index.js` — cała logika. Polityka domyślna zaszyta w kodzie.
- KV namespace `SECURITY_POLICIES` — nadpisania per host, klucz `policy:<hostname>`.
  Zmiana polityki NIE wymaga wdrożenia kodu.
- Analytics Engine dataset `csp_reports` — naruszenia zgłaszane przez przeglądarki.
- Endpoint `/__csp-report` — obsługiwany przez Workera, przyjmuje raporty.

### Tryby nonce'a (pole `csp.nonce`)

| Tryb | Kiedy | Uwagi |
|---|---|---|
| `auto` | domyślny, aplikacja niezmieniona | Worker dokleja nonce do każdego `<script>` |
| `placeholder` | docelowy, wymaga zmiany w originie | origin renderuje `nonce="__CSP_NONCE__"`, HTML pozostaje cache'owalny |
| `origin` | Next.js, Nuxt, SvelteKit | Worker przekazuje nonce nagłówkiem `x-csp-nonce`, framework używa go sam |
| `off` | CSP bez nonce'a | ostateczność |

## Zasady, których nie łamiemy

1. **Każdy nowy host zaczyna od `report-only`.** Bez wyjątków, nawet dla
   prostych aplikacji. Tryb `enforce` dopiero po przejrzeniu raportów.
2. **Przełączenie na `enforce` wymaga wyraźnej zgody człowieka**, po pokazaniu
   raportów z ostatnich dni.
3. **`hsts.preload` zostaje na `false`.** Włączenie wymaga osobnej decyzji
   i audytu wszystkich subdomen, bo jest praktycznie nieodwracalne.
4. **Nie dopisujemy domen do polityki na podstawie samego raportu.**
   Obecność domeny w raporcie nie znaczy, że ma tam być — może to być
   właśnie to, przed czym się bronimy. Zawsze potwierdzenie od człowieka.
5. **`nonceOnStyles` zostaje na `false`**, dopóki ktoś świadomie nie zdecyduje
   inaczej. Włączenie łamie każdy atrybut `style=""` w aplikacji.
6. **Logika w `src/index.js` nie jest zmieniana bez rozmowy.** Jeśli coś wymaga
   poprawki, najpierw uzasadnienie, potem zmiana.
7. **Przed każdym `wrangler deploy` pokazujemy, co się zmieni**, i czekamy
   na potwierdzenie.

## Stan wdrożenia

Aktualizuj tę tabelę po każdej zmianie.

| Host | Tryb | Nonce | Od kiedy | Uwagi |
|---|---|---|---|---|
| _(uzupełnić)_ | | | | |

## Dane konta

```
Account ID:        (uzupełnić)
Zone:              (uzupełnić)
KV namespace id:   (uzupełnić)
Plan:              (Workers Paid / Free)
```

## Przydatne komendy

```bash
# Nagłówki na produkcji
curl -sI https://HOST | grep -i -E "content-security|strict-transport|permissions|referrer|x-content"

# Aktualna polityka hosta
npx wrangler kv key get --binding SECURITY_POLICIES "policy:HOST" --remote

# Zmiana polityki (bez wdrożenia kodu)
npx wrangler kv key put --binding SECURITY_POLICIES "policy:HOST" 'JSON' --remote

# ROLLBACK — powrót do trybu obserwacji
npx wrangler kv key put --binding SECURITY_POLICIES "policy:HOST" \
  '{"csp":{"mode":"report-only"}}' --remote

# Logi na żywo
npx wrangler tail

# Wdrożenie
npx wrangler deploy
```

## Zapytanie o raporty

```sql
SELECT blob4 AS dyrektywa, blob3 AS zablokowane, blob2 AS strona, count() AS ile
FROM csp_reports
WHERE timestamp > now() - INTERVAL '14' DAY
GROUP BY dyrektywa, zablokowane, strona
ORDER BY ile DESC
LIMIT 100
```

Endpoint: `https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/analytics_engine/sql`,
token z uprawnieniem *Account Analytics: Read*.

Mapowanie pól: `blob1` host, `blob2` documentURL, `blob3` blockedURL,
`blob4` effectiveDirective, `blob5` sourceFile, `blob6` disposition,
`double1` lineNumber.

## Znane pułapki

- Naruszenia z adresów `chrome-extension://`, `moz-extension://` i podobnych
  to rozszerzenia w przeglądarkach użytkowników. Szum, ignorujemy.
- Aplikacje na Cloudflare Pages mają własny plik `_headers`, który koliduje
  z tym Workerem. Trzeba wybrać jeden mechanizm.
- `fetch(request)` do tego samego hosta nie zapętla się — Cloudflare nie
  uruchamia tego samego Workera po raz drugi w łańcuchu subrequestów.
- HTMLRewriter zmienia długość body, dlatego Worker usuwa `Content-Length`
  przy przepisywaniu. To celowe.
- Framework z własnym mechanizmem nonce'ów plus tryb `auto` daje dwie różne
  wartości i wszystko przestaje się ładować. Dla takich stacków tryb `origin`.
````
