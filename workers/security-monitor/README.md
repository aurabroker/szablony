# security-monitor

Cloudflare Worker uruchamiany z Cron Triggers. Cyklicznie sprawdza stan
bezpieczeństwa listy hostów, zapisuje raport i alarmuje **wyłącznie o zmianach**
względem poprzedniego przebiegu.

Nie stoi na ścieżce żądań produkcyjnych. Awaria monitora nie może wpłynąć na
działanie stron, które monitoruje.

## Co sprawdza

| Sonda | Co robi | Kiedy zgłasza błąd |
|---|---|---|
| `headers` | pobiera stronę główną i ocenia komplet nagłówków | brak CSP, brak ochrony przed ramkowaniem, brak HSTS |
| `frame` | osobno pilnuje ochrony przed clickjackingiem | `frame-ancestors` tylko w report-only i brak `X-Frame-Options` |
| `csp-nonce` | wykrywa `'strict-dynamic'` bez nonce'a | polityka, która wygląda na strict, a nie chroni niczego |
| `cookies` | flagi ciasteczek ze strony głównej | ciasteczko bez `Secure` |
| `http-redirect` | czy port 80 przekierowuje trwale na HTTPS | brak przekierowania |
| `path:*` | wrażliwe ścieżki (`/.env`, `/.git/config`, …) | odpowiedź 200 |
| `methods` | nagłówek `Allow` z odpowiedzi na OPTIONS | ryzykowne metody jako ostrzeżenie |
| `security-txt` | obecność i termin ważności `/.well-known/security.txt` | wygasłe jako ostrzeżenie |
| `csp-pipeline` | wysyła syntetyczny raport na `/__csp-report` | endpoint nie odpowiada 204 |
| `asset:*` | SHA-256 wskazanych plików JS względem zapisanego wzorca | zmiana zawartości bez zapowiedzi |
| `certificate` | dni do wygaśnięcia certyfikatu brzegowego (API Cloudflare) | mniej niż 7 dni |
| `csp-domains` | nowe domeny w raportach CSP z ostatniej doby (Analytics Engine) | nowa domena jako ostrzeżenie |

Dwie ostatnie sondy są opcjonalne — bez `CF_API_TOKEN` po prostu się pomijają.

Sonda `csp-pipeline` istnieje po to, żeby cisza w datasecie nie była mylona
z czystą aplikacją. Brak raportów prawie zawsze znaczy zepsuty kanał.

## Czego ten Worker nie robi

- Niczego nie blokuje. Wykrywa i informuje, decyzje należą do człowieka.
- Nie zastępuje reguł WAF, rate limitingu ani Turnstile. To osobne warstwy,
  działające przed Workerem i zmienialne bez wdrożenia kodu.
- Nie skanuje podatności w zależnościach — to zadanie dla CI.
- Nie wykryje ataku, który nie dotyka odpowiedzi HTTP: przejętego konta
  administratora, podatności w API, wycieku bazy.

## Uruchomienie

```bash
npm test                                    # 32 testy, bez instalowania zależności
npx wrangler kv namespace create MONITOR_STATE
# wpisz zwrócone id do wrangler.jsonc

npx wrangler secret put MONITOR_TOKEN       # wymagany, chroni endpoint HTTP
npx wrangler secret put ALERT_WEBHOOK       # opcjonalny
npx wrangler secret put CF_API_TOKEN        # opcjonalny, tylko odczyt
npx wrangler secret put CF_ACCOUNT_ID       # opcjonalny

npx wrangler deploy --dry-run               # sprawdzenie bez wdrożenia
npx wrangler deploy
```

Konfiguracja celów trafia do KV i zmienia się bez wdrożenia kodu:

```bash
npx wrangler kv key put --binding MONITOR_STATE "monitor:config" \
  --path config/monitor-config.example.json --remote
```

Pierwszy przebieg odpal ręcznie i obejrzyj wynik, zanim zaczniesz ufać alertom:

```bash
curl -s -X POST -H "Authorization: Bearer $MONITOR_TOKEN" \
  https://security-monitor.<subdomena>.workers.dev/run | head -40
```

## Endpointy

Wszystkie poza `/health` wymagają tokenu, w nagłówku `Authorization: Bearer`
albo w parametrze `?token=`. Bez sekretu `MONITOR_TOKEN` endpoint zwraca 503.

| Ścieżka | Metoda | Co zwraca |
|---|---|---|
| `/` | GET | ostatni raport jako strona HTML |
| `/report.json` | GET | ostatni raport jako JSON |
| `/config` | GET | konfiguracja po walidacji, z listą odrzuconych wpisów |
| `/run` | POST | uruchamia przebieg teraz i zwraca raport |
| `/health` | GET | `{"ok":true}`, bez tokenu, nic nie ujawnia |

## Alerty

Bez `ALERT_WEBHOOK` monitor działa w trybie cichym — raport i tak leży w KV
i jest widoczny pod `/`. Z webhookiem wysyła jeden POST z JSON-em, który ma
naraz pole `text` (Slack, Mattermost) i `content` (Discord), plus pełne
podsumowanie w `report`. Dowolny inny odbiorca czyta to, co mu wygodniej.

Alarm leci tylko przy zmianie stanu: nowy problem, pogorszenie albo naprawa.
Ostrzeżenie, które trwa od tygodnia, nie odzywa się co godzinę. Raz na dobę
(cron `0 6 * * *`) idzie pełne podsumowanie niezależnie od zmian.

Poczta: Cloudflare Email Routing pozwala wysyłać z Workera na zweryfikowany
adres przez binding `send_email`. Świadomie nie ma tego w kodzie — jedna
zależność mniej, a webhook pokrywa wszystkie znane przypadki.

## Limity i koszty

- **Podżądania.** Plan darmowy dopuszcza 50 na wywołanie, płatny 1000.
  `maxSubrequests` domyślnie 45. Po wyczerpaniu budżetu pozostałe sondy
  dostają status `skip` i widać to w raporcie — przebieg nie jest ucinany po cichu.
  Jeden host to około 10 podżądań, więc na planie darmowym mieszczą się 4 hosty.
- **Cron Triggers** działają także na planie darmowym.
- **Cache.** Sondy wysyłają `cache-control: no-cache`, ale nie da się w pełni
  wykluczyć, że odpowiedź przyjdzie z bufora brzegowego. Przy diagnozowaniu
  różnic sprawdź to samo curl-em spoza Cloudflare.

## Struktura

```
src/checks.js   funkcje oceniające, czyste, bez wejścia/wyjścia — cały test jednostkowy siedzi tutaj
src/probes.js   jedyne miejsce wykonujące żądania sieciowe
src/cfapi.js    sondy korzystające z API Cloudflare, w całości opcjonalne
src/config.js   wczytanie i walidacja konfiguracji z KV
src/alert.js    budowa treści alertu i wysyłka webhooka
src/report.js   raport HTML, bez zasobów zewnętrznych
src/index.js    handlery scheduled i fetch, orkiestracja
```

Konfiguracja z KV przechodzi przez `sanitizeConfig` — zły wpis daje pominięty
cel i notatkę w raporcie, nigdy wyjątku w handlerze. To wniosek z audytu
Workera nagłówkowego, gdzie `{"csp": null}` w KV wywracało hosta.

## Testy

```bash
npm test
```

Bez `npm install`. Testy jednostkowe pokrywają funkcje oceniające i walidację
konfiguracji, testy integracyjne podstawiają `fetch` i KV, więc cały przebieg
audytu jest sprawdzany bez wranglera i bez ruchu sieciowego.
