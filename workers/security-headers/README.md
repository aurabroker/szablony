# security-headers

Cloudflare Worker dokładający nagłówki bezpieczeństwa do odpowiedzi wszystkich
aplikacji. Jedno miejsce zamiast konfiguracji w każdym frameworku osobno.

**Stan: niewdrożony. Pole `routes` jest puste celowo.**

Ten Worker stoi na ścieżce ruchu produkcyjnego, w odróżnieniu od monitora,
który działa obok. Jego awaria oznacza niedostępne strony, nie brakujący
nagłówek w raporcie.

## Czym różni się od wersji wejściowej

Kod powstał z przeglądu wklejonej wersji, opisanego w
`docs/cloudflare-security-headers-worker.md`. Naprawione ustalenia:

| Ustalenie | Co było | Co jest |
|---|---|---|
| B1 | `enforce` z trybem `auto` nadawał nonce także skryptowi wstrzykniętemu | kombinacja zablokowana w walidacji, tryb obniżany do `report-only` |
| B2 | brak przechwytywania błędów, wyjątek kładł wszystkie hosty | cały handler w `try/catch`, ruch przechodzi bez modyfikacji |
| B3 | `{"csp": null}` w KV wywracało hosta | `sanitizePolicy` sprowadza dowolne wejście do poprawnej polityki |
| B4 | tryb `origin` rozjeżdżał się z buforowaniem | dokument dostaje `Cache-Control: private, no-store` |
| W1 | `CORP: same-origin` na fontach i obrazkach blokował ich użycie z innych domen | osobne wartości dla dokumentów i zasobów |
| W4 | brak wyłącznika awaryjnego | klucz `policy:__global` z flagą `disabled` |
| W5, W6 | `HTMLRewriter` psuł strony spoza UTF-8 i odpowiedzi częściowe | przepisujemy tylko status 200, HTML i UTF-8 |
| W7 | `'self'` w apostrofach dawało niepoprawny `Permissions-Policy` | normalizacja i odrzucanie wpisów nieparsowalnych |
| W8, K2 | `X-Frame-Options` kasowany bezwarunkowo, przez co faza obserwacji obniżała bezpieczeństwo | nagłówek wyliczany z `frame-ancestors` |
| W2 | publiczny endpoint raportów bez limitów | typ treści, rozmiar, liczba wpisów, zapis przez `waitUntil` |

Domyślny `max-age` dla HSTS to **300 sekund**, nie dwa lata. HSTS wprowadza się
schodkowo, bo przeglądarka zapamiętuje wartość natychmiast i nie da się jej
łatwo cofnąć. Kolejność: 300 s, jeden dzień, tydzień, docelowo, z weryfikacją
wszystkich subdomen na każdym stopniu.

## Tryby nonce

| Tryb | Kiedy | Uwagi |
|---|---|---|
| `auto` | **tylko diagnostyka** w `report-only` | Worker dokleja nonce do każdego skryptu, więc także do wstrzykniętego. Walidacja nie dopuści tego do trybu `enforce`. |
| `placeholder` | docelowy, wymaga zmiany w szablonie | origin renderuje `nonce="__CSP_NONCE__"`, dokument pozostaje buforowalny |
| `origin` | Next.js, Nuxt, SvelteKit | Worker przekazuje nonce nagłówkiem `x-csp-nonce`, framework używa go sam; dokument nie jest buforowany |
| `off` | CSP bez nonce'a | ostateczność |

## Zanim to wdrożysz

1. **Audyt strefy.** Rocket Loader, Email Address Obfuscation i Bot Fight Mode
   wstrzykują własne skrypty **po** Workerze, więc nie dostaną nonce'a.
   Przy `enforce` zostaną zablokowane, w `report-only` zaleją dataset.
   Do sprawdzenia też Response Header Transform Rules, bo wykonują się po
   Workerze i mogą nadpisać nasze nagłówki.
2. **Czy host jest za proxy.** Na domenie z wyłączoną pomarańczową chmurką
   Worker się nie uruchomi. Monitor to sprawdza.
3. **Czy host serwuje zasoby dla innych domen.** Decyduje o wartości
   `corpAsset`.
4. **Logowanie przez popup i płatności.** COOP `same-origin` zrywa
   `window.opener`. To działa od pierwszego żądania, niezależnie od tego, że
   CSP jest tylko obserwacyjne.

**`report-only` dotyczy wyłącznie CSP.** COOP, CORP, `Permissions-Policy`,
HSTS i `nosniff` działają w pełni od pierwszej sekundy.

## Wdrożenie etapami

```bash
npm test                                        # 28 testow, bez instalowania zaleznosci
npx wrangler kv namespace create SECURITY_POLICIES
# wpisz zwrocone id do wrangler.jsonc
npx wrangler deploy --dry-run
```

1. Dodaj **jeden** host do `routes`, najmniej krytyczny. Wdróż.
2. Sprawdź nagłówki curlem i przeklikaj stronę: logowanie, formularz, płatność.
3. Zbieraj raporty 7 do 14 dni. Weryfikuj, że kanał raportów działa, zamiast
   brać ciszę za sukces.
4. Domknij listy źródeł w KV dla tego hosta.
5. Zmień tryb nonce na `placeholder` albo `origin`. `auto` nie idzie do `enforce`.
6. Włącz `enforce` dla tego hosta. Potem dopiero kolejny host.
7. HSTS podnoś schodkowo, `preload` na końcu i tylko po audycie subdomen.

## Wyłącznik awaryjny

```bash
# cala warstwa przestaje modyfikowac ruch
npx wrangler kv key put --binding SECURITY_POLICIES "policy:__global" \
  '{"disabled":true}' --remote
```

Propagacja do minuty, bo `cacheTtl` wynosi 60 sekund. Prawdziwe wyjście
awaryjne przy poważnej awarii to usunięcie trasy Workera w panelu, bo działa
natychmiast.

## Rollback polityki hosta

Merge jest płytki, więc zapis fragmentu **kasuje reszte polityki tego hosta**.
Przed zmianą zrób kopię i przywracaj ją w całości:

```bash
npx wrangler kv key get --binding SECURITY_POLICIES "policy:HOST" --remote \
  > kopia-HOST-$(date +%F).json
```

## Struktura

```
src/policy.js    wartosci domyslne, walidacja wejscia z KV, scalanie
src/headers.js   budowanie naglowkow, decyzje o przepisywaniu
src/report.js    endpoint raportow CSP z limitami
src/index.js     handler fetch z przechwytywaniem bledow
```

Logika oceny jest w funkcjach czystych, więc testy nie potrzebują wranglera
ani sieci.
