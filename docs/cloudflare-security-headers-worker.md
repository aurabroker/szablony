# Cloudflare Worker `security-headers` — analiza i proponowane działania

- **Status:** analiza wejściowa, **nic nie wdrożone**, czekam na instrukcje.
- **Data:** 2026-09-09
- **Repo:** `aurabroker/szablony`, branch `claude/clever-shannon-30pmsy`
- **Źródło:** kod wklejony w rozmowie (snapshot w Załączniku A). W repo go nie ma.

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
| 2026-09-09 | Analiza zapisana, wdrożenie wstrzymane do instrukcji | — |

---

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
