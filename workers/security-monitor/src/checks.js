/**
 * Czyste funkcje oceniające. Zero wejścia/wyjścia, zero zależności od runtime'u
 * Workers — dzięki temu całość da się przetestować zwykłym `node --test`.
 *
 * Każda funkcja zwraca listę ustaleń w kształcie:
 *   { id, status, title, detail }
 *
 * status: 'ok' | 'info' | 'skip' | 'warn' | 'fail'
 */

export const RANK = { ok: 0, info: 1, skip: 1, warn: 2, fail: 3 };

/** Nagłówki zdradzające stack. Ta sama lista, co w Workerze nagłówkowym. */
export const LEAKY_HEADERS = [
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
  'x-turbo-charged-by',
];

/** Ścieżki sprawdzane domyślnie. Tylko GET, tylko własne hosty. */
export const DEFAULT_PROBE_PATHS = [
  '/.env',
  '/.git/config',
  '/.well-known/../.env',
  '/wp-config.php.bak',
  '/config.json',
  '/server-status',
];

export const DEFAULT_EXPECT = {
  // 'enforce' | 'report-only' | 'any' | 'none'
  csp: 'any',
  requireHsts: true,
  hstsMinAge: 15552000, // 180 dni — próg ostrzeżenia, nie cel docelowy
  frameProtection: true,
  nosniff: true,
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: true,
  coop: null, // null = nie sprawdzamy
  corp: null,
  // ciasteczka bez HttpOnly bywają celowe (czytane z JS) — lista wyjątków po nazwie
  cookiesAllowedWithoutHttpOnly: [],
};

const finding = (id, status, title, detail = null) => ({ id, status, title, detail });

export function worst(statuses) {
  let out = 'ok';
  for (const s of statuses) if ((RANK[s] ?? 0) > (RANK[out] ?? 0)) out = s;
  return out;
}

export function summarize(findings) {
  const counts = { ok: 0, info: 0, skip: 0, warn: 0, fail: 0 };
  for (const f of findings) counts[f.status] = (counts[f.status] ?? 0) + 1;
  return { counts, worst: worst(findings.map((f) => f.status)) };
}

/* ------------------------------------------------------------------ */
/* Nagłówki                                                            */
/* ------------------------------------------------------------------ */

export function parseHsts(value) {
  if (!value) return null;
  const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(value);
  return {
    maxAge: maxAge ? Number(maxAge[1]) : null,
    includeSubDomains: /includesubdomains/i.test(value),
    preload: /preload/i.test(value),
  };
}

/**
 * @param {Record<string,string>} h nagłówki odpowiedzi, klucze małymi literami
 * @param {object} expect oczekiwania dla tego hosta
 */
export function evaluateSecurityHeaders(h, expect = {}) {
  const e = { ...DEFAULT_EXPECT, ...expect };
  const out = [];

  const cspEnforce = h['content-security-policy'] ?? null;
  const cspReport = h['content-security-policy-report-only'] ?? null;

  // --- CSP -----------------------------------------------------------
  if (e.csp === 'none') {
    out.push(finding('csp', 'info', 'CSP świadomie wyłączone'));
  } else if (!cspEnforce && !cspReport) {
    out.push(finding('csp', 'fail', 'Brak jakiegokolwiek nagłówka CSP'));
  } else if (e.csp === 'enforce' && !cspEnforce) {
    out.push(
      finding('csp', 'fail', 'CSP tylko w trybie report-only, oczekiwano enforce', {
        obecne: 'Content-Security-Policy-Report-Only',
      }),
    );
  } else if (e.csp === 'report-only' && cspEnforce) {
    out.push(
      finding('csp', 'warn', 'CSP w trybie enforce, a konfiguracja mówi report-only', {
        uwaga: 'ktoś przełączył tryb poza uzgodnionym procesem',
      }),
    );
  } else {
    out.push(
      finding('csp', 'ok', cspEnforce ? 'CSP w trybie enforce' : 'CSP w trybie report-only'),
    );
  }

  // nonce w polityce, która nie jest egzekwowana, nic nie daje — sygnalizujemy
  const activeCsp = cspEnforce ?? cspReport ?? '';
  if (cspEnforce && /'strict-dynamic'/.test(cspEnforce) && !/'nonce-/.test(cspEnforce)) {
    out.push(
      finding(
        'csp-nonce',
        'fail',
        "CSP zawiera 'strict-dynamic' bez nonce'a — script-src nie chroni niczego",
      ),
    );
  }

  // --- ochrona przed ramkowaniem -------------------------------------
  // To jest ustalenie K2 z analizy: przy CSP w trybie report-only dyrektywa
  // frame-ancestors NIE jest egzekwowana, więc bez X-Frame-Options host
  // nie ma żadnej ochrony przed clickjackingiem.
  if (e.frameProtection) {
    const xfo = h['x-frame-options'] ?? null;
    const enforcedAncestors = cspEnforce && /frame-ancestors/i.test(cspEnforce);
    if (enforcedAncestors) {
      out.push(finding('frame', 'ok', 'frame-ancestors egzekwowane'));
    } else if (xfo) {
      out.push(finding('frame', 'ok', `X-Frame-Options: ${xfo}`));
    } else if (cspReport && /frame-ancestors/i.test(cspReport)) {
      out.push(
        finding(
          'frame',
          'fail',
          'Brak ochrony przed ramkowaniem: frame-ancestors jest tylko w report-only, X-Frame-Options usunięte',
        ),
      );
    } else {
      out.push(finding('frame', 'fail', 'Brak ochrony przed ramkowaniem'));
    }
  }

  // --- HSTS ----------------------------------------------------------
  if (e.requireHsts) {
    const hsts = parseHsts(h['strict-transport-security']);
    if (!hsts) {
      out.push(finding('hsts', 'fail', 'Brak Strict-Transport-Security'));
    } else {
      const problems = [];
      if (!hsts.maxAge || hsts.maxAge < e.hstsMinAge) {
        problems.push(`max-age=${hsts.maxAge ?? 'brak'} poniżej progu ${e.hstsMinAge}`);
      }
      if (!hsts.includeSubDomains) problems.push('brak includeSubDomains');
      if (hsts.preload) problems.push('preload włączone — zmiana praktycznie nieodwracalna');
      out.push(
        problems.length
          ? finding('hsts', 'warn', 'HSTS wymaga uwagi', { problemy: problems })
          : finding('hsts', 'ok', `HSTS max-age=${hsts.maxAge}`),
      );
    }
  }

  // --- pozostałe -----------------------------------------------------
  if (e.nosniff) {
    const v = (h['x-content-type-options'] ?? '').toLowerCase();
    out.push(
      v === 'nosniff'
        ? finding('nosniff', 'ok', 'X-Content-Type-Options: nosniff')
        : finding('nosniff', 'warn', 'Brak X-Content-Type-Options: nosniff'),
    );
  }

  if (e.referrerPolicy) {
    const v = h['referrer-policy'] ?? null;
    if (!v) out.push(finding('referrer', 'warn', 'Brak Referrer-Policy'));
    else if (v.toLowerCase() !== String(e.referrerPolicy).toLowerCase()) {
      out.push(
        finding('referrer', 'info', 'Referrer-Policy inne niż oczekiwane', {
          jest: v,
          oczekiwano: e.referrerPolicy,
        }),
      );
    } else out.push(finding('referrer', 'ok', `Referrer-Policy: ${v}`));
  }

  if (e.permissionsPolicy) {
    out.push(
      h['permissions-policy']
        ? finding('permissions', 'ok', 'Permissions-Policy obecne')
        : finding('permissions', 'warn', 'Brak Permissions-Policy'),
    );
  }

  for (const [key, header] of [
    ['coop', 'cross-origin-opener-policy'],
    ['corp', 'cross-origin-resource-policy'],
  ]) {
    if (!e[key]) continue;
    const v = h[header] ?? null;
    out.push(
      v === e[key]
        ? finding(key, 'ok', `${header}: ${v}`)
        : finding(key, 'warn', `${header} inne niż oczekiwane`, { jest: v, oczekiwano: e[key] }),
    );
  }

  // --- wycieki informacji --------------------------------------------
  const leaks = LEAKY_HEADERS.filter((name) => h[name]);
  if (leaks.length) {
    out.push(
      finding('leaky', 'warn', 'Nagłówki zdradzające stack przechodzą do klienta', {
        naglowki: leaks.map((n) => `${n}: ${h[n]}`),
      }),
    );
  }

  const server = h['server'] ?? '';
  if (/\d+\.\d+/.test(server)) {
    out.push(finding('server', 'info', 'Nagłówek Server ujawnia wersję', { server }));
  }

  return out;
}

/* ------------------------------------------------------------------ */
/* Ciasteczka                                                          */
/* ------------------------------------------------------------------ */

export function parseCookie(raw) {
  const [pair, ...attrs] = String(raw).split(';');
  const name = pair.split('=')[0].trim();
  const flags = attrs.map((a) => a.trim().toLowerCase());
  const sameSite = flags.find((f) => f.startsWith('samesite='));
  return {
    name,
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: sameSite ? sameSite.split('=')[1] : null,
  };
}

export function evaluateCookies(rawCookies, expect = {}) {
  const e = { ...DEFAULT_EXPECT, ...expect };
  if (!rawCookies || rawCookies.length === 0) {
    return [finding('cookies', 'ok', 'Strona główna nie ustawia ciasteczek')];
  }

  const problems = [];
  for (const raw of rawCookies) {
    const c = parseCookie(raw);
    const missing = [];
    if (!c.secure) missing.push('Secure');
    if (!c.httpOnly && !e.cookiesAllowedWithoutHttpOnly.includes(c.name)) missing.push('HttpOnly');
    if (!c.sameSite) missing.push('SameSite');
    if (missing.length) problems.push({ ciasteczko: c.name, brakuje: missing });
  }

  if (!problems.length) {
    return [finding('cookies', 'ok', `Wszystkie ciasteczka (${rawCookies.length}) mają komplet flag`)];
  }
  // brak Secure to błąd, sam brak SameSite/HttpOnly to ostrzeżenie
  const hasInsecure = problems.some((p) => p.brakuje.includes('Secure'));
  return [
    finding(
      'cookies',
      hasInsecure ? 'fail' : 'warn',
      `Ciasteczka bez kompletu flag: ${problems.length}`,
      { problemy: problems },
    ),
  ];
}

/* ------------------------------------------------------------------ */
/* security.txt                                                        */
/* ------------------------------------------------------------------ */

export function evaluateSecurityTxt(status, text, now = Date.now()) {
  if (status === 404) return [finding('security-txt', 'info', 'Brak /.well-known/security.txt')];
  if (status !== 200) {
    return [finding('security-txt', 'info', `security.txt zwrócił ${status}`)];
  }
  const m = /^expires:\s*(.+)$/im.exec(String(text ?? ''));
  if (!m) return [finding('security-txt', 'warn', 'security.txt bez pola Expires')];
  const expires = Date.parse(m[1].trim());
  if (Number.isNaN(expires)) {
    return [finding('security-txt', 'warn', 'security.txt: nieczytelna data w Expires')];
  }
  const days = Math.floor((expires - now) / 86400000);
  if (days < 0) return [finding('security-txt', 'warn', `security.txt wygasł ${-days} dni temu`)];
  if (days < 30) return [finding('security-txt', 'warn', `security.txt wygasa za ${days} dni`)];
  return [finding('security-txt', 'ok', `security.txt ważny jeszcze ${days} dni`)];
}

/* ------------------------------------------------------------------ */
/* Porównanie z poprzednim przebiegiem                                 */
/* ------------------------------------------------------------------ */

export const stateKey = (host, id) => `${host}|${id}`;

/** Spłaszcza wynik przebiegu do mapy klucz → status. */
export function toState(targets) {
  const state = {};
  for (const t of targets) {
    for (const f of t.findings) state[stateKey(t.host, f.id)] = f.status;
  }
  return state;
}

/**
 * Różnica między przebiegami. Alarmujemy wyłącznie o zmianach, nie o stanie —
 * inaczej po tygodniu nikt tych alertów nie czyta.
 */
export function diffStates(prev = {}, next = {}) {
  const nowe = [];
  const pogorszone = [];
  const naprawione = [];

  for (const [key, status] of Object.entries(next)) {
    const before = prev[key];
    const rankNow = RANK[status] ?? 0;
    const rankBefore = RANK[before] ?? 0;
    if (before === undefined) {
      if (rankNow >= RANK.warn) nowe.push({ key, status });
    } else if (rankNow > rankBefore && rankNow >= RANK.warn) {
      pogorszone.push({ key, status, poprzednio: before });
    } else if (rankBefore >= RANK.warn && rankNow < RANK.warn) {
      naprawione.push({ key, status, poprzednio: before });
    }
  }

  for (const [key, status] of Object.entries(prev)) {
    if (next[key] === undefined && (RANK[status] ?? 0) >= RANK.warn) {
      naprawione.push({ key, status: 'zniknęło', poprzednio: status });
    }
  }

  return { nowe, pogorszone, naprawione };
}

/* ------------------------------------------------------------------ */
/* Inwentarz skryptów na stronie                                       */
/* ------------------------------------------------------------------ */

const SCRIPT_TAG = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const SCRIPT_SRC_ONLY = /<script\b([^>]*?)\/?>/gi;
const SRC_ATTR = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;

/** Adres bez parametrów i kotwicy — wersje typu ?ver=6.4 nie mają robić szumu. */
export function normalizeScriptUrl(raw, host) {
  try {
    const url = new URL(String(raw).trim(), `https://${host}/`);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.search = '';
    url.hash = '';
    return { url: url.toString(), host: url.hostname.toLowerCase() };
  } catch {
    return null;
  }
}

/**
 * Wyciąga z HTML listę skryptów. Świadomie na wyrażeniach regularnych, a nie
 * na HTMLRewriterze: dzięki temu funkcja jest czysta i testowalna w node.
 */
export function extractScripts(html, host, limitBytes = 512 * 1024) {
  const source = String(html ?? '').slice(0, limitBytes);
  const external = new Set();
  let inlineCount = 0;
  let inlineBytes = 0;

  SCRIPT_TAG.lastIndex = 0;
  let match;
  while ((match = SCRIPT_TAG.exec(source)) !== null) {
    const attrs = match[1] ?? '';
    const body = match[2] ?? '';
    const src = SRC_ATTR.exec(attrs);
    if (src) {
      const normalized = normalizeScriptUrl(src[1] ?? src[2] ?? src[3], host);
      if (normalized) external.add(normalized.url);
    } else if (body.trim().length) {
      inlineCount += 1;
      inlineBytes += body.length;
    }
  }

  // Znaczniki samozamykające się i takie bez pary, których pętla wyżej nie złapie.
  SCRIPT_SRC_ONLY.lastIndex = 0;
  while ((match = SCRIPT_SRC_ONLY.exec(source)) !== null) {
    const src = SRC_ATTR.exec(match[1] ?? '');
    if (!src) continue;
    const normalized = normalizeScriptUrl(src[1] ?? src[2] ?? src[3], host);
    if (normalized) external.add(normalized.url);
  }

  return { external: [...external].sort(), inlineCount, inlineBytes };
}

export const scriptHosts = (urls) =>
  [...new Set(urls.map((u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return null; } }).filter(Boolean))].sort();

/**
 * Porównanie inwentarza z zapisanym wzorcem. Nowa obca domena serwująca skrypt
 * to najmocniejszy sygnał, jaki ta warstwa potrafi dać — tak wygląda podmiana
 * kodu na stronie zbierającej dane z formularzy.
 */
export function evaluateScriptInventory(current, baseline, host) {
  if (!baseline || !Array.isArray(baseline.external)) {
    return [
      {
        id: 'scripts',
        status: 'info',
        title: `Zapisano wzorzec: ${current.external.length} skryptów zewnętrznych, ${current.inlineCount} wplecionych`,
        detail: { domeny: scriptHosts(current.external) },
      },
    ];
  }

  const before = new Set(baseline.external);
  const added = current.external.filter((u) => !before.has(u));
  const removed = baseline.external.filter((u) => !current.external.includes(u));

  const knownHosts = new Set(scriptHosts(baseline.external));
  const newHosts = scriptHosts(added).filter((h) => !knownHosts.has(h) && h !== host);

  const out = [];

  if (newHosts.length) {
    out.push({
      id: 'scripts',
      status: 'warn',
      title: `Nowa domena serwuje skrypt na tej stronie: ${newHosts.join(', ')}`,
      detail: { nowe: added.slice(0, 15), usuniete: removed.slice(0, 15) },
    });
  } else if (added.length || removed.length) {
    out.push({
      id: 'scripts',
      status: 'info',
      title: `Zmiana listy skryptów: ${added.length} nowych, ${removed.length} usuniętych`,
      detail: { nowe: added.slice(0, 15), usuniete: removed.slice(0, 15) },
    });
  } else {
    out.push({
      id: 'scripts',
      status: 'ok',
      title: `Bez zmian: ${current.external.length} skryptów zewnętrznych`,
      detail: null,
    });
  }

  if (current.inlineCount !== baseline.inlineCount) {
    out.push({
      id: 'scripts-inline',
      status: 'info',
      title: `Zmiana liczby skryptów wplecionych w HTML: ${baseline.inlineCount} → ${current.inlineCount}`,
      detail: null,
    });
  }

  return out;
}

/* ------------------------------------------------------------------ */
/* Poczta i stan proxy w DNS                                           */
/* ------------------------------------------------------------------ */

const txtTresc = (r) => String(r.content ?? '').replace(/^"|"$/g, '').trim();

/**
 * Ocena rekordów DNS strefy pod kątem podszywania się pod domenę i tego,
 * czy ruch w ogóle przechodzi przez Cloudflare.
 *
 * Brak DMARC to nie jest problem techniczny, tylko biznesowy: bez niego
 * każdy może wysłać maila wyglądającego na pismo z kancelarii.
 */
export function evaluateDns(records, host) {
  const lista = Array.isArray(records) ? records : [];
  const out = [];

  const txt = lista.filter((r) => r.type === 'TXT');
  const spf = txt.find((r) => r.name === host && /^v=spf1\b/i.test(txtTresc(r)));
  const dmarc = txt.find((r) => r.name === `_dmarc.${host}` && /^v=DMARC1\b/i.test(txtTresc(r)));
  const dkim = lista.some((r) => r.name.includes('._domainkey'));
  const maMx = lista.some((r) => r.type === 'MX');

  // --- SPF ---
  if (!spf) {
    out.push({
      id: 'spf',
      status: maMx ? 'fail' : 'warn',
      title: 'Brak rekordu SPF',
      detail: { skutek: 'dowolny serwer może wysyłać pocztę podającą się za tę domenę' },
    });
  } else {
    const tresc = txtTresc(spf);
    const luzny = /[?~]all\s*$/.test(tresc) || !/all\s*$/.test(tresc);
    out.push({
      id: 'spf',
      status: luzny ? 'warn' : 'ok',
      title: luzny ? 'SPF jest, ale nie odrzuca obcych nadawców' : 'SPF poprawny',
      detail: { rekord: tresc.slice(0, 200) },
    });
  }

  // --- DMARC ---
  if (!dmarc) {
    out.push({
      id: 'dmarc',
      status: 'fail',
      title: 'Brak rekordu DMARC',
      detail: { skutek: 'nikt nie blokuje maili podszywających się pod tę domenę' },
    });
  } else {
    const tresc = txtTresc(dmarc);
    const polityka = (/\bp\s*=\s*(none|quarantine|reject)/i.exec(tresc) ?? [])[1]?.toLowerCase() ?? 'brak';
    out.push({
      id: 'dmarc',
      status: polityka === 'none' || polityka === 'brak' ? 'warn' : 'ok',
      title:
        polityka === 'none'
          ? 'DMARC tylko obserwuje (p=none), nic nie blokuje'
          : polityka === 'brak'
            ? 'DMARC bez ustawionej polityki'
            : `DMARC egzekwowany (p=${polityka})`,
      detail: { rekord: tresc.slice(0, 200) },
    });
  }

  // --- DKIM ---
  if (maMx && !dkim) {
    out.push({ id: 'dkim', status: 'warn', title: 'Domena odbiera pocztę, ale nie ma podpisu DKIM', detail: null });
  }

  // --- ruch przez Cloudflare ---
  const webowe = lista.filter(
    (r) => ['A', 'AAAA', 'CNAME'].includes(r.type) && (r.name === host || r.name === `www.${host}`),
  );
  const bezProxy = webowe.filter((r) => r.proxied === false).map((r) => r.name);
  if (webowe.length === 0) {
    out.push({ id: 'proxy', status: 'info', title: 'Brak rekordów wskazujących stronę www', detail: null });
  } else if (bezProxy.length) {
    out.push({
      id: 'proxy',
      status: 'warn',
      title: `Ruch omija Cloudflare: ${bezProxy.join(', ')}`,
      detail: { skutek: 'nie działają tam reguły ochronne ani nagłówki dokładane na brzegu' },
    });
  } else {
    out.push({ id: 'proxy', status: 'ok', title: 'Cały ruch www idzie przez Cloudflare', detail: null });
  }

  return out;
}
