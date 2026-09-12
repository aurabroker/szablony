/**
 * Polityka nagłówków: wartości domyślne, walidacja i scalanie.
 *
 * Wszystko tutaj jest czyste, bez wejścia i wyjścia, poza `loadPolicy`.
 * Kluczowa zasada: **żadna wartość z KV nie trafia do logiki bez walidacji**.
 * W pierwotnej wersji wpis `{"csp": null}` w KV zamieniał hosta w błąd 1101.
 */

export const REPORT_PATH = '/__csp-report';
export const NONCE_PLACEHOLDER = '__CSP_NONCE__';
export const POLICY_CACHE_TTL = 60; // sekundy; 60 to minimum KV, świadomie krótko
export const GLOBAL_KEY = 'policy:__global';

/** Nagłówki zdradzające stack — usuwamy je z każdej odpowiedzi. */
export const LEAKY_HEADERS = [
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-cache',
  'x-runtime',
  'x-turbo-charged-by',
];

export const TRYBY_NONCE = ['auto', 'placeholder', 'origin', 'off'];
export const TRYBY_CSP = ['report-only', 'enforce'];

export const DEFAULT_POLICY = {
  csp: {
    enabled: true,
    mode: 'report-only',
    nonce: 'auto',
    scriptSrc: [],
    styleSrc: [],
    connectSrc: [],
    imgSrc: [],
    fontSrc: [],
    frameSrc: [],
    formAction: [],
    frameAncestors: ["'none'"],
    nonceOnStyles: false,
    upgradeInsecureRequests: true,
  },
  hsts: {
    // Schodkowo: zaczynamy od pięciu minut, podnosimy po potwierdzeniu,
    // że wszystkie subdomeny działają po https. Docelowo 63072000.
    maxAge: 300,
    includeSubDomains: false,
    preload: false,
  },
  referrerPolicy: 'strict-origin-when-cross-origin',
  coop: 'same-origin',
  // CORP osobno dla dokumentów i dla zasobów: 'same-origin' na obrazku czy
  // foncie blokuje jego użycie z innej domeny, co jest cichą awarią.
  corpDocument: 'same-origin',
  corpAsset: 'cross-origin',
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

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const stringArray = (v, fallback) =>
  Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim()) : fallback;
const clampInt = (v, min, max, fallback) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.trunc(n))) : fallback;
};

/**
 * Sprowadza dowolne wejście do poprawnej polityki. Zwraca też listę uwag,
 * żeby dało się zobaczyć, co zostało odrzucone, zamiast zgadywać.
 */
export function sanitizePolicy(raw) {
  const problems = [];
  const out = structuredClone(DEFAULT_POLICY);

  if (raw !== null && raw !== undefined && !isObject(raw)) {
    problems.push('polityka nie jest obiektem, użyto domyślnej');
    return { policy: out, problems };
  }

  const src = isObject(raw) ? raw : {};

  if ('csp' in src) {
    if (!isObject(src.csp)) {
      problems.push('csp nie jest obiektem, pominięte');
    } else {
      const c = src.csp;
      if ('enabled' in c) out.csp.enabled = Boolean(c.enabled);
      if ('mode' in c) {
        if (TRYBY_CSP.includes(c.mode)) out.csp.mode = c.mode;
        else problems.push(`csp.mode nieznany (${JSON.stringify(c.mode)}), zostaje report-only`);
      }
      if ('nonce' in c) {
        if (TRYBY_NONCE.includes(c.nonce)) out.csp.nonce = c.nonce;
        else problems.push(`csp.nonce nieznany (${JSON.stringify(c.nonce)}), zostaje auto`);
      }
      if ('nonceOnStyles' in c) out.csp.nonceOnStyles = Boolean(c.nonceOnStyles);
      if ('upgradeInsecureRequests' in c) out.csp.upgradeInsecureRequests = Boolean(c.upgradeInsecureRequests);
      for (const key of ['scriptSrc', 'styleSrc', 'connectSrc', 'imgSrc', 'fontSrc', 'frameSrc', 'formAction', 'frameAncestors']) {
        if (!(key in c)) continue;
        const lista = stringArray(c[key], null);
        if (lista) out.csp[key] = lista;
        else problems.push(`csp.${key} nie jest listą tekstów, pominięte`);
      }
    }
  }

  if ('hsts' in src) {
    if (src.hsts === false) out.hsts = null;
    else if (!isObject(src.hsts)) problems.push('hsts nie jest obiektem, pominięte');
    else {
      out.hsts.maxAge = clampInt(src.hsts.maxAge, 0, 63072000, DEFAULT_POLICY.hsts.maxAge);
      out.hsts.includeSubDomains = Boolean(src.hsts.includeSubDomains);
      out.hsts.preload = Boolean(src.hsts.preload);
      if (out.hsts.preload && !out.hsts.includeSubDomains) {
        out.hsts.preload = false;
        problems.push('hsts.preload wymaga includeSubDomains, wyłączone');
      }
    }
  }

  for (const key of ['referrerPolicy', 'coop', 'corpDocument', 'corpAsset']) {
    if (!(key in src)) continue;
    if (src[key] === null || typeof src[key] === 'string') out[key] = src[key];
    else problems.push(`${key} nie jest tekstem, pominięte`);
  }

  if ('permissions' in src) {
    if (!isObject(src.permissions)) problems.push('permissions nie jest obiektem, pominięte');
    else {
      for (const [feature, lista] of Object.entries(src.permissions)) {
        if (!/^[a-z0-9-]+$/.test(feature)) {
          problems.push(`permissions.${feature}: nazwa odrzucona`);
          continue;
        }
        const wartosci = stringArray(lista, null);
        if (wartosci) out.permissions[feature] = wartosci;
        else problems.push(`permissions.${feature} nie jest listą tekstów, pominięte`);
      }
    }
  }

  // Ustalenie B1: nonce doklejany automatycznie do każdego skryptu dostaje też
  // skrypt wstrzyknięty, więc CSP przestaje chronić przed XSS. Taka kombinacja
  // nie ma prawa trafić na produkcję w trybie egzekwowania.
  if (out.csp.enabled && out.csp.mode === 'enforce' && out.csp.nonce === 'auto') {
    out.csp.mode = 'report-only';
    problems.push(
      "kombinacja enforce + nonce:auto jest zablokowana (nonce trafiłby też do skryptu wstrzykniętego); " +
        'tryb obniżony do report-only, użyj placeholder albo origin',
    );
  }

  return { policy: out, problems };
}

/** Płytki merge z jednym poziomem zagnieżdżenia, po walidacji obu stron. */
export function mergePolicy(base, override) {
  if (!isObject(override)) return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = isObject(value) ? { ...(base[key] ?? {}), ...value } : value;
  }
  return out;
}

/**
 * Odczyt polityki hosta wraz z globalnym wyłącznikiem awaryjnym.
 * Awaria KV nigdy nie może zatrzymać żądania.
 */
export async function loadPolicy(hostname, env) {
  let globalne = null;
  let hosta = null;

  if (env.SECURITY_POLICIES) {
    const opcje = { type: 'json', cacheTtl: POLICY_CACHE_TTL };
    [globalne, hosta] = await Promise.all([
      env.SECURITY_POLICIES.get(GLOBAL_KEY, opcje).catch(() => null),
      env.SECURITY_POLICIES.get(`policy:${hostname}`, opcje).catch(() => null),
    ]);
  }

  if (isObject(globalne) && globalne.disabled === true) {
    return { policy: null, problems: ['wyłącznik globalny aktywny: policy:__global disabled'] };
  }

  const scalone = mergePolicy(isObject(globalne) ? globalne.defaults ?? {} : {}, isObject(hosta) ? hosta : {});
  return sanitizePolicy(scalone);
}
