/**
 * Sondy — jedyne miejsce, które wykonuje żądania sieciowe.
 * Każda zwraca listę ustaleń w formacie z checks.js i nigdy nie rzuca wyjątku.
 */

import {
  evaluateCookies,
  evaluateScriptInventory,
  evaluateSecurityHeaders,
  evaluateSecurityTxt,
  extractScripts,
  scriptHosts,
} from './checks.js';

const UA = 'aura-security-monitor/1.0 (+wewnetrzny audyt naglowkow)';

/** Prosty licznik podżądań — chroni przed przekroczeniem limitu platformy. */
export class Budget {
  constructor(limit) {
    this.left = limit;
    this.used = 0;
  }
  take(n = 1) {
    if (this.left < n) return false;
    this.left -= n;
    this.used += n;
    return true;
  }
}

async function request(url, { method = 'GET', timeoutMs = 10000, redirect = 'manual', body } = {}) {
  try {
    const response = await fetch(url, {
      method,
      redirect,
      body,
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        'user-agent': UA,
        'cache-control': 'no-cache',
        pragma: 'no-cache',
        ...(body ? { 'content-type': 'application/csp-report' } : {}),
      },
    });
    return { ok: true, response };
  } catch (error) {
    return { ok: false, error: String(error?.message ?? error) };
  }
}

function headersToObject(headers) {
  const out = {};
  for (const [key, value] of headers) out[key.toLowerCase()] = value;
  return out;
}

function readSetCookie(headers) {
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie();
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

const fail = (id, title, detail) => [{ id, status: 'fail', title, detail }];
const skip = (id, title) => [{ id, status: 'skip', title, detail: null }];

/* ------------------------------------------------------------------ */

export async function probeHeaders(target, budget, timeoutMs, kv) {
  if (!budget.take()) return skip('headers', 'Pominięte: wyczerpany budżet podżądań');

  // redirect: 'follow' celowo — chcemy nagłówki strony, którą realnie widzi użytkownik
  const { ok, response, error } = await request(`https://${target.host}/`, {
    timeoutMs,
    redirect: 'follow',
  });
  if (!ok) return fail('headers', 'Host nieosiągalny', { blad: error });

  const findings = [
    {
      id: 'reachable',
      status: response.status < 500 ? 'ok' : 'fail',
      title: `Odpowiedź HTTP ${response.status}`,
      detail: null,
    },
    ...evaluateSecurityHeaders(headersToObject(response.headers), target.expect),
    ...evaluateCookies(readSetCookie(response.headers), target.expect),
  ];

  // Inwentarz skryptów z tej samej odpowiedzi — bez dodatkowego podżądania.
  const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
  if (target.checkScripts && response.status === 200 && contentType.includes('text/html')) {
    findings.push(...(await inventoryScripts(target, response, kv)));
  }

  return findings;
}

/**
 * Porównanie listy skryptów ze wzorcem.
 *
 * Wzorca NIE nadpisujemy, gdy pojawiła się nowa obca domena. Inaczej
 * ostrzeżenie zniknęłoby po jednym przebiegu, a chcemy, żeby wisiało do
 * czasu, aż człowiek je obejrzy i zaakceptuje przez POST /accept.
 */
async function inventoryScripts(target, response, kv) {
  let html = '';
  try {
    html = await response.text();
  } catch (error) {
    return [{ id: 'scripts', status: 'info', title: 'Nie udało się odczytać treści strony', detail: { blad: String(error?.message ?? error) } }];
  }

  const current = extractScripts(html, target.host);
  const key = `baseline:scripts:${target.host}`;

  let baseline = null;
  try {
    baseline = kv ? await kv.get(key, { type: 'json' }) : null;
  } catch {
    baseline = null;
  }

  const findings = evaluateScriptInventory(current, baseline, target.host);
  const nowaDomena = findings.some((f) => f.id === 'scripts' && f.status === 'warn');

  if (kv && !nowaDomena) {
    await kv.put(
      key,
      JSON.stringify({ ...current, domeny: scriptHosts(current.external), seenAt: new Date().toISOString() }),
    );
  }

  return findings;
}

export async function probeHttpRedirect(target, budget, timeoutMs) {
  if (!target.checkHttpRedirect) return [];
  if (!budget.take()) return skip('http-redirect', 'Pominięte: wyczerpany budżet podżądań');

  const { ok, response, error } = await request(`http://${target.host}/`, { timeoutMs });
  if (!ok) return [{ id: 'http-redirect', status: 'info', title: 'Port 80 nieosiągalny', detail: { blad: error } }];

  const location = response.headers.get('location') ?? '';
  if ([301, 308].includes(response.status) && location.startsWith('https://')) {
    return [{ id: 'http-redirect', status: 'ok', title: `HTTP przekierowuje trwale na HTTPS (${response.status})`, detail: null }];
  }
  if ([302, 303, 307].includes(response.status) && location.startsWith('https://')) {
    return [{ id: 'http-redirect', status: 'warn', title: `HTTP przekierowuje na HTTPS, ale tymczasowo (${response.status})`, detail: { location } }];
  }
  return fail('http-redirect', 'HTTP nie przekierowuje na HTTPS', { status: response.status, location });
}

export async function probeExposedPaths(target, budget, timeoutMs) {
  const findings = [];
  for (const path of target.probePaths) {
    if (!budget.take()) {
      findings.push(skip(`path:${path}`, 'Pominięte: wyczerpany budżet podżądań')[0]);
      continue;
    }
    const { ok, response, error } = await request(`https://${target.host}${path}`, { timeoutMs });
    if (!ok) {
      findings.push({ id: `path:${path}`, status: 'info', title: `Nie udało się sprawdzić ${path}`, detail: { blad: error } });
      continue;
    }
    if (response.status === 200) {
      const type = response.headers.get('content-type') ?? '';
      findings.push({
        id: `path:${path}`,
        status: 'fail',
        title: `Wrażliwa ścieżka odpowiada 200: ${path}`,
        detail: { 'content-type': type },
      });
    } else {
      findings.push({ id: `path:${path}`, status: 'ok', title: `${path} → ${response.status}`, detail: null });
    }
  }
  return findings;
}

export async function probeAllowedMethods(target, budget, timeoutMs) {
  if (!budget.take()) return skip('methods', 'Pominięte: wyczerpany budżet podżądań');

  const { ok, response } = await request(`https://${target.host}/`, { method: 'OPTIONS', timeoutMs });
  if (!ok) return [{ id: 'methods', status: 'info', title: 'OPTIONS bez odpowiedzi', detail: null }];

  const allow = (response.headers.get('allow') ?? '').toUpperCase();
  if (!allow) return [{ id: 'methods', status: 'info', title: 'Serwer nie zwraca nagłówka Allow', detail: null }];

  const risky = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'PATCH'].filter((m) => allow.includes(m));
  return risky.length
    ? [{ id: 'methods', status: 'warn', title: 'Serwer deklaruje ryzykowne metody', detail: { allow, ryzykowne: risky } }]
    : [{ id: 'methods', status: 'ok', title: `Dozwolone metody: ${allow}`, detail: null }];
}

export async function probeSecurityTxt(target, budget, timeoutMs) {
  if (!target.checkSecurityTxt) return [];
  if (!budget.take()) return skip('security-txt', 'Pominięte: wyczerpany budżet podżądań');

  const { ok, response } = await request(`https://${target.host}/.well-known/security.txt`, { timeoutMs });
  if (!ok) return [{ id: 'security-txt', status: 'info', title: 'security.txt nieosiągalny', detail: null }];

  const text = response.status === 200 ? await response.text() : '';
  return evaluateSecurityTxt(response.status, text);
}

/**
 * Kanał raportów CSP. Cisza w datasecie prawie zawsze znaczy zepsuty kanał,
 * a nie czystą aplikację — dlatego sprawdzamy go osobno, syntetycznym raportem.
 */
export async function probeCspPipeline(target, budget, timeoutMs) {
  if (!target.checkCspPipeline) return [];
  if (!budget.take()) return skip('csp-pipeline', 'Pominięte: wyczerpany budżet podżądań');

  const payload = JSON.stringify({
    'csp-report': {
      'document-uri': `https://${target.host}/__monitor-probe`,
      'violated-directive': 'monitor-probe',
      'effective-directive': 'monitor-probe',
      'blocked-uri': 'https://monitor.invalid/probe.js',
      disposition: 'monitor',
    },
  });

  const { ok, response, error } = await request(`https://${target.host}${target.cspReportPath}`, {
    method: 'POST',
    timeoutMs,
    body: payload,
  });
  if (!ok) return fail('csp-pipeline', 'Endpoint raportów CSP nieosiągalny', { blad: error });

  if (response.status === 204) {
    return [{ id: 'csp-pipeline', status: 'ok', title: 'Endpoint raportów CSP odpowiada 204', detail: null }];
  }
  return fail('csp-pipeline', `Endpoint raportów CSP odpowiada ${response.status} zamiast 204`, {
    uwaga: 'brak raportów w datasecie może wynikać z zepsutego kanału, nie z czystej aplikacji',
  });
}

/**
 * Dryf plików JS. Pierwszy przebieg zapisuje wzorzec, kolejne porównują.
 * Zmiana hasha bez zapowiedzi to najwcześniejszy sygnał podmiany skryptu.
 */
export async function probeAssetHashes(target, budget, timeoutMs, kv) {
  const findings = [];
  for (const url of target.assets) {
    const id = `asset:${url}`;
    if (!budget.take()) {
      findings.push(skip(id, 'Pominięte: wyczerpany budżet podżądań')[0]);
      continue;
    }
    const { ok, response, error } = await request(url, { timeoutMs, redirect: 'follow' });
    if (!ok || response.status !== 200) {
      findings.push({
        id,
        status: 'warn',
        title: `Nie udało się pobrać pliku: ${url}`,
        detail: { blad: error ?? `HTTP ${response.status}` },
      });
      continue;
    }

    const buffer = await response.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    const hash = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');

    const key = `baseline:asset:${url}`;
    let baseline = null;
    try {
      baseline = kv ? await kv.get(key, { type: 'json' }) : null;
    } catch {
      baseline = null;
    }

    if (!baseline?.hash) {
      if (kv) await kv.put(key, JSON.stringify({ hash, seenAt: new Date().toISOString() }));
      findings.push({ id, status: 'info', title: `Zapisano wzorzec dla ${url}`, detail: { hash } });
    } else if (baseline.hash !== hash) {
      findings.push({
        id,
        status: 'fail',
        title: `Zmiana zawartości pliku: ${url}`,
        detail: { bylo: baseline.hash, jest: hash, wzorzecZ: baseline.seenAt },
      });
    } else {
      findings.push({ id, status: 'ok', title: `Bez zmian: ${url}`, detail: null });
    }
  }
  return findings;
}
