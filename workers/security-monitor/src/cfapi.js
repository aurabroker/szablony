/**
 * Sondy korzystające z API Cloudflare. Wszystkie są opcjonalne — bez tokenu
 * zwracają status 'skip' i nie blokują reszty przebiegu.
 *
 * Token: uprawnienia tylko do odczytu (Zone: SSL and Certificates: Read,
 * Account Analytics: Read). Trzymany jako secret CF_API_TOKEN.
 */

const API = 'https://api.cloudflare.com/client/v4';

const skip = (id, title) => [{ id, status: 'skip', title, detail: null }];

async function api(env, path, init = {}) {
  const response = await fetch(`${API}${path}`, {
    ...init,
    signal: AbortSignal.timeout(15000),
    headers: {
      authorization: `Bearer ${env.CF_API_TOKEN}`,
      'content-type': 'application/json',
      ...init.headers,
    },
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* odpowiedź nie-JSON obsługujemy niżej */
  }
  if (!response.ok || json?.success === false) {
    const reason = json?.errors?.map((e) => e.message).join('; ') || `HTTP ${response.status}`;
    throw new Error(reason);
  }
  return json;
}

async function resolveZoneId(env, zone) {
  const cacheKey = `cache:zone-id:${zone}`;
  if (env.MONITOR_STATE) {
    const cached = await env.MONITOR_STATE.get(cacheKey);
    if (cached) return cached;
  }
  const json = await api(env, `/zones?name=${encodeURIComponent(zone)}`);
  const id = json?.result?.[0]?.id ?? null;
  if (id && env.MONITOR_STATE) {
    await env.MONITOR_STATE.put(cacheKey, id, { expirationTtl: 86400 });
  }
  return id;
}

/** Ile dni zostało do wygaśnięcia certyfikatu brzegowego obsługującego hosta. */
export async function probeCertificate(target, env, budget) {
  if (!env.CF_API_TOKEN) return skip('certificate', 'Pominięte: brak CF_API_TOKEN');
  if (!target.zone) return skip('certificate', 'Pominięte: cel nie ma ustawionego pola zone');
  if (!budget.take(2)) return skip('certificate', 'Pominięte: wyczerpany budżet podżądań');

  try {
    const zoneId = await resolveZoneId(env, target.zone);
    if (!zoneId) {
      // Pusta odpowiedź przy udanym wywołaniu znaczy, że token jest ważny, ale
      // ta strefa nie mieści się w jego zakresie. Liczba stref, które w ogóle
      // widzi, od razu mówi, czy to kwestia uprawnienia, czy zakresu zasobów.
      let widoczne = null;
      try {
        const wszystkie = await api(env, '/zones?per_page=1');
        widoczne = wszystkie?.result_info?.total_count ?? null;
      } catch {
        widoczne = null;
      }
      const wskazowka =
        widoczne === 0
          ? 'token nie widzi żadnej strefy: brak uprawnienia Zone → Zone → Read'
          : widoczne
            ? `token widzi ${widoczne} stref, ale nie tę: w zakresie zasobów ustaw Include → All zones`
            : 'nie udało się ustalić, ile stref widzi token';
      return [{
        id: 'certificate',
        status: 'warn',
        title: `Strefa ${target.zone} poza zakresem tokenu`,
        detail: { wskazowka, stref_widocznych: widoczne },
      }];
    }

    const json = await api(env, `/zones/${zoneId}/ssl/certificate_packs?status=all`);
    const packs = Array.isArray(json?.result) ? json.result : [];

    const matches = (host) =>
      host === target.host ||
      (host.startsWith('*.') && target.host.endsWith(host.slice(1)) &&
        target.host.split('.').length === host.split('.').length);

    let soonest = null;
    for (const pack of packs) {
      const hosts = Array.isArray(pack.hosts) ? pack.hosts : [];
      if (!hosts.some(matches)) continue;
      const certs = Array.isArray(pack.certificates) ? pack.certificates : [];
      for (const cert of certs) {
        const at = Date.parse(cert.expires_on ?? '');
        if (!Number.isNaN(at) && (soonest === null || at < soonest)) soonest = at;
      }
    }

    if (soonest === null) {
      return [{ id: 'certificate', status: 'info', title: 'Nie znaleziono certyfikatu obejmującego ten host', detail: null }];
    }

    const days = Math.floor((soonest - Date.now()) / 86400000);
    const status = days < 7 ? 'fail' : days < 21 ? 'warn' : 'ok';
    return [{ id: 'certificate', status, title: `Certyfikat wygasa za ${days} dni`, detail: { wygasa: new Date(soonest).toISOString() } }];
  } catch (error) {
    return [{ id: 'certificate', status: 'warn', title: 'Nie udało się odczytać certyfikatu', detail: { blad: String(error.message ?? error) } }];
  }
}

const IGNORED_SCHEMES = ['chrome-extension:', 'moz-extension:', 'safari-web-extension:', 'safari-extension:', 'about:', 'data:', 'blob:'];

export function extractDomain(blockedUrl) {
  const value = String(blockedUrl ?? '').trim();
  if (!value) return null;
  if (IGNORED_SCHEMES.some((s) => value.startsWith(s))) return null;
  if (['inline', 'eval', 'self', 'unsafe-inline', 'unsafe-eval'].includes(value)) return null;
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Nowe domeny w raportach CSP z ostatniej doby. Domena, której wcześniej
 * nie było, to najwcześniejszy sygnał wstrzyknięcia, jaki ta warstwa daje.
 */
export async function probeCspViolations(target, env, budget) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) {
    return skip('csp-domains', 'Pominięte: brak CF_API_TOKEN lub CF_ACCOUNT_ID');
  }
  if (!budget.take()) return skip('csp-domains', 'Pominięte: wyczerpany budżet podżądań');

  const dataset = env.CSP_DATASET || 'csp_reports';
  const host = target.host.replace(/'/g, '');
  const sql = `SELECT blob3 AS blocked, sum(_sample_interval) AS hits
               FROM ${dataset}
               WHERE timestamp > NOW() - INTERVAL '1' DAY AND blob1 = '${host}'
               GROUP BY blocked ORDER BY hits DESC LIMIT 200`;

  try {
    const json = await api(env, `/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: sql,
    });

    const rows = Array.isArray(json?.data) ? json.data : [];
    const domains = new Map();
    for (const row of rows) {
      const domain = extractDomain(row.blocked);
      if (domain) domains.set(domain, (domains.get(domain) ?? 0) + Number(row.hits ?? 0));
    }

    const key = `baseline:csp-domains:${target.host}`;
    let known = [];
    try {
      known = (await env.MONITOR_STATE?.get(key, { type: 'json' })) ?? [];
    } catch {
      known = [];
    }
    const knownSet = new Set(Array.isArray(known) ? known : []);
    const fresh = [...domains.keys()].filter((d) => !knownSet.has(d));

    if (env.MONITOR_STATE) {
      const merged = [...new Set([...knownSet, ...domains.keys()])].slice(0, 500);
      await env.MONITOR_STATE.put(key, JSON.stringify(merged));
    }

    if (!rows.length) {
      return [{
        id: 'csp-domains',
        status: 'info',
        title: 'Brak raportów CSP z ostatniej doby',
        detail: { uwaga: 'sprawdź wynik sondy csp-pipeline — cisza zwykle znaczy zepsuty kanał' },
      }];
    }
    if (!fresh.length) {
      return [{ id: 'csp-domains', status: 'ok', title: `Brak nowych domen w raportach (${domains.size} znanych)`, detail: null }];
    }
    return [{
      id: 'csp-domains',
      status: 'warn',
      title: `Nowe domeny w raportach CSP: ${fresh.length}`,
      detail: { domeny: fresh.slice(0, 25).map((d) => ({ domena: d, trafienia: domains.get(d) })) },
    }];
  } catch (error) {
    return [{ id: 'csp-domains', status: 'warn', title: 'Nie udało się odczytać raportów CSP', detail: { blad: String(error.message ?? error) } }];
  }
}
