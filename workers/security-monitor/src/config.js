/**
 * Konfiguracja monitora. Źródłem prawdy jest KV (klucz `monitor:config`),
 * a zmienna MONITOR_CONFIG z wrangler.jsonc służy jako wartość startowa,
 * zanim ktokolwiek cokolwiek zapisze do KV.
 *
 * Każda wartość z zewnątrz przechodzi przez sanitizeConfig. Zły wpis w KV
 * ma dawać pominięty cel, a nie wyjątek w handlerze cron.
 */

import { DEFAULT_EXPECT, DEFAULT_PROBE_PATHS } from './checks.js';

export const CONFIG_KEY = 'monitor:config';

export const DEFAULT_CONFIG = {
  targets: [],
  // ile podżądań wolno zużyć na jeden przebieg; plan darmowy daje 50
  maxSubrequests: 45,
  // ile hostów bierze jeden przebieg; 0 = wszystkie. Przy wielu hostach
  // rozkładamy audyt na kolejne tury, żeby zmieścić się w limicie podżądań.
  hostsPerRun: 4,
  requestTimeoutMs: 10000,
  // cron, po którym wysyłamy pełne podsumowanie niezależnie od zmian
  digestCron: '0 6 * * *',
  alerts: {
    // najniższa waga, przy której w ogóle zawracamy komuś głowę
    minStatus: 'warn',
    notifyOnRecovery: true,
  },
};

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

function asStringArray(value, fallback = []) {
  if (!Array.isArray(value)) return fallback;
  return value.filter((v) => typeof v === 'string' && v.length > 0).map((v) => v.trim());
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

export function normalizeTarget(raw) {
  const source = typeof raw === 'string' ? { host: raw } : raw;
  if (!isObject(source)) return null;

  const host = String(source.host ?? '').trim().toLowerCase();
  if (!HOSTNAME.test(host)) return null;

  const expect = isObject(source.expect) ? source.expect : {};
  const normalizedExpect = { ...DEFAULT_EXPECT };
  for (const key of Object.keys(DEFAULT_EXPECT)) {
    if (!(key in expect)) continue;
    const value = expect[key];
    if (key === 'csp') {
      normalizedExpect.csp = ['enforce', 'report-only', 'any', 'none'].includes(value)
        ? value
        : DEFAULT_EXPECT.csp;
    } else if (key === 'hstsMinAge') {
      normalizedExpect.hstsMinAge = clampInt(value, 0, 63072000, DEFAULT_EXPECT.hstsMinAge);
    } else if (key === 'cookiesAllowedWithoutHttpOnly') {
      normalizedExpect[key] = asStringArray(value);
    } else if (typeof DEFAULT_EXPECT[key] === 'boolean') {
      normalizedExpect[key] = Boolean(value);
    } else {
      normalizedExpect[key] = value === null || typeof value === 'string' ? value : DEFAULT_EXPECT[key];
    }
  }

  return {
    host,
    zone: typeof source.zone === 'string' ? source.zone.trim().toLowerCase() : null,
    // Podany wprost identyfikator strefy oszczędza wyszukiwania po nazwie,
    // a tym samym uprawnienia Zone Read na tokenie.
    zoneId: /^[0-9a-f]{32}$/.test(String(source.zoneId ?? '')) ? source.zoneId : null,
    expect: normalizedExpect,
    probePaths: asStringArray(source.probePaths, DEFAULT_PROBE_PATHS).filter((p) => p.startsWith('/')),
    assets: asStringArray(source.assets).filter((u) => u.startsWith('https://')),
    cspReportPath:
      typeof source.cspReportPath === 'string' && source.cspReportPath.startsWith('/')
        ? source.cspReportPath
        : '/__csp-report',
    // Sonda kanału raportów ma sens tylko tam, gdzie stoi Worker nagłówkowy.
    // Domyślnie wyłączona, żeby nie produkować 404 jako fałszywych błędów.
    checkCspPipeline: source.checkCspPipeline === true,
    checkScripts: source.checkScripts !== false,
    checkHttpRedirect: source.checkHttpRedirect !== false,
    checkSecurityTxt: source.checkSecurityTxt !== false,
    enabled: source.enabled !== false,
  };
}

export function sanitizeConfig(raw) {
  if (!isObject(raw)) return { ...DEFAULT_CONFIG, problems: ['konfiguracja nie jest obiektem'] };

  const problems = [];
  const targets = [];
  const rawTargets = Array.isArray(raw.targets) ? raw.targets : [];
  for (const [index, entry] of rawTargets.entries()) {
    const target = normalizeTarget(entry);
    if (target) targets.push(target);
    else problems.push(`targets[${index}]: pominięty, brak poprawnego hosta`);
  }
  if (!rawTargets.length) problems.push('lista targets jest pusta');

  const alerts = isObject(raw.alerts) ? raw.alerts : {};

  return {
    targets,
    maxSubrequests: clampInt(raw.maxSubrequests, 5, 900, DEFAULT_CONFIG.maxSubrequests),
    hostsPerRun: clampInt(raw.hostsPerRun, 0, 200, DEFAULT_CONFIG.hostsPerRun),
    requestTimeoutMs: clampInt(raw.requestTimeoutMs, 1000, 30000, DEFAULT_CONFIG.requestTimeoutMs),
    digestCron:
      typeof raw.digestCron === 'string' ? raw.digestCron.trim() : DEFAULT_CONFIG.digestCron,
    alerts: {
      minStatus: ['info', 'warn', 'fail'].includes(alerts.minStatus)
        ? alerts.minStatus
        : DEFAULT_CONFIG.alerts.minStatus,
      notifyOnRecovery: alerts.notifyOnRecovery !== false,
    },
    problems,
  };
}

export async function loadConfig(env) {
  let raw = null;

  if (env.MONITOR_STATE) {
    try {
      raw = await env.MONITOR_STATE.get(CONFIG_KEY, { type: 'json' });
    } catch {
      // awaria KV nie może zatrzymać przebiegu — spadamy na wartość z wrangler.jsonc
    }
  }

  if (!raw && typeof env.MONITOR_CONFIG === 'string') {
    try {
      raw = JSON.parse(env.MONITOR_CONFIG);
    } catch {
      return { ...DEFAULT_CONFIG, problems: ['MONITOR_CONFIG nie jest poprawnym JSON-em'] };
    }
  }

  return sanitizeConfig(raw ?? {});
}
