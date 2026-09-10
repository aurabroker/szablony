/**
 * Monitor bezpieczeństwa — Worker uruchamiany z Cron Triggers.
 *
 * Nie stoi na ścieżce żądań produkcyjnych. Cyklicznie sprawdza stan hostów,
 * zapisuje wynik per host i alarmuje wyłącznie o zmianach względem
 * poprzedniego sprawdzenia tego samego hosta.
 *
 * Przy większej liczbie hostów jeden przebieg bierze kolejną turę
 * (`hostsPerRun`), bo platforma limituje liczbę podżądań na wywołanie.
 *
 * Sekrety:
 *   MONITOR_TOKEN   — wymagany, chroni endpoint HTTP
 *   ALERT_WEBHOOK   — opcjonalny, Slack / Discord / dowolny odbiorca JSON
 *   CF_API_TOKEN    — opcjonalny, tylko odczyt: certyfikaty + Analytics Engine
 *   CF_ACCOUNT_ID   — opcjonalny, potrzebny do odczytu raportów CSP
 */

import { summarize, toState, diffStates, worst } from './checks.js';
import { loadConfig } from './config.js';
import { buildAlertText, sendAlert, shouldAlert } from './alert.js';
import { renderReportHtml } from './report.js';
import { probeCertificate, probeCspViolations } from './cfapi.js';
import {
  Budget,
  probeAllowedMethods,
  probeAssetHashes,
  probeCspPipeline,
  probeExposedPaths,
  probeHeaders,
  probeHttpRedirect,
  probeSecurityTxt,
} from './probes.js';

const CURSOR_KEY = 'state:cursor';
const hostKey = (host) => `host:${host}`;

/* ------------------------------------------------------------------ */
/* Przebieg                                                            */
/* ------------------------------------------------------------------ */

async function auditTarget(target, env, budget, timeoutMs) {
  const kv = env.MONITOR_STATE;
  const probes = [
    probeHeaders(target, budget, timeoutMs, kv),
    probeHttpRedirect(target, budget, timeoutMs),
    probeExposedPaths(target, budget, timeoutMs),
    probeAllowedMethods(target, budget, timeoutMs),
    probeSecurityTxt(target, budget, timeoutMs),
    probeCspPipeline(target, budget, timeoutMs),
    probeAssetHashes(target, budget, timeoutMs, kv),
    probeCertificate(target, env, budget),
    probeCspViolations(target, env, budget),
  ];

  // Awaria pojedynczej sondy nie może przerwać audytu pozostałych.
  const settled = await Promise.allSettled(probes);
  const findings = [];
  for (const [index, result] of settled.entries()) {
    if (result.status === 'fulfilled') findings.push(...result.value);
    else {
      findings.push({
        id: `probe-${index}`,
        status: 'warn',
        title: 'Sonda zakończyła się wyjątkiem',
        detail: { blad: String(result.reason?.message ?? result.reason) },
      });
    }
  }

  return { host: target.host, findings, summary: summarize(findings) };
}

/** Kolejna tura hostów, w kółko po liście celów. */
export function selectSlice(targets, cursor, hostsPerRun) {
  if (!hostsPerRun || hostsPerRun >= targets.length) return { slice: targets, nextCursor: 0 };
  const start = ((cursor % targets.length) + targets.length) % targets.length;
  const slice = [];
  for (let i = 0; i < hostsPerRun; i += 1) slice.push(targets[(start + i) % targets.length]);
  return { slice, nextCursor: (start + hostsPerRun) % targets.length };
}

export async function runAudit(env, trigger = 'manual', { all = false } = {}) {
  const startedAt = Date.now();
  const config = await loadConfig(env);
  const budget = new Budget(config.maxSubrequests);
  const enabled = config.targets.filter((t) => t.enabled);

  let cursor = 0;
  if (!all && env.MONITOR_STATE) {
    const stored = await env.MONITOR_STATE.get(CURSOR_KEY);
    cursor = Number(stored) || 0;
  }
  const { slice, nextCursor } = selectSlice(enabled, cursor, all ? 0 : config.hostsPerRun);

  const targets = [];
  for (const target of slice) {
    targets.push(await auditTarget(target, env, budget, config.requestTimeoutMs));
  }

  if (!all && env.MONITOR_STATE) await env.MONITOR_STATE.put(CURSOR_KEY, String(nextCursor));

  const allFindings = targets.flatMap((t) => t.findings);
  const report = {
    generatedAt: new Date(startedAt).toISOString(),
    durationMs: Date.now() - startedAt,
    trigger,
    subrequestsUsed: budget.used,
    config: {
      maxSubrequests: config.maxSubrequests,
      hostsPerRun: all ? 0 : config.hostsPerRun,
      celeLacznie: enabled.length,
      problems: config.problems ?? [],
    },
    targets,
    summary: {
      hosts: targets.length,
      counts: summarize(allFindings).counts,
      worst: worst(targets.map((t) => t.summary.worst)),
    },
  };

  return { report, config };
}

/**
 * Zapis wyniku i alert. Stan trzymamy per host, więc tura obejmująca cztery
 * hosty nie kasuje wiedzy o pozostałych.
 */
async function persistAndNotify(env, report, config, { digest = false } = {}) {
  const kv = env.MONITOR_STATE;
  const diff = { nowe: [], pogorszone: [], naprawione: [] };

  for (const target of report.targets) {
    let previous = null;
    if (kv) {
      try {
        previous = await kv.get(hostKey(target.host), { type: 'json' });
      } catch {
        previous = null;
      }
    }
    const nextState = toState([target]);
    const partial = diffStates(previous?.state ?? {}, nextState);
    diff.nowe.push(...partial.nowe);
    diff.pogorszone.push(...partial.pogorszone);
    diff.naprawione.push(...partial.naprawione);

    if (kv) {
      await kv.put(
        hostKey(target.host),
        JSON.stringify({ ...target, state: nextState, checkedAt: report.generatedAt }),
      );
    }
  }

  report.diff = diff;

  const view = digest ? await loadFullView(env, config) : report;
  if (digest || shouldAlert(diff, config)) {
    report.alert = await sendAlert(env, buildAlertText(view, diff, { digest }), view, { digest });
  } else {
    report.alert = { sent: false, reason: 'brak zmian wartych alertu' };
  }

  return report;
}

/** Widok wszystkich hostów, złożony z ostatnich znanych wyników. */
export async function loadFullView(env, config) {
  const kv = env.MONITOR_STATE;
  const records = kv
    ? await Promise.all(
        config.targets.map(async (t) => {
          try {
            return await kv.get(hostKey(t.host), { type: 'json' });
          } catch {
            return null;
          }
        }),
      )
    : [];

  const targets = [];
  for (const [index, record] of records.entries()) {
    const host = config.targets[index].host;
    if (record) targets.push({ host, findings: record.findings, summary: record.summary, checkedAt: record.checkedAt });
    else {
      targets.push({
        host,
        findings: [{ id: 'pending', status: 'skip', title: 'Host czeka na pierwsze sprawdzenie', detail: null }],
        summary: summarize([{ status: 'skip' }]),
        checkedAt: null,
      });
    }
  }

  const checked = targets.map((t) => t.checkedAt).filter(Boolean).sort();
  return {
    generatedAt: checked[checked.length - 1] ?? new Date().toISOString(),
    durationMs: 0,
    trigger: 'widok zbiorczy',
    subrequestsUsed: 0,
    config: {
      maxSubrequests: config.maxSubrequests,
      hostsPerRun: config.hostsPerRun,
      celeLacznie: config.targets.length,
      problems: config.problems ?? [],
    },
    targets,
    summary: {
      hosts: targets.length,
      counts: summarize(targets.flatMap((t) => t.findings)).counts,
      worst: worst(targets.map((t) => t.summary.worst)),
    },
  };
}

/* ------------------------------------------------------------------ */
/* Endpoint HTTP                                                       */
/* ------------------------------------------------------------------ */

function timingSafeEqual(a, b) {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

function authorize(request, env) {
  if (!env.MONITOR_TOKEN) {
    return new Response('Brak sekretu MONITOR_TOKEN — endpoint wyłączony.\n', {
      status: 503,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }
  const url = new URL(request.url);
  const header = request.headers.get('authorization') ?? '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
  const supplied = bearer || url.searchParams.get('token') || '';
  if (!supplied || !timingSafeEqual(supplied, env.MONITOR_TOKEN)) {
    return new Response('Brak autoryzacji.\n', {
      status: 401,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'www-authenticate': 'Bearer' },
    });
  }
  return null;
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-robots-tag': 'noindex, nofollow',
    },
  });

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        try {
          const { report, config } = await runAudit(env, `cron:${event.cron}`);
          const digest = event.cron === config.digestCron;
          await persistAndNotify(env, report, config, { digest });
        } catch (error) {
          // Ostatnia linia obrony: monitor, który cicho umiera, jest gorszy niż brak monitora.
          console.error('przebieg monitora nie powiódł się', error);
          if (env.ALERT_WEBHOOK) {
            await sendAlert(env, `[Monitor] Przebieg zakończony wyjątkiem: ${String(error?.message ?? error)}`, {
              generatedAt: new Date().toISOString(),
              summary: { hosts: 0, worst: 'fail' },
              targets: [],
            });
          }
        }
      })(),
    );
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/health') return json({ ok: true });

    const denied = authorize(request, env);
    if (denied) return denied;

    if (url.pathname === '/' || url.pathname === '/report') {
      const config = await loadConfig(env);
      const view = await loadFullView(env, config);
      return new Response(renderReportHtml(view), {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'x-robots-tag': 'noindex, nofollow',
        },
      });
    }

    if (url.pathname === '/report.json') {
      const config = await loadConfig(env);
      return json(await loadFullView(env, config));
    }

    if (url.pathname === '/config') {
      return json(await loadConfig(env));
    }

    // Akceptacja nowego stanu skryptów: kasujemy wzorzec, kolejny przebieg
    // zapisze aktualną listę jako obowiązującą.
    if (url.pathname === '/accept') {
      if (request.method !== 'POST') {
        return new Response(null, { status: 405, headers: { allow: 'POST' } });
      }
      const host = (url.searchParams.get('host') ?? '').trim().toLowerCase();
      if (!host) return json({ error: 'podaj ?host=' }, 400);
      await env.MONITOR_STATE?.delete(`baseline:scripts:${host}`);
      return json({ ok: true, host, info: 'wzorzec skryptów skasowany, następny przebieg zapisze nowy' });
    }

    if (url.pathname === '/run') {
      if (request.method !== 'POST') {
        return new Response(null, { status: 405, headers: { allow: 'POST' } });
      }
      const all = url.searchParams.get('all') === '1';
      const { report, config } = await runAudit(env, 'manual', { all });
      await persistAndNotify(env, report, config, { digest: url.searchParams.get('digest') === '1' });
      return json(report);
    }

    return new Response('Nie znaleziono.\n', {
      status: 404,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  },
};
