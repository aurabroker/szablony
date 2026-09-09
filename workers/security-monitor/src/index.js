/**
 * Monitor bezpieczeństwa — Worker uruchamiany z Cron Triggers.
 *
 * Nie stoi na ścieżce żądań produkcyjnych. Cyklicznie sprawdza stan hostów,
 * zapisuje raport do KV, a alarmuje wyłącznie o zmianach względem poprzedniego
 * przebiegu. Endpoint HTTP służy do podejrzenia raportu i wymaga tokenu.
 *
 * wrangler.jsonc: patrz plik obok. Sekrety:
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

const STATE_KEY = 'state:last';
const LATEST_KEY = 'report:latest';
const HISTORY_TTL = 60 * 60 * 24 * 30; // 30 dni

/* ------------------------------------------------------------------ */
/* Przebieg                                                            */
/* ------------------------------------------------------------------ */

async function auditTarget(target, env, budget, timeoutMs) {
  const kv = env.MONITOR_STATE;
  const probes = [
    probeHeaders(target, budget, timeoutMs),
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

export async function runAudit(env, trigger = 'manual') {
  const startedAt = Date.now();
  const config = await loadConfig(env);
  const budget = new Budget(config.maxSubrequests);

  const targets = [];
  for (const target of config.targets) {
    if (!target.enabled) continue;
    targets.push(await auditTarget(target, env, budget, config.requestTimeoutMs));
  }

  const allFindings = targets.flatMap((t) => t.findings);
  const report = {
    generatedAt: new Date(startedAt).toISOString(),
    durationMs: Date.now() - startedAt,
    trigger,
    subrequestsUsed: budget.used,
    config: { maxSubrequests: config.maxSubrequests, problems: config.problems ?? [] },
    targets,
    summary: {
      hosts: targets.length,
      counts: summarize(allFindings).counts,
      worst: worst(targets.map((t) => t.summary.worst)),
    },
  };

  return { report, config };
}

async function persistAndNotify(env, report, config, { digest = false } = {}) {
  const kv = env.MONITOR_STATE;
  let previous = {};
  if (kv) {
    try {
      previous = (await kv.get(STATE_KEY, { type: 'json' })) ?? {};
    } catch {
      previous = {};
    }
  }

  const next = toState(report.targets);
  const diff = diffStates(previous, next);
  report.diff = diff;

  if (kv) {
    const stamp = report.generatedAt.replace(/[:.]/g, '-');
    await Promise.all([
      kv.put(LATEST_KEY, JSON.stringify(report)),
      kv.put(`report:${stamp}`, JSON.stringify(report), { expirationTtl: HISTORY_TTL }),
      kv.put(STATE_KEY, JSON.stringify(next)),
    ]);
  }

  if (digest || shouldAlert(diff, config)) {
    const text = buildAlertText(report, diff, { digest });
    report.alert = await sendAlert(env, text, report);
  } else {
    report.alert = { sent: false, reason: 'brak zmian wartych alertu' };
  }

  return report;
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
            await sendAlert(
              env,
              `[Monitor] Przebieg zakończony wyjątkiem: ${String(error?.message ?? error)}`,
              { generatedAt: new Date().toISOString(), summary: {}, targets: [] },
            );
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
      const stored = await env.MONITOR_STATE?.get(LATEST_KEY, { type: 'json' });
      if (!stored) {
        return new Response('Brak zapisanego raportu. Uruchom przebieg: POST /run\n', {
          status: 404,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        });
      }
      return new Response(renderReportHtml(stored), {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'x-robots-tag': 'noindex, nofollow',
        },
      });
    }

    if (url.pathname === '/report.json') {
      const stored = await env.MONITOR_STATE?.get(LATEST_KEY, { type: 'json' });
      return stored ? json(stored) : json({ error: 'brak zapisanego raportu' }, 404);
    }

    if (url.pathname === '/config') {
      const config = await loadConfig(env);
      return json(config);
    }

    if (url.pathname === '/run') {
      if (request.method !== 'POST') {
        return new Response(null, { status: 405, headers: { allow: 'POST' } });
      }
      const { report, config } = await runAudit(env, 'manual');
      await persistAndNotify(env, report, config, { digest: url.searchParams.get('digest') === '1' });
      return json(report);
    }

    return new Response('Nie znaleziono.\n', {
      status: 404,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  },
};
