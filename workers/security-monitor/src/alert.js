/**
 * Wysyłka alertów. Jeden webhook, format zgodny naraz ze Slackiem (`text`)
 * i Discordem (`content`), z pełnym raportem w polu `report` dla wszystkiego
 * innego. Brak ALERT_WEBHOOK oznacza tryb cichy — raport i tak leży w KV.
 */

import { RANK } from './checks.js';

const ICON = { ok: 'OK', info: 'i', skip: '-', warn: 'UWAGA', fail: 'BŁĄD' };

export function buildAlertText(report, diff, { digest = false } = {}) {
  const lines = [];
  const nagłówek = digest ? 'Przegląd dobowy' : 'Zmiana stanu bezpieczeństwa';
  lines.push(`[${nagłówek}] ${report.summary.hosts} hostów, stan: ${report.summary.worst.toUpperCase()}`);

  if (diff.nowe.length) {
    lines.push('', `Nowe problemy (${diff.nowe.length}):`);
    for (const item of diff.nowe.slice(0, 15)) lines.push(`  ${ICON[item.status]} ${item.key}`);
  }
  if (diff.pogorszone.length) {
    lines.push('', `Pogorszenia (${diff.pogorszone.length}):`);
    for (const item of diff.pogorszone.slice(0, 15)) {
      lines.push(`  ${ICON[item.status]} ${item.key} (było: ${item.poprzednio})`);
    }
  }
  if (diff.naprawione.length) {
    lines.push('', `Naprawione (${diff.naprawione.length}):`);
    for (const item of diff.naprawione.slice(0, 15)) lines.push(`  ${item.key}`);
  }

  if (digest) {
    lines.push('', 'Stan hostów:');
    for (const target of report.targets) {
      const c = target.summary.counts;
      lines.push(`  ${target.host}: ${target.summary.worst.toUpperCase()} (błędy ${c.fail}, ostrzeżenia ${c.warn})`);
    }
  }

  return lines.join('\n');
}

/** Czy jest o czym w ogóle informować. */
export function shouldAlert(diff, config) {
  const próg = RANK[config.alerts.minStatus] ?? RANK.warn;
  const istotne = [...diff.nowe, ...diff.pogorszone].some((i) => (RANK[i.status] ?? 0) >= próg);
  const naprawy = config.alerts.notifyOnRecovery && diff.naprawione.length > 0;
  return istotne || naprawy;
}

export async function sendAlert(env, text, report) {
  if (!env.ALERT_WEBHOOK) return { sent: false, reason: 'brak ALERT_WEBHOOK' };
  try {
    const response = await fetch(env.ALERT_WEBHOOK, {
      method: 'POST',
      signal: AbortSignal.timeout(10000),
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        text, // Slack, Mattermost
        content: text, // Discord
        username: 'security-monitor',
        report: {
          generatedAt: report.generatedAt,
          summary: report.summary,
          targets: report.targets.map((t) => ({ host: t.host, worst: t.summary.worst, counts: t.summary.counts })),
        },
      }),
    });
    return { sent: response.ok, status: response.status };
  } catch (error) {
    return { sent: false, reason: String(error?.message ?? error) };
  }
}
