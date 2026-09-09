/** Renderowanie raportu do HTML. Bez zasobów zewnętrznych, bez skryptów. */

const escape = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const LABEL = { ok: 'ok', info: 'info', skip: 'pominięte', warn: 'ostrzeżenie', fail: 'błąd' };

function detailToText(detail) {
  if (detail === null || detail === undefined) return '';
  return JSON.stringify(detail, null, 1).replace(/[{}"]/g, '').replace(/\n\s*/g, ' ').trim();
}

export function renderReportHtml(report) {
  const rows = report.targets
    .map((target) => {
      const findings = target.findings
        .map(
          (f) => `<tr class="s-${escape(f.status)}">
            <td><span class="pill p-${escape(f.status)}">${escape(LABEL[f.status] ?? f.status)}</span></td>
            <td><code>${escape(f.id)}</code></td>
            <td>${escape(f.title)}<div class="detail">${escape(detailToText(f.detail))}</div></td>
          </tr>`,
        )
        .join('');
      const c = target.summary.counts;
      return `<section>
        <h2>${escape(target.host)} <span class="pill p-${escape(target.summary.worst)}">${escape(LABEL[target.summary.worst])}</span></h2>
        <p class="counts">błędy: ${c.fail} · ostrzeżenia: ${c.warn} · info: ${c.info} · ok: ${c.ok} · pominięte: ${c.skip}</p>
        <table><tbody>${findings}</tbody></table>
      </section>`;
    })
    .join('');

  const problems = report.config.problems.length
    ? `<div class="banner">Uwagi do konfiguracji: ${escape(report.config.problems.join('; '))}</div>`
    : '';

  return `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Monitor bezpieczeństwa</title>
<style>
:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1a1a19;--mut:#6b6b68;--line:#e3e3e0;--card:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#17171a;--fg:#ececea;--mut:#9a9a96;--line:#2e2e33;--card:#1e1e22}}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif}
main{max-width:960px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:16px;margin:0 0 4px;display:flex;gap:8px;align-items:center}
.meta,.counts{color:var(--mut);margin:0 0 12px;font-size:13px}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin:16px 0}
table{width:100%;border-collapse:collapse}
td{padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}
td:first-child{width:96px}td:nth-child(2){width:200px}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut);word-break:break-all}
.detail{color:var(--mut);font-size:12px;margin-top:2px;word-break:break-word}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.p-fail{background:#fdecec;color:#8c1d1d;border-color:#f3bcbc}
.p-warn{background:#fdf4e3;color:#7a5406;border-color:#f0dcae}
.p-ok{background:#eaf6ed;color:#1f5c33;border-color:#bfe0c9}
.p-info,.p-skip{background:transparent;color:var(--mut)}
@media(prefers-color-scheme:dark){
.p-fail{background:#3a1d1d;color:#f3b6b6;border-color:#5d2b2b}
.p-warn{background:#3a2f18;color:#f0d79b;border-color:#5c4a24}
.p-ok{background:#1c3325;color:#a9d9ba;border-color:#2c5039}}
.banner{background:#fdf4e3;color:#7a5406;border:1px solid #f0dcae;border-radius:8px;padding:10px 14px;margin:12px 0}
@media(prefers-color-scheme:dark){.banner{background:#3a2f18;color:#f0d79b;border-color:#5c4a24}}
</style></head><body><main>
<h1>Monitor bezpieczeństwa</h1>
<p class="meta">Przebieg: ${escape(report.generatedAt)} · wyzwalacz: ${escape(report.trigger)} · czas: ${escape(report.durationMs)} ms · podżądania: ${escape(report.subrequestsUsed)}/${escape(report.config.maxSubrequests)} · stan ogólny: <strong>${escape(LABEL[report.summary.worst] ?? report.summary.worst)}</strong></p>
${problems}
${rows || '<section><p>Brak skonfigurowanych celów. Uzupełnij klucz <code>monitor:config</code> w KV.</p></section>'}
</main></body></html>`;
}
