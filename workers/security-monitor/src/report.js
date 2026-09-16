/**
 * Raport jako macierz: domeny w wierszach, grupy kontroli w kolumnach.
 * Każda komórka to dioda z najgorszym stanem w danej grupie, a kliknięcie
 * wiersza rozwija pełną listę ustaleń.
 *
 * Bez zasobów zewnętrznych. Jedyny skrypt obsługuje rozwijanie wierszy
 * i filtr, obie rzeczy działają na atrybucie hidden.
 */

const escape = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const RANG = { ok: 0, info: 1, skip: 1, warn: 2, fail: 3 };
const ETYKIETA = { ok: 'w porządku', info: 'informacja', skip: 'pominięte', warn: 'zastrzeżenie', fail: 'błąd' };

/**
 * Grupy kontroli. Kolejność kolumn idzie od rzeczy, które psują stronę,
 * do tych, które psują reputację.
 */
const KOLUMNY = [
  { id: 'dostep', label: 'Dostęp', opis: 'czy strona odpowiada', pasuje: (id) => id === 'reachable' },
  { id: 'https', label: 'HTTPS', opis: 'przekierowanie z portu 80', pasuje: (id) => id === 'http-redirect' },
  { id: 'csp', label: 'CSP', opis: 'polityka bezpieczeństwa treści', pasuje: (id) => ['csp', 'csp-nonce', 'csp-pipeline', 'csp-domains'].includes(id) },
  { id: 'ramki', label: 'Ramki', opis: 'ochrona przed clickjackingiem', pasuje: (id) => id === 'frame' },
  { id: 'hsts', label: 'HSTS', opis: 'wymuszenie szyfrowania', pasuje: (id) => id === 'hsts' },
  { id: 'naglowki', label: 'Nagłówki', opis: 'nosniff, referrer, uprawnienia, wycieki', pasuje: (id) => ['nosniff', 'referrer', 'permissions', 'coop', 'corp', 'leaky', 'server'].includes(id) },
  { id: 'ciasteczka', label: 'Ciastka', opis: 'flagi ciasteczek', pasuje: (id) => id === 'cookies' },
  { id: 'pliki', label: 'Pliki', opis: 'wrażliwe ścieżki, metody, security.txt', pasuje: (id) => id.startsWith('path:') || ['methods', 'security-txt'].includes(id) },
  { id: 'skrypty', label: 'Skrypty', opis: 'inwentarz skryptów i dryf plików', pasuje: (id) => id.startsWith('asset:') || ['scripts', 'scripts-inline'].includes(id) },
  { id: 'tresc', label: 'Treść', opis: 'wstrzyknięty spam i ukryte odnośniki', pasuje: (id) => ['spam-slowa', 'spam-ukryte', 'linki'].includes(id) },
  { id: 'poczta', label: 'Poczta', opis: 'SPF, DMARC, DKIM', pasuje: (id) => ['spf', 'dmarc', 'dkim', 'dns'].includes(id) },
  { id: 'proxy', label: 'Proxy', opis: 'czy ruch idzie przez Cloudflare', pasuje: (id) => id === 'proxy' },
  { id: 'cert', label: 'Cert', opis: 'termin ważności certyfikatu', pasuje: (id) => id === 'certificate' },
];

const najgorszy = (statusy) => statusy.reduce((a, b) => ((RANG[b] ?? 0) > (RANG[a] ?? 0) ? b : a), 'ok');

function detalToLinie(detail) {
  if (detail === null || detail === undefined) return [];
  if (typeof detail !== 'object') return [String(detail)];
  return Object.entries(detail).map(([klucz, wartosc]) => {
    const tekst = Array.isArray(wartosc)
      ? wartosc.map((v) => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(', ')
      : typeof wartosc === 'object'
        ? JSON.stringify(wartosc)
        : String(wartosc);
    return `${klucz.replace(/_/g, ' ')}: ${tekst}`;
  });
}

function komorka(findings) {
  if (!findings.length) return { status: 'brak', tytul: 'brak danych' };
  const status = najgorszy(findings.map((f) => f.status));
  const istotne = findings.filter((f) => f.status === status);
  return { status, tytul: istotne.map((f) => f.title).join(' • ') };
}

function wierszSzczegolow(target, index, kolumny) {
  const sekcje = KOLUMNY.map((kol) => {
    const lista = kolumny[kol.id];
    if (!lista.length) return '';
    const pozycje = lista
      .sort((a, b) => (RANG[b.status] ?? 0) - (RANG[a.status] ?? 0))
      .map((f) => {
        const linie = detalToLinie(f.detail);
        return `<li>
          <span class="pill p-${escape(f.status)}">${escape(ETYKIETA[f.status] ?? f.status)}</span>
          <span class="tytul">${escape(f.title)}</span>
          <code>${escape(f.id)}</code>
          ${linie.length ? `<div class="detal">${linie.map((l) => escape(l)).join('<br>')}</div>` : ''}
        </li>`;
      })
      .join('');
    return `<section><h3>${escape(kol.label)} <small>${escape(kol.opis)}</small></h3><ul>${pozycje}</ul></section>`;
  }).join('');

  return `<tr class="szczegoly" id="d${index}" hidden>
    <td colspan="${KOLUMNY.length + 2}"><div class="rozwiniecie">${sekcje}</div></td>
  </tr>`;
}

export function renderReportHtml(report) {
  const wiersze = report.targets
    .map((target, index) => {
      const kolumny = Object.fromEntries(
        KOLUMNY.map((kol) => [kol.id, target.findings.filter((f) => kol.pasuje(f.id))]),
      );
      const komorki = KOLUMNY.map((kol) => {
        const { status, tytul } = komorka(kolumny[kol.id]);
        return `<td class="k"><span class="dioda d-${escape(status)}" title="${escape(kol.label)}: ${escape(tytul)}"></span></td>`;
      }).join('');

      const stan = target.summary?.worst ?? 'brak';
      const kiedy = target.checkedAt ? String(target.checkedAt).slice(11, 16) : '—';

      return `<tr class="wiersz s-${escape(stan)}" data-stan="${escape(stan)}" onclick="przelacz(${index})" tabindex="0" onkeydown="if(event.key==='Enter')przelacz(${index})">
        <td class="host"><span class="strzalka" id="s${index}">▸</span> ${escape(target.host)}</td>
        ${komorki}
        <td class="czas">${escape(kiedy)}</td>
      </tr>
      ${wierszSzczegolow(target, index, kolumny)}`;
    })
    .join('');

  const naglowki = KOLUMNY.map((kol) => `<th class="k" title="${escape(kol.opis)}">${escape(kol.label)}</th>`).join('');
  const c = report.summary?.counts ?? {};
  const problemy = report.config?.problems ?? [];

  return `<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Monitor bezpieczeństwa</title>
<style>
:root{color-scheme:light dark;
 --bg:#fbfbfa;--fg:#1a1a19;--mut:#6b6b68;--line:#e3e3e0;--card:#fff;--row:#f6f6f4;
 --ok:#1f9d55;--warn:#d98c00;--fail:#d13b2e;--brak:#c9c9c5}
@media(prefers-color-scheme:dark){:root{
 --bg:#17171a;--fg:#ececea;--mut:#9a9a96;--line:#2e2e33;--card:#1e1e22;--row:#232328;
 --ok:#3ecf7e;--warn:#f0b64a;--fail:#f26a5c;--brak:#4a4a50}}
*{box-sizing:border-box}
body{margin:0;padding:20px;background:var(--bg);color:var(--fg);
 font:14px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif}
main{max-width:1200px;margin:0 auto}
h1{font-size:19px;margin:0 0 4px}
.meta{color:var(--mut);font-size:13px;margin:0 0 14px}
.pasek{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin:0 0 12px;font-size:13px}
.legenda{display:flex;gap:12px;align-items:center;color:var(--mut)}
.legenda span{display:flex;gap:5px;align-items:center}
label.filtr{display:flex;gap:6px;align-items:center;cursor:pointer;color:var(--mut)}
.ramka{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{position:sticky;top:0;background:var(--card);text-align:left;padding:10px 8px;
 border-bottom:1px solid var(--line);font-weight:600;white-space:nowrap;z-index:2}
td{padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:middle}
th.k,td.k{text-align:center;width:52px}
.wiersz{cursor:pointer}
.wiersz:hover{background:var(--row)}
.wiersz:focus{outline:2px solid var(--mut);outline-offset:-2px}
.host{font-weight:500;white-space:nowrap}
.czas{color:var(--mut);text-align:right;white-space:nowrap}
.strzalka{display:inline-block;width:12px;color:var(--mut);transition:transform .12s}
.strzalka.otwarta{transform:rotate(90deg)}
.dioda{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--brak)}
.d-ok{background:var(--ok)}
.d-info,.d-skip{background:var(--brak)}
.d-warn{background:var(--warn)}
.d-fail{background:var(--fail)}
.rozwiniecie{padding:6px 4px 14px 26px;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}
.rozwiniecie h3{font-size:13px;margin:0 0 6px;font-weight:600}
.rozwiniecie h3 small{color:var(--mut);font-weight:400}
.rozwiniecie ul{list-style:none;margin:0;padding:0}
.rozwiniecie li{padding:5px 0;border-top:1px solid var(--line)}
.tytul{margin:0 6px}
.detal{color:var(--mut);font-size:12px;margin-top:3px;word-break:break-word}
code{font:11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--mut)}
.pill{display:inline-block;padding:0 7px;border-radius:999px;font-size:11px;border:1px solid var(--line);white-space:nowrap}
.p-fail{background:#fdecec;color:#8c1d1d;border-color:#f3bcbc}
.p-warn{background:#fdf4e3;color:#7a5406;border-color:#f0dcae}
.p-ok{background:#eaf6ed;color:#1f5c33;border-color:#bfe0c9}
.p-info,.p-skip{background:transparent;color:var(--mut)}
@media(prefers-color-scheme:dark){
 .p-fail{background:#3a1d1d;color:#f3b6b6;border-color:#5d2b2b}
 .p-warn{background:#3a2f18;color:#f0d79b;border-color:#5c4a24}
 .p-ok{background:#1c3325;color:#a9d9ba;border-color:#2c5039}}
.banner{background:#fdf4e3;color:#7a5406;border:1px solid #f0dcae;border-radius:8px;padding:9px 13px;margin:0 0 12px;font-size:13px}
@media(prefers-color-scheme:dark){.banner{background:#3a2f18;color:#f0d79b;border-color:#5c4a24}}
</style></head><body><main>
<h1>Monitor bezpieczeństwa</h1>
<p class="meta">${escape(report.targets.length)} domen · ostatni przebieg ${escape(String(report.generatedAt).slice(0, 16).replace('T', ' '))} ·
 błędy: ${escape(c.fail ?? 0)} · zastrzeżenia: ${escape(c.warn ?? 0)} · w porządku: ${escape(c.ok ?? 0)}</p>
${problemy.length ? `<div class="banner">Uwagi do konfiguracji: ${escape(problemy.join('; '))}</div>` : ''}
<div class="pasek">
  <div class="legenda">
    <span><i class="dioda d-ok"></i> w porządku</span>
    <span><i class="dioda d-warn"></i> zastrzeżenie</span>
    <span><i class="dioda d-fail"></i> błąd</span>
    <span><i class="dioda"></i> brak danych</span>
  </div>
  <label class="filtr"><input type="checkbox" id="tylkoProblemy" onchange="filtruj()"> pokaż tylko domeny z problemami</label>
</div>
<div class="ramka"><table>
<thead><tr><th>Domena</th>${naglowki}<th class="czas">Godz.</th></tr></thead>
<tbody>${wiersze || `<tr><td colspan="${KOLUMNY.length + 2}">Brak danych. Uruchom przebieg: POST /run</td></tr>`}</tbody>
</table></div>
<script>
function przelacz(i){
  var d=document.getElementById('d'+i), s=document.getElementById('s'+i);
  if(!d) return;
  d.hidden=!d.hidden;
  s.classList.toggle('otwarta', !d.hidden);
}
function filtruj(){
  var tylko=document.getElementById('tylkoProblemy').checked;
  document.querySelectorAll('tr.wiersz').forEach(function(w,i){
    var zle=['warn','fail'].indexOf(w.dataset.stan)>=0;
    var ukryj=tylko&&!zle;
    w.hidden=ukryj;
    if(ukryj){var d=w.nextElementSibling; if(d&&d.classList.contains('szczegoly')){d.hidden=true;}}
  });
}
</script>
</main></body></html>`;
}
