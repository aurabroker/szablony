import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  diffStates,
  evaluateCookies,
  evaluateSecurityHeaders,
  evaluateSecurityTxt,
  parseCookie,
  parseHsts,
  summarize,
  toState,
  worst,
} from '../src/checks.js';

const byId = (findings, id) => findings.find((f) => f.id === id);

const FULL = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'; script-src 'nonce-abc' 'strict-dynamic'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
};

test('komplet nagłówków nie generuje ostrzeżeń', () => {
  const findings = evaluateSecurityHeaders(FULL);
  assert.equal(summarize(findings).worst, 'ok');
});

test('brak CSP to błąd', () => {
  const findings = evaluateSecurityHeaders({ ...FULL, 'content-security-policy': undefined });
  assert.equal(byId(findings, 'csp').status, 'fail');
});

test('oczekiwany enforce przy samym report-only to błąd', () => {
  const findings = evaluateSecurityHeaders(
    { 'content-security-policy-report-only': "default-src 'self'" },
    { csp: 'enforce', requireHsts: false },
  );
  assert.equal(byId(findings, 'csp').status, 'fail');
});

test('report-only plus brak X-Frame-Options wykrywa lukę w ochronie przed ramkowaniem', () => {
  // Ustalenie K2: frame-ancestors w report-only nie jest egzekwowane,
  // a Worker nagłówkowy usuwa X-Frame-Options.
  const findings = evaluateSecurityHeaders({
    'content-security-policy-report-only': "default-src 'self'; frame-ancestors 'none'",
    'strict-transport-security': 'max-age=63072000; includeSubDomains',
  });
  const frame = byId(findings, 'frame');
  assert.equal(frame.status, 'fail');
  assert.match(frame.title, /ramkowaniem/);
});

test('X-Frame-Options wystarcza, gdy CSP jest tylko obserwacyjne', () => {
  const findings = evaluateSecurityHeaders({
    'content-security-policy-report-only': "default-src 'self'",
    'x-frame-options': 'DENY',
    'strict-transport-security': 'max-age=63072000; includeSubDomains',
  });
  assert.equal(byId(findings, 'frame').status, 'ok');
});

test("strict-dynamic bez nonce'a to błąd", () => {
  const findings = evaluateSecurityHeaders({
    ...FULL,
    'content-security-policy': "script-src 'strict-dynamic' https:",
  });
  assert.equal(byId(findings, 'csp-nonce').status, 'fail');
});

test('parseHsts czyta wszystkie pola', () => {
  assert.deepEqual(parseHsts('max-age=31536000; includeSubDomains; preload'), {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  });
  assert.equal(parseHsts(''), null);
});

test('krótki max-age i brak includeSubDomains dają ostrzeżenie', () => {
  const findings = evaluateSecurityHeaders({ ...FULL, 'strict-transport-security': 'max-age=300' });
  const hsts = byId(findings, 'hsts');
  assert.equal(hsts.status, 'warn');
  assert.equal(hsts.detail.problemy.length, 2);
});

test('włączony preload jest zgłaszany jako decyzja nieodwracalna', () => {
  const findings = evaluateSecurityHeaders({
    ...FULL,
    'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  });
  assert.match(byId(findings, 'hsts').detail.problemy.join(' '), /nieodwracalna/);
});

test('nagłówki zdradzające stack są wychwytywane', () => {
  const findings = evaluateSecurityHeaders({ ...FULL, 'x-powered-by': 'PHP/8.1.2' });
  assert.equal(byId(findings, 'leaky').status, 'warn');
});

test('parseCookie czyta flagi', () => {
  assert.deepEqual(parseCookie('sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax'), {
    name: 'sid',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
  });
});

test('ciasteczko bez Secure to błąd, bez SameSite tylko ostrzeżenie', () => {
  assert.equal(evaluateCookies(['sid=a; HttpOnly; SameSite=Lax'])[0].status, 'fail');
  assert.equal(evaluateCookies(['sid=a; Secure; HttpOnly'])[0].status, 'warn');
  assert.equal(evaluateCookies(['sid=a; Secure; HttpOnly; SameSite=Lax'])[0].status, 'ok');
});

test('wyjątek na liście zdejmuje wymóg HttpOnly', () => {
  const findings = evaluateCookies(['csrf=a; Secure; SameSite=Lax'], {
    cookiesAllowedWithoutHttpOnly: ['csrf'],
  });
  assert.equal(findings[0].status, 'ok');
});

test('security.txt po terminie daje ostrzeżenie', () => {
  const now = Date.parse('2026-09-09T00:00:00Z');
  assert.equal(evaluateSecurityTxt(200, 'Expires: 2026-01-01T00:00:00Z', now)[0].status, 'warn');
  assert.equal(evaluateSecurityTxt(200, 'Expires: 2027-01-01T00:00:00Z', now)[0].status, 'ok');
  assert.equal(evaluateSecurityTxt(404, '', now)[0].status, 'info');
});

test('worst i summarize wybierają najgorszy status', () => {
  assert.equal(worst(['ok', 'warn', 'info']), 'warn');
  assert.equal(worst(['ok', 'fail', 'warn']), 'fail');
  assert.equal(summarize([{ status: 'ok' }, { status: 'warn' }]).counts.warn, 1);
});

test('diffStates alarmuje o zmianach, nie o stanie', () => {
  const prev = { 'a|csp': 'ok', 'a|hsts': 'warn', 'a|frame': 'fail' };
  const next = { 'a|csp': 'fail', 'a|hsts': 'warn', 'a|frame': 'ok', 'a|cookies': 'warn' };
  const diff = diffStates(prev, next);

  assert.deepEqual(diff.pogorszone, [{ key: 'a|csp', status: 'fail', poprzednio: 'ok' }]);
  assert.deepEqual(diff.nowe, [{ key: 'a|cookies', status: 'warn' }]);
  assert.deepEqual(diff.naprawione, [{ key: 'a|frame', status: 'ok', poprzednio: 'fail' }]);
});

test('utrzymujące się ostrzeżenie nie generuje kolejnego alertu', () => {
  const state = { 'a|hsts': 'warn' };
  const diff = diffStates(state, state);
  assert.equal(diff.nowe.length + diff.pogorszone.length + diff.naprawione.length, 0);
});

test('toState spłaszcza wynik przebiegu', () => {
  const state = toState([{ host: 'a.pl', findings: [{ id: 'csp', status: 'ok' }] }]);
  assert.deepEqual(state, { 'a.pl|csp': 'ok' });
});

test('extractScripts zbiera skrypty zewnętrzne i liczy wplecione', async () => {
  const { extractScripts } = await import('../src/checks.js');
  const html = `<html><head>
    <script src="/js/app.js?ver=6.4"></script>
    <script src='https://cdn.example.com/lib.js'></script>
    <script src=https://bez.cudzyslowow.pl/x.js></script>
    <script>var a=1;</script>
    <script type="application/json">{"a":1}</script>
  </head></html>`;
  const inv = extractScripts(html, 'app.example.com');

  assert.deepEqual(inv.external, [
    'https://app.example.com/js/app.js',
    'https://bez.cudzyslowow.pl/x.js',
    'https://cdn.example.com/lib.js',
  ]);
  assert.equal(inv.inlineCount, 2);
});

test('parametr wersji nie robi szumu przy porównaniu', async () => {
  const { extractScripts } = await import('../src/checks.js');
  const a = extractScripts('<script src="/app.js?ver=1"></script>', 'a.pl');
  const b = extractScripts('<script src="/app.js?ver=2"></script>', 'a.pl');
  assert.deepEqual(a.external, b.external);
});

test('nowa obca domena serwująca skrypt to ostrzeżenie', async () => {
  const { evaluateScriptInventory } = await import('../src/checks.js');
  const baseline = { external: ['https://a.pl/app.js'], inlineCount: 1 };
  const current = { external: ['https://a.pl/app.js', 'https://zla.example/skimmer.js'], inlineCount: 1 };

  const findings = evaluateScriptInventory(current, baseline, 'a.pl');
  const scripts = findings.find((f) => f.id === 'scripts');
  assert.equal(scripts.status, 'warn');
  assert.match(scripts.title, /zla\.example/);
});

test('nowy plik na znanej domenie to tylko informacja', async () => {
  const { evaluateScriptInventory } = await import('../src/checks.js');
  const baseline = { external: ['https://a.pl/app.js'], inlineCount: 1 };
  const current = { external: ['https://a.pl/app.js', 'https://a.pl/nowy.js'], inlineCount: 1 };
  assert.equal(evaluateScriptInventory(current, baseline, 'a.pl').find((f) => f.id === 'scripts').status, 'info');
});

test('brak wzorca zapisuje stan wyjściowy zamiast alarmować', async () => {
  const { evaluateScriptInventory } = await import('../src/checks.js');
  const findings = evaluateScriptInventory({ external: ['https://a.pl/x.js'], inlineCount: 0 }, null, 'a.pl');
  assert.equal(findings[0].status, 'info');
  assert.match(findings[0].title, /Zapisano wzorzec/);
});

test('zmiana liczby skryptów wplecionych jest odnotowana osobno', async () => {
  const { evaluateScriptInventory } = await import('../src/checks.js');
  const findings = evaluateScriptInventory(
    { external: [], inlineCount: 3 },
    { external: [], inlineCount: 1 },
    'a.pl',
  );
  assert.equal(findings.find((f) => f.id === 'scripts-inline').status, 'info');
});

const dns = (rekordy) => rekordy.map((r) => ({ proxied: true, ...r }));
const znajdz = (f, id) => f.find((x) => x.id === id);

test('brak DMARC to blad, brak SPF przy dzialajacej poczcie tez', async () => {
  const { evaluateDns } = await import('../src/checks.js');
  const f = evaluateDns(dns([{ type: 'MX', name: 'a.pl', content: 'mx.a.pl' }, { type: 'A', name: 'a.pl' }]), 'a.pl');
  assert.equal(znajdz(f, 'dmarc').status, 'fail');
  assert.equal(znajdz(f, 'spf').status, 'fail');
  assert.equal(znajdz(f, 'dkim').status, 'warn');
});

test('domena bez poczty nadal potrzebuje DMARC, ale brak SPF to tylko ostrzezenie', async () => {
  const { evaluateDns } = await import('../src/checks.js');
  const f = evaluateDns(dns([{ type: 'A', name: 'a.pl' }]), 'a.pl');
  assert.equal(znajdz(f, 'spf').status, 'warn');
  assert.equal(znajdz(f, 'dmarc').status, 'fail');
  assert.equal(znajdz(f, 'dkim'), undefined, 'bez poczty nie wymagamy DKIM');
});

test('DMARC tylko obserwujacy to ostrzezenie, egzekwowany to ok', async () => {
  const { evaluateDns } = await import('../src/checks.js');
  const zRekordem = (tresc) =>
    evaluateDns(dns([{ type: 'TXT', name: '_dmarc.a.pl', content: tresc }, { type: 'A', name: 'a.pl' }]), 'a.pl');
  assert.equal(znajdz(zRekordem('v=DMARC1; p=none'), 'dmarc').status, 'warn');
  assert.equal(znajdz(zRekordem('v=DMARC1; p=quarantine'), 'dmarc').status, 'ok');
  assert.equal(znajdz(zRekordem('"v=DMARC1; p=reject; rua=mailto:a@a.pl"'), 'dmarc').status, 'ok');
});

test('SPF konczacy sie ~all nie odrzuca obcych nadawcow', async () => {
  const { evaluateDns } = await import('../src/checks.js');
  const zSpf = (tresc) => evaluateDns(dns([{ type: 'TXT', name: 'a.pl', content: tresc }]), 'a.pl');
  assert.equal(znajdz(zSpf('v=spf1 include:_spf.google.com ~all'), 'spf').status, 'warn');
  assert.equal(znajdz(zSpf('v=spf1 include:_spf.google.com -all'), 'spf').status, 'ok');
  assert.equal(znajdz(zSpf('v=spf1 -all'), 'spf').status, 'ok');
});

test('rekord z wylaczonym proxy jest zglaszany', async () => {
  const { evaluateDns } = await import('../src/checks.js');
  const f = evaluateDns([{ type: 'A', name: 'www.a.pl', proxied: false }, { type: 'A', name: 'a.pl', proxied: true }], 'a.pl');
  assert.equal(znajdz(f, 'proxy').status, 'warn');
  assert.match(znajdz(f, 'proxy').title, /www\.a\.pl/);
});

test('caly ruch za proxy to ok', async () => {
  const { evaluateDns } = await import('../src/checks.js');
  assert.equal(znajdz(evaluateDns(dns([{ type: 'A', name: 'a.pl' }]), 'a.pl'), 'proxy').status, 'ok');
});

test('ukryty odnosnik ze stylem jest wykrywany', async () => {
  const { extractLinks, evaluateContentIntegrity } = await import('../src/checks.js');
  const html = `<p>tekst</p>
    <a href="https://kasyno.example/bonus" style="display:none">wygraj</a>
    <a href="https://partner.example">normalny partner</a>`;
  const inv = extractLinks(html, 'a.pl');
  assert.equal(inv.ukryteOdnosniki, 1);
  assert.deepEqual(inv.domeny, ['kasyno.example', 'partner.example']);

  const f = evaluateContentIntegrity(inv, { domeny: [] }, 'a.pl');
  assert.equal(f.find((x) => x.id === 'spam-ukryte').status, 'fail');
});

test('odnosnik w kontenerze wypchnietym za ekran to ostrzezenie', async () => {
  const { extractLinks, evaluateContentIntegrity } = await import('../src/checks.js');
  const inv = extractLinks('<div style="position:absolute;left:-9999px"><a href="https://x.example">a</a></div>', 'a.pl');
  assert.equal(inv.ukryteKontenery, 1);
  assert.equal(inv.ukryteOdnosniki, 0);
  assert.equal(evaluateContentIntegrity(inv, { domeny: [] }, 'a.pl').find((x) => x.id === 'spam-ukryte').status, 'warn');
});

test('slowa obce dla kancelarii to blad, wlasna terminologia nie', async () => {
  const { extractLinks, evaluateContentIntegrity } = await import('../src/checks.js');
  const spam = extractLinks('<p>Tanie kamagra i kasyno online</p>', 'a.pl');
  assert.equal(evaluateContentIntegrity(spam, { domeny: [] }, 'a.pl').find((x) => x.id === 'spam-slowa').status, 'fail');

  const wlasne = extractLinks('<p>Odszkodowanie, kredyt, pożyczka, rozwód, alimenty</p>', 'a.pl');
  assert.equal(wlasne.slowa.length, 0, 'normalna treść nie może wywoływać alarmu');
});

test('wlasne odnosniki i www nie licza sie jako zewnetrzne', async () => {
  const { extractLinks } = await import('../src/checks.js');
  const inv = extractLinks('<a href="/kontakt">x</a><a href="https://www.a.pl/o-nas">y</a><a href="https://a.pl/#top">z</a>', 'a.pl');
  assert.deepEqual(inv.domeny, []);
});

test('nowa domena w odnosnikach to ostrzezenie, znana nie', async () => {
  const { evaluateContentIntegrity } = await import('../src/checks.js');
  const teraz = { domeny: ['facebook.com', 'obca.example'], ukryteOdnosniki: 0, ukryteKontenery: 0, slowa: [] };
  assert.equal(evaluateContentIntegrity(teraz, { domeny: ['facebook.com'] }, 'a.pl').find((x) => x.id === 'linki').status, 'warn');
  assert.equal(
    evaluateContentIntegrity(teraz, { domeny: ['facebook.com', 'obca.example'] }, 'a.pl').find((x) => x.id === 'linki').status,
    'ok',
  );
});

test('pierwszy przebieg zapisuje wzorzec zamiast alarmowac', async () => {
  const { evaluateContentIntegrity } = await import('../src/checks.js');
  const f = evaluateContentIntegrity({ domeny: ['x.example'], ukryteOdnosniki: 0, ukryteKontenery: 0, slowa: [] }, null, 'a.pl');
  assert.equal(f[0].status, 'info');
  assert.match(f[0].title, /Zapisano wzorzec/);
});
