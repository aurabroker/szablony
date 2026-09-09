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
