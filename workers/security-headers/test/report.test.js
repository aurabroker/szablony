import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseReports, typDozwolony, handleCspReport } from '../src/report.js';

test('oba formaty raportow sa rozumiane', () => {
  const stary = parseReports({ 'csp-report': { 'violated-directive': 'script-src', 'blocked-uri': 'https://x.pl/a.js' } });
  assert.equal(stary[0].directive, 'script-src');
  assert.equal(stary[0].blockedURL, 'https://x.pl/a.js');

  const nowy = parseReports([{ body: { effectiveDirective: 'img-src', blockedURL: 'https://y.pl/b.png' } }]);
  assert.equal(nowy[0].directive, 'img-src');
});

test('liczba wpisow w jednej paczce jest ograniczona', () => {
  assert.equal(parseReports(Array.from({ length: 500 }, () => ({}))).length, 50);
});

test('nieznany typ tresci jest odrzucany', () => {
  assert.equal(typDozwolony('application/csp-report'), true);
  assert.equal(typDozwolony('application/reports+json; charset=utf-8'), true);
  assert.equal(typDozwolony('text/html'), false);
  assert.equal(typDozwolony(null), false);
});

const zadanie = (init) => new Request('https://a.pl/__csp-report', init);

test('endpoint pilnuje metody, typu i rozmiaru', async () => {
  const env = {};
  assert.equal((await handleCspReport(zadanie({ method: 'GET' }), env)).status, 405);
  assert.equal(
    (await handleCspReport(zadanie({ method: 'POST', headers: { 'content-type': 'text/html' }, body: '{}' }), env)).status,
    415,
  );
  assert.equal(
    (await handleCspReport(
      zadanie({ method: 'POST', headers: { 'content-type': 'application/json', 'content-length': '999999' }, body: '{}' }),
      env,
    )).status,
    413,
  );
});

test('poprawny raport trafia do datasetu i konczy sie 204', async () => {
  const zapisane = [];
  const env = { CSP_REPORTS: { writeDataPoint: (p) => zapisane.push(p) } };
  const odpowiedz = await handleCspReport(
    zadanie({
      method: 'POST',
      headers: { 'content-type': 'application/csp-report' },
      body: JSON.stringify({ 'csp-report': { 'violated-directive': 'script-src', 'line-number': 42 } }),
    }),
    env,
  );
  assert.equal(odpowiedz.status, 204);
  assert.equal(zapisane.length, 1);
  assert.deepEqual(zapisane[0].indexes, ['script-src']);
  assert.deepEqual(zapisane[0].doubles, [42]);
});

test('bledny JSON nie zwraca bledu przegladarce', async () => {
  const odpowiedz = await handleCspReport(
    zadanie({ method: 'POST', headers: { 'content-type': 'application/json' }, body: 'to nie json' }),
    {},
  );
  assert.equal(odpowiedz.status, 204);
});
