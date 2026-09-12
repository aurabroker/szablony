/**
 * Test integracyjny orkiestracji: podstawiamy fetch i KV, więc cały przebieg
 * da się sprawdzić bez wranglera i bez ruszania czegokolwiek w sieci.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runAudit } from '../src/index.js';

function fakeKv() {
  const store = new Map();
  return {
    store,
    async get(key, options) {
      const raw = store.get(key);
      if (raw === undefined) return null;
      return options?.type === 'json' ? JSON.parse(raw) : raw;
    },
    async put(key, value) {
      store.set(key, value);
    },
  };
}

const HEADERS_OK = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'; script-src 'nonce-x' 'strict-dynamic'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
};

function installFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const key = `${init.method ?? 'GET'} ${String(url)}`;
    calls.push(key);
    const route = routes[key] ?? routes[String(url)];
    if (!route) return new Response('brak', { status: 404 });
    return new Response(route.body ?? null, { status: route.status ?? 200, headers: route.headers ?? {} });
  };
  return calls;
}

const env = (extra = {}) => ({
  MONITOR_CONFIG: JSON.stringify({ targets: [{ host: 'app.example.com', probePaths: ['/.env'], assets: [], checkCspPipeline: true }] }),
  MONITOR_STATE: fakeKv(),
  ...extra,
});

test('zdrowy host kończy przebieg bez błędów', async () => {
  installFetch({
    'GET https://app.example.com/': { headers: HEADERS_OK },
    'GET http://app.example.com/': { status: 301, headers: { location: 'https://app.example.com/' } },
    'GET https://app.example.com/.env': { status: 404 },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET, HEAD, POST' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
    'POST https://app.example.com/__csp-report': { status: 204 },
  });

  const { report } = await runAudit(env(), 'test');
  assert.equal(report.targets.length, 1);
  assert.equal(report.summary.worst, 'info'); // brak security.txt i pominięte sondy API
  assert.equal(report.targets[0].summary.counts.fail, 0);
});

test('odsłonięty plik .env i brak przekierowania są wychwytywane', async () => {
  installFetch({
    'GET https://app.example.com/': { headers: HEADERS_OK },
    'GET http://app.example.com/': { status: 200 },
    'GET https://app.example.com/.env': { status: 200, body: 'SECRET=1', headers: { 'content-type': 'text/plain' } },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET, TRACE' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
    'POST https://app.example.com/__csp-report': { status: 204 },
  });

  const { report } = await runAudit(env(), 'test');
  const ids = report.targets[0].findings.filter((f) => f.status === 'fail').map((f) => f.id);
  assert.ok(ids.includes('path:/.env'));
  assert.ok(ids.includes('http-redirect'));
  assert.equal(report.summary.worst, 'fail');
});

test('niedziałający kanał raportów CSP jest zgłaszany osobno', async () => {
  installFetch({
    'GET https://app.example.com/': { headers: HEADERS_OK },
    'GET http://app.example.com/': { status: 301, headers: { location: 'https://app.example.com/' } },
    'GET https://app.example.com/.env': { status: 404 },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
    'POST https://app.example.com/__csp-report': { status: 404 },
  });

  const { report } = await runAudit(env(), 'test');
  const pipeline = report.targets[0].findings.find((f) => f.id === 'csp-pipeline');
  assert.equal(pipeline.status, 'fail');
});

test('host nieosiągalny nie przerywa przebiegu', async () => {
  globalThis.fetch = async () => {
    throw new Error('połączenie odrzucone');
  };
  const { report } = await runAudit(env(), 'test');
  assert.equal(report.summary.worst, 'fail');
  assert.ok(report.targets[0].findings.some((f) => f.id === 'headers' && f.status === 'fail'));
});

test('budżet podżądań zatrzymuje przebieg zamiast przekroczyć limit platformy', async () => {
  installFetch({});
  const tightEnv = env({
    MONITOR_CONFIG: JSON.stringify({
      maxSubrequests: 5,
      targets: [{ host: 'a.example.com' }, { host: 'b.example.com' }],
    }),
  });
  const { report } = await runAudit(tightEnv, 'test');
  assert.ok(report.subrequestsUsed <= 5);
  const skipped = report.targets.flatMap((t) => t.findings).filter((f) => f.status === 'skip');
  assert.ok(skipped.length > 0, 'pominięte sondy powinny być widoczne w raporcie');
});

test('wzorzec hasha zapisuje się przy pierwszym przebiegu, a zmiana jest błędem', async () => {
  const kv = fakeKv();
  const withAsset = {
    MONITOR_CONFIG: JSON.stringify({
      targets: [{ host: 'app.example.com', probePaths: [], assets: ['https://app.example.com/app.js'], checkCspPipeline: true }],
    }),
    MONITOR_STATE: kv,
  };
  const routes = {
    'GET https://app.example.com/': { headers: HEADERS_OK },
    'GET http://app.example.com/': { status: 301, headers: { location: 'https://app.example.com/' } },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
    'POST https://app.example.com/__csp-report': { status: 204 },
    'GET https://app.example.com/app.js': { body: 'console.log(1)' },
  };

  installFetch(routes);
  const first = await runAudit(withAsset, 'test');
  assert.equal(first.report.targets[0].findings.find((f) => f.id.startsWith('asset:')).status, 'info');

  routes['GET https://app.example.com/app.js'] = { body: 'console.log(2) /* podmienione */' };
  installFetch(routes);
  const second = await runAudit(withAsset, 'test');
  const asset = second.report.targets[0].findings.find((f) => f.id.startsWith('asset:'));
  assert.equal(asset.status, 'fail');
  assert.match(asset.title, /Zmiana zawartości/);
});

test('tura bierze kolejne hosty i wraca na początek listy', async () => {
  const { selectSlice } = await import('../src/index.js');
  const targets = ['a', 'b', 'c', 'd', 'e'];

  const first = selectSlice(targets, 0, 2);
  assert.deepEqual(first.slice, ['a', 'b']);
  assert.equal(first.nextCursor, 2);

  const second = selectSlice(targets, first.nextCursor, 2);
  assert.deepEqual(second.slice, ['c', 'd']);

  const third = selectSlice(targets, second.nextCursor, 2);
  assert.deepEqual(third.slice, ['e', 'a'], 'ostatnia tura zawija się na początek');

  assert.deepEqual(selectSlice(targets, 3, 0).slice, targets, 'zero znaczy wszystkie hosty');
});

test('kolejne tury nie kasują wiedzy o hostach spoza tury', async () => {
  const kv = fakeKv();
  const cfg = JSON.stringify({
    hostsPerRun: 1,
    targets: [{ host: 'a.example.com', probePaths: [] }, { host: 'b.example.com', probePaths: [] }],
  });
  installFetch({});

  const { runAudit } = await import('../src/index.js');
  const first = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.deepEqual(first.report.targets.map((t) => t.host), ['a.example.com']);

  await kv.put('host:a.example.com', JSON.stringify({ host: 'a.example.com', findings: [], summary: {}, state: {} }));
  const second = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.deepEqual(second.report.targets.map((t) => t.host), ['b.example.com']);
  assert.ok(kv.store.has('host:a.example.com'), 'wynik poprzedniej tury zostaje w KV');
});

test('wzorzec skryptów nie jest nadpisywany, gdy pojawia się obca domena', async () => {
  const kv = fakeKv();
  const cfg = JSON.stringify({ targets: [{ host: 'app.example.com', probePaths: [] }] });
  const strona = (extra) =>
    `<html><script src="/app.js"></script>${extra}</html>`;

  const routes = (extra) => ({
    'GET https://app.example.com/': {
      body: strona(extra),
      headers: { ...HEADERS_OK, 'content-type': 'text/html; charset=utf-8' },
    },
    'GET http://app.example.com/': { status: 301, headers: { location: 'https://app.example.com/' } },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
  });

  installFetch(routes(''));
  const first = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.match(first.report.targets[0].findings.find((f) => f.id === 'scripts').title, /Zapisano wzorzec/);

  installFetch(routes('<script src="https://zla.example/skimmer.js"></script>'));
  const second = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.equal(second.report.targets[0].findings.find((f) => f.id === 'scripts').status, 'warn');

  // trzeci przebieg: ostrzeżenie ma nadal wisieć, bo nikt go nie zaakceptował
  const third = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.equal(third.report.targets[0].findings.find((f) => f.id === 'scripts').status, 'warn');
});

test('strona zastepcza na wrazliwej sciezce nie jest bledem, prawdziwy plik jest', async () => {
  const wspolne = {
    'GET https://app.example.com/': { headers: { ...HEADERS_OK, 'content-type': 'text/html' } },
    'GET http://app.example.com/': { status: 301, headers: { location: 'https://app.example.com/' } },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
  };
  const cfg = JSON.stringify({ targets: [{ host: 'app.example.com', probePaths: ['/.env'], checkScripts: false }] });

  // katch-all SPA: 200, ale text/html
  installFetch({ ...wspolne, 'GET https://app.example.com/.env': { status: 200, body: '<html>404</html>', headers: { 'content-type': 'text/html; charset=utf-8' } } });
  const spa = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: fakeKv() }, 'test');
  assert.equal(spa.report.targets[0].findings.find((f) => f.id === 'path:/.env').status, 'ok');

  // prawdziwy plik konfiguracyjny
  installFetch({ ...wspolne, 'GET https://app.example.com/.env': { status: 200, body: 'DB_PASSWORD=1', headers: { 'content-type': 'text/plain' } } });
  const plik = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: fakeKv() }, 'test');
  assert.equal(plik.report.targets[0].findings.find((f) => f.id === 'path:/.env').status, 'fail');
});

test('wstrzyknieta tresc jest wychwytywana w pelnym przebiegu', async () => {
  const kv = fakeKv();
  const cfg = JSON.stringify({ targets: [{ host: 'app.example.com', probePaths: [] }] });
  const strona = (dodatek) => `<html><body><h1>Kancelaria</h1>${dodatek}</body></html>`;

  const trasy = (dodatek) => ({
    'GET https://app.example.com/': { body: strona(dodatek), headers: { ...HEADERS_OK, 'content-type': 'text/html' } },
    'GET http://app.example.com/': { status: 301, headers: { location: 'https://app.example.com/' } },
    'OPTIONS https://app.example.com/': { headers: { allow: 'GET' } },
    'GET https://app.example.com/.well-known/security.txt': { status: 404 },
  });

  installFetch(trasy('<a href="https://facebook.com/x">fb</a>'));
  const pierwszy = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.match(pierwszy.report.targets[0].findings.find((f) => f.id === 'linki').title, /Zapisano wzorzec/);

  installFetch(trasy('<a href="https://facebook.com/x">fb</a><a href="https://kasyno.example" style="display:none">bonus</a>'));
  const drugi = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  const ustalenia = drugi.report.targets[0].findings;
  assert.equal(ustalenia.find((f) => f.id === 'spam-ukryte').status, 'fail');
  assert.equal(ustalenia.find((f) => f.id === 'linki').status, 'warn');

  // wzorzec nie zostal nadpisany, wiec ostrzezenie wisi dalej
  const trzeci = await runAudit({ MONITOR_CONFIG: cfg, MONITOR_STATE: kv }, 'test');
  assert.equal(trzeci.report.targets[0].findings.find((f) => f.id === 'linki').status, 'warn');
});
