import { test } from 'node:test';
import assert from 'node:assert/strict';

import { sanitizePolicy, mergePolicy, DEFAULT_POLICY } from '../src/policy.js';

test('zepsute wejscie nie wywala walidacji', () => {
  for (const zle of [null, undefined, 'tekst', 42, []]) {
    const { policy } = sanitizePolicy(zle);
    assert.equal(policy.csp.mode, 'report-only');
    assert.ok(Array.isArray(policy.csp.frameAncestors));
  }
});

test('csp ustawione na null nie psuje polityki', () => {
  // To jest ustalenie B3: taki wpis w KV zamienial hosta w blad 1101.
  const { policy, problems } = sanitizePolicy({ csp: null });
  assert.equal(policy.csp.enabled, true);
  assert.match(problems.join(' '), /csp nie jest obiektem/);
});

test('lista podana jako tekst jest odrzucana, nie rozbijana na znaki', () => {
  const { policy, problems } = sanitizePolicy({ csp: { connectSrc: 'https://api.example.com' } });
  assert.deepEqual(policy.csp.connectSrc, []);
  assert.match(problems.join(' '), /connectSrc nie jest listą/);
});

test('enforce z automatycznym nonce jest blokowany', () => {
  const { policy, problems } = sanitizePolicy({ csp: { mode: 'enforce', nonce: 'auto' } });
  assert.equal(policy.csp.mode, 'report-only');
  assert.match(problems.join(' '), /zablokowana/);
});

test('enforce przechodzi z trybem placeholder i origin', () => {
  for (const nonce of ['placeholder', 'origin']) {
    const { policy } = sanitizePolicy({ csp: { mode: 'enforce', nonce } });
    assert.equal(policy.csp.mode, 'enforce');
    assert.equal(policy.csp.nonce, nonce);
  }
});

test('nieznany tryb wraca do wartosci domyslnej', () => {
  const { policy } = sanitizePolicy({ csp: { mode: 'wymuszaj', nonce: 'magia' } });
  assert.equal(policy.csp.mode, 'report-only');
  assert.equal(policy.csp.nonce, 'auto');
});

test('hsts: maxAge przycinany, preload wymaga includeSubDomains', () => {
  assert.equal(sanitizePolicy({ hsts: { maxAge: 999999999 } }).policy.hsts.maxAge, 63072000);
  assert.equal(sanitizePolicy({ hsts: { maxAge: -5 } }).policy.hsts.maxAge, 0);

  const { policy, problems } = sanitizePolicy({ hsts: { maxAge: 300, preload: true } });
  assert.equal(policy.hsts.preload, false);
  assert.match(problems.join(' '), /preload wymaga includeSubDomains/);
});

test('domyslny maxAge jest krotki, bo HSTS wprowadzamy schodkowo', () => {
  assert.equal(DEFAULT_POLICY.hsts.maxAge, 300);
  assert.equal(DEFAULT_POLICY.hsts.includeSubDomains, false);
  assert.equal(DEFAULT_POLICY.hsts.preload, false);
});

test('CORP jest rozdzielone na dokumenty i zasoby', () => {
  assert.equal(DEFAULT_POLICY.corpDocument, 'same-origin');
  assert.equal(DEFAULT_POLICY.corpAsset, 'cross-origin');
});

test('nazwa funkcji w permissions jest walidowana', () => {
  const { policy, problems } = sanitizePolicy({ permissions: { 'camera; drop': ['self'], camera: ['self'] } });
  assert.deepEqual(policy.permissions.camera, ['self']);
  assert.match(problems.join(' '), /nazwa odrzucona/);
});

test('mergePolicy scala jeden poziom i nie gubi reszty', () => {
  const scalone = mergePolicy({ csp: { mode: 'report-only', nonce: 'auto' }, coop: 'same-origin' }, { csp: { mode: 'enforce' } });
  assert.equal(scalone.csp.mode, 'enforce');
  assert.equal(scalone.csp.nonce, 'auto');
  assert.equal(scalone.coop, 'same-origin');
});
