import { test } from 'node:test';
import assert from 'node:assert/strict';

import { normalizeTarget, sanitizeConfig } from '../src/config.js';
import { extractDomain } from '../src/cfapi.js';

test('cel podany jako sam host dostaje komplet domyślnych ustawień', () => {
  const target = normalizeTarget('App.Example.COM');
  assert.equal(target.host, 'app.example.com');
  assert.equal(target.cspReportPath, '/__csp-report');
  assert.ok(target.probePaths.length > 0);
});

test('niepoprawny host jest odrzucany zamiast wywalać przebieg', () => {
  for (const bad of ['', 'localhost', 'nie ma kropki', { host: 42 }, null, 'http://a.pl']) {
    assert.equal(normalizeTarget(bad), null);
  }
});

test('zły typ w expect nie przechodzi do polityki', () => {
  const target = normalizeTarget({ host: 'a.example.com', expect: { csp: 'kompletnie-inne', hstsMinAge: 'dużo' } });
  assert.equal(target.expect.csp, 'any');
  assert.equal(typeof target.expect.hstsMinAge, 'number');
});

test('sanitizeConfig przeżywa śmieci w KV', () => {
  for (const bad of [null, 'tekst', 42, []]) {
    const config = sanitizeConfig(bad);
    assert.deepEqual(config.targets, []);
    assert.ok(config.problems.length > 0);
  }
});

test('sanitizeConfig pomija zepsute cele i zachowuje poprawne', () => {
  const config = sanitizeConfig({ targets: ['a.example.com', { host: '' }, 'b.example.com'] });
  assert.deepEqual(config.targets.map((t) => t.host), ['a.example.com', 'b.example.com']);
  assert.equal(config.problems.length, 1);
});

test('limity są przycinane do bezpiecznego zakresu', () => {
  assert.equal(sanitizeConfig({ maxSubrequests: 100000 }).maxSubrequests, 900);
  assert.equal(sanitizeConfig({ requestTimeoutMs: 1 }).requestTimeoutMs, 1000);
});

test('ścieżki spoza formatu i zasoby po http są odfiltrowane', () => {
  const target = normalizeTarget({
    host: 'a.example.com',
    probePaths: ['/ok', 'bez-slasha', 42],
    assets: ['https://a.example.com/app.js', 'http://a.example.com/x.js'],
  });
  assert.deepEqual(target.probePaths, ['/ok']);
  assert.deepEqual(target.assets, ['https://a.example.com/app.js']);
});

test('extractDomain odsiewa szum z rozszerzeń przeglądarki', () => {
  assert.equal(extractDomain('chrome-extension://abcd/inject.js'), null);
  assert.equal(extractDomain('inline'), null);
  assert.equal(extractDomain('https://Analytics.Example.com/x.js'), 'analytics.example.com');
});
