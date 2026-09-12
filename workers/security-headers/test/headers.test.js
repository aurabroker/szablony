import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  applySecurityHeaders,
  buildCsp,
  buildPermissionsPolicy,
  frameOptionsFor,
  isUtf8,
  shouldRewrite,
} from '../src/headers.js';
import { sanitizePolicy } from '../src/policy.js';

const polityka = (override) => sanitizePolicy(override).policy;

test('CSP zawiera nonce i strict-dynamic', () => {
  const csp = buildCsp(polityka().csp, 'abc123', 'https://a.pl/__csp-report');
  assert.match(csp, /script-src 'nonce-abc123' 'strict-dynamic' https: 'unsafe-inline'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.match(csp, /upgrade-insecure-requests/);
});

test('dyrektywa bez wartosci nie zostawia wiszacego separatora', () => {
  const csp = buildCsp(polityka().csp, null, 'https://a.pl/r');
  assert.ok(!csp.includes('; ;'));
  assert.ok(!/'nonce-/.test(csp));
});

test('Permissions-Policy normalizuje self w apostrofach', () => {
  // Wartosc 'self' naturalna dla CSP dawala wczesniej niepoprawny naglowek.
  assert.equal(buildPermissionsPolicy({ payment: ["'self'"] }), 'payment=(self)');
  assert.equal(buildPermissionsPolicy({ payment: ['self', 'https://js.stripe.com'] }), 'payment=(self "https://js.stripe.com")');
  assert.equal(buildPermissionsPolicy({ camera: [] }), 'camera=()');
  assert.equal(buildPermissionsPolicy({ usb: ['to nie adres'] }), 'usb=()');
});

test('X-Frame-Options wyliczany z frame-ancestors', () => {
  assert.equal(frameOptionsFor(["'none'"]), 'DENY');
  assert.equal(frameOptionsFor(["'self'"]), 'SAMEORIGIN');
  assert.equal(frameOptionsFor(['https://klient.pl']), null);
});

test('w trybie report-only host nadal ma ochrone przed ramkowaniem', () => {
  // Ustalenie K2: wczesniej XFO bylo kasowane, a frame-ancestors nie bylo
  // egzekwowane, wiec faza obserwacji obnizala bezpieczenstwo.
  const headers = new Headers({ 'x-frame-options': 'SAMEORIGIN' });
  applySecurityHeaders(headers, {
    policy: polityka(),
    nonce: 'n',
    isHtml: true,
    url: new URL('https://a.pl/'),
  });
  assert.equal(headers.get('x-frame-options'), 'DENY');
  assert.ok(headers.get('content-security-policy-report-only'));
  assert.equal(headers.get('content-security-policy'), null);
});

test('CORP zalezy od tego, czy to dokument czy zasob', () => {
  const dokument = new Headers();
  applySecurityHeaders(dokument, { policy: polityka(), nonce: null, isHtml: true, url: new URL('https://a.pl/') });
  assert.equal(dokument.get('cross-origin-resource-policy'), 'same-origin');

  const zasob = new Headers();
  applySecurityHeaders(zasob, { policy: polityka(), nonce: null, isHtml: false, url: new URL('https://a.pl/font.woff2') });
  assert.equal(zasob.get('cross-origin-resource-policy'), 'cross-origin');
  assert.equal(zasob.get('permissions-policy'), null, 'na zasobie to zmarnowane bajty');
});

test('naglowki zdradzajace stack sa usuwane', () => {
  const headers = new Headers({ 'x-powered-by': 'PHP/8.1', 'x-runtime': '0.1' });
  applySecurityHeaders(headers, { policy: polityka(), nonce: null, isHtml: true, url: new URL('https://a.pl/') });
  assert.equal(headers.get('x-powered-by'), null);
  assert.equal(headers.get('x-runtime'), null);
});

test('HSTS tylko po https i tylko przy dodatnim maxAge', () => {
  const poHttp = new Headers();
  applySecurityHeaders(poHttp, { policy: polityka(), nonce: null, isHtml: true, url: new URL('http://a.pl/') });
  assert.equal(poHttp.get('strict-transport-security'), null);

  const poHttps = new Headers();
  applySecurityHeaders(poHttps, { policy: polityka({ hsts: { maxAge: 31536000, includeSubDomains: true } }), nonce: null, isHtml: true, url: new URL('https://a.pl/') });
  assert.equal(poHttps.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');

  const wylaczone = new Headers();
  applySecurityHeaders(wylaczone, { policy: polityka({ hsts: false }), nonce: null, isHtml: true, url: new URL('https://a.pl/') });
  assert.equal(wylaczone.get('strict-transport-security'), null);
});

test('tryb origin wymusza brak buforowania dokumentu', () => {
  const headers = new Headers({ 'cache-control': 'public, max-age=3600' });
  applySecurityHeaders(headers, {
    policy: polityka({ csp: { nonce: 'origin', mode: 'enforce' } }),
    nonce: 'n',
    isHtml: true,
    url: new URL('https://a.pl/'),
  });
  assert.equal(headers.get('cache-control'), 'private, no-store');
});

test('przepisywanie tylko dla 200, HTML i UTF-8', () => {
  const p = polityka();
  assert.equal(shouldRewrite(200, 'text/html; charset=utf-8', p, 'n'), true);
  assert.equal(shouldRewrite(200, 'text/html', p, 'n'), true);
  assert.equal(shouldRewrite(206, 'text/html', p, 'n'), false, 'odpowiedz czesciowa');
  assert.equal(shouldRewrite(304, 'text/html', p, 'n'), false);
  assert.equal(shouldRewrite(200, 'application/json', p, 'n'), false);
  assert.equal(shouldRewrite(200, 'text/html; charset=windows-1250', p, 'n'), false, 'HTMLRewriter obsluguje tylko UTF-8');
  assert.equal(shouldRewrite(200, 'text/html', p, null), false, 'bez nonce nie ma co wstawiac');
  assert.equal(shouldRewrite(200, 'text/html', polityka({ csp: { nonce: 'origin' } }), 'n'), false, 'w trybie origin nie przepisujemy');
});

test('isUtf8 rozpoznaje deklaracje kodowania', () => {
  assert.equal(isUtf8('text/html'), true);
  assert.equal(isUtf8('text/html; charset=UTF-8'), true);
  assert.equal(isUtf8('text/html; charset=utf8'), true);
  assert.equal(isUtf8('text/html; charset=iso-8859-2'), false);
});
