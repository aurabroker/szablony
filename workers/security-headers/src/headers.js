/** Budowanie nagłówków. Wszystko czyste, żeby dało się przetestować bez runtime'u. */

import { LEAKY_HEADERS, REPORT_PATH } from './policy.js';

export function buildCsp(csp, nonce, reportEndpoint) {
  const nonceToken = nonce ? `'nonce-${nonce}'` : null;

  const directives = {
    'default-src': ["'self'"],
    // Klasyczna strict CSP. Nowoczesne przeglądarki widzą nonce i ignorują
    // 'unsafe-inline' oraz https:. Stare spadają na https: zamiast na nic.
    'script-src': [nonceToken, "'strict-dynamic'", 'https:', "'unsafe-inline'", ...csp.scriptSrc],
    'style-src': csp.nonceOnStyles
      ? ["'self'", nonceToken, ...csp.styleSrc]
      : ["'self'", "'unsafe-inline'", ...csp.styleSrc],
    'img-src': ["'self'", 'data:', 'blob:', 'https:', ...csp.imgSrc],
    'font-src': ["'self'", 'data:', ...csp.fontSrc],
    'connect-src': ["'self'", ...csp.connectSrc],
    'frame-src': ["'self'", ...csp.frameSrc],
    'form-action': ["'self'", ...csp.formAction],
    'frame-ancestors': csp.frameAncestors,
    'object-src': ["'none'"],
    'base-uri': ["'none'"],
    'report-to': ['csp'],
    'report-uri': [reportEndpoint],
  };

  if (csp.upgradeInsecureRequests) directives['upgrade-insecure-requests'] = [];

  return Object.entries(directives)
    .map(([name, values]) => {
      const cleaned = values.filter(Boolean);
      return cleaned.length ? `${name} ${cleaned.join(' ')}` : name;
    })
    .join('; ');
}

/**
 * Lista dozwolonych źródeł dla Permissions-Policy.
 * `self` zapisuje się bez cudzysłowów, origin w cudzysłowach. Wartość `'self'`
 * w apostrofach, naturalna dla CSP, dawała wcześniej niepoprawny nagłówek.
 */
export function buildPermissionsPolicy(features) {
  const wpisy = [];
  for (const [name, allowList] of Object.entries(features ?? {})) {
    if (!Array.isArray(allowList) || allowList.length === 0) {
      wpisy.push(`${name}=()`);
      continue;
    }
    const origins = [];
    for (const raw of allowList) {
      const value = String(raw).trim().replace(/^'|'$/g, '');
      if (value === 'self' || value === '*') origins.push(value);
      else {
        try {
          origins.push(`"${new URL(value).origin}"`);
        } catch {
          // wpis nieparsowalny pomijamy zamiast psuć cały nagłówek
        }
      }
    }
    wpisy.push(origins.length ? `${name}=(${origins.join(' ')})` : `${name}=()`);
  }
  return wpisy.join(', ');
}

/**
 * X-Frame-Options wyliczany z frame-ancestors, zamiast bezwarunkowego usuwania.
 * To ustalenie K2: w trybie report-only frame-ancestors nie jest egzekwowane,
 * więc skasowanie XFO zostawia hosta bez żadnej ochrony przed ramkowaniem.
 */
export function frameOptionsFor(frameAncestors) {
  const lista = (frameAncestors ?? []).map((v) => String(v).trim().toLowerCase());
  if (lista.length === 1 && lista[0] === "'none'") return 'DENY';
  if (lista.length === 1 && lista[0] === "'self'") return 'SAMEORIGIN';
  return null; // lista domen nie ma odpowiednika w XFO
}

export function isHtmlResponse(contentType) {
  return (contentType ?? '').toLowerCase().includes('text/html');
}

/** HTMLRewriter obsługuje wyłącznie UTF-8; inne kodowanie by rozsypał. */
export function isUtf8(contentType) {
  const charset = /charset\s*=\s*"?([\w-]+)"?/i.exec(contentType ?? '');
  return !charset || /^utf-?8$/i.test(charset[1]);
}

export function shouldRewrite(status, contentType, policy, nonce) {
  if (!nonce) return false;
  if (status !== 200) return false;
  if (!isHtmlResponse(contentType) || !isUtf8(contentType)) return false;
  return policy.csp.nonce === 'auto' || policy.csp.nonce === 'placeholder';
}

export function applySecurityHeaders(headers, { policy, nonce, isHtml, url }) {
  for (const name of LEAKY_HEADERS) headers.delete(name);

  headers.set('X-Content-Type-Options', 'nosniff');
  if (policy.referrerPolicy) headers.set('Referrer-Policy', policy.referrerPolicy);

  const corp = isHtml ? policy.corpDocument : policy.corpAsset;
  if (corp) headers.set('Cross-Origin-Resource-Policy', corp);
  else headers.delete('Cross-Origin-Resource-Policy');

  if (url.protocol === 'https:' && policy.hsts && policy.hsts.maxAge > 0) {
    let value = `max-age=${policy.hsts.maxAge}`;
    if (policy.hsts.includeSubDomains) value += '; includeSubDomains';
    if (policy.hsts.preload) value += '; preload';
    headers.set('Strict-Transport-Security', value);
  }

  if (!isHtml) return;

  headers.set('Permissions-Policy', buildPermissionsPolicy(policy.permissions));
  if (policy.coop) headers.set('Cross-Origin-Opener-Policy', policy.coop);

  if (!policy.csp.enabled) return;

  const reportEndpoint = `https://${url.hostname}${REPORT_PATH}`;
  headers.set('Reporting-Endpoints', `csp="${reportEndpoint}"`);

  headers.delete('Content-Security-Policy');
  headers.delete('Content-Security-Policy-Report-Only');

  const xfo = frameOptionsFor(policy.csp.frameAncestors);
  if (xfo) headers.set('X-Frame-Options', xfo);
  else headers.delete('X-Frame-Options');

  const nazwa = policy.csp.mode === 'enforce' ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
  headers.set(nazwa, buildCsp(policy.csp, nonce, reportEndpoint));

  // Ustalenie B4: w trybie origin nonce siedzi w treści renderowanej przez
  // aplikację, a nagłówek powstaje przy każdym żądaniu. Zbuforowany dokument
  // niesie stary nonce i wszystkie skrypty zostają zablokowane.
  if (policy.csp.nonce === 'origin') headers.set('Cache-Control', 'private, no-store');
}
