/**
 * Centralna warstwa nagłówków bezpieczeństwa dla wszystkich aplikacji.
 *
 * Jeden Worker wpięty w routes kilku hostów. Polityka domyślna w kodzie,
 * nadpisania per host w KV, więc zmiana polityki nie wymaga wdrożenia.
 *
 * UWAGA: ten Worker stoi na ścieżce ruchu produkcyjnego. Jego awaria to
 * niedostępne strony, dlatego cały handler jest opakowany w przechwytywanie
 * błędów z zachowaniem ruchu (fail-open na nagłówkach, nigdy na dostępności).
 *
 * Stan: NIEWDROŻONY. Wdrożenie wyłącznie etapami, zaczynając od jednego
 * hosta w trybie report-only. Patrz README.md.
 */

import { loadPolicy, NONCE_PLACEHOLDER, REPORT_PATH } from './policy.js';
import { applySecurityHeaders, isHtmlResponse, shouldRewrite } from './headers.js';
import { handleCspReport } from './report.js';

export default {
  async fetch(request, env, ctx) {
    try {
      return await obsluz(request, env, ctx);
    } catch (error) {
      // Ostatnia linia obrony. Strona musi się otworzyć nawet wtedy, gdy nasza
      // warstwa nagłówków jest zepsuta.
      console.error('warstwa nagłówków zawiodła, ruch przechodzi bez zmian', error);
      try {
        return await fetch(request);
      } catch {
        return new Response('Bad gateway', { status: 502 });
      }
    }
  },
};

async function obsluz(request, env, ctx) {
  const url = new URL(request.url);

  if (url.pathname === REPORT_PATH) return handleCspReport(request, env, ctx);

  const { policy, problems } = await loadPolicy(url.hostname, env);

  // Wyłącznik globalny: przepuszczamy ruch bez żadnych modyfikacji.
  if (!policy) return fetch(request);

  if (problems.length) console.warn(`polityka ${url.hostname}:`, problems.join(' | '));

  const nonce = policy.csp.enabled && policy.csp.nonce !== 'off' ? generateNonce() : null;

  // Kopia żądania z mutowalnymi nagłówkami. Kasujemy x-csp-nonce, żeby klient
  // nie mógł podstawić własnej wartości z zewnątrz.
  const upstream = new Request(request);
  upstream.headers.delete('x-csp-nonce');
  if (nonce) upstream.headers.set('x-csp-nonce', nonce);

  const originResponse = await fetch(upstream);

  const contentType = originResponse.headers.get('content-type') ?? '';
  const isHtml = isHtmlResponse(contentType);

  const response = new Response(originResponse.body, originResponse);
  applySecurityHeaders(response.headers, { policy, nonce, isHtml, url });

  if (!shouldRewrite(originResponse.status, contentType, policy, nonce)) return response;

  // HTMLRewriter zmienia długość treści, więc Content-Length przestaje być prawdziwy.
  response.headers.delete('content-length');
  return nonceRewriter(nonce, policy.csp.nonce).transform(response);
}

function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

function nonceRewriter(nonce, mode) {
  const handler =
    mode === 'placeholder'
      ? {
          element(element) {
            if (element.getAttribute('nonce') === NONCE_PLACEHOLDER) element.setAttribute('nonce', nonce);
          },
        }
      : {
          element(element) {
            element.setAttribute('nonce', nonce);
          },
        };

  return new HTMLRewriter()
    .on('script', handler)
    .on('style', handler)
    .on('link[rel="stylesheet"]', handler);
}
