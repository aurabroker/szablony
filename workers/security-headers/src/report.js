/**
 * Endpoint raportów CSP.
 *
 * Jest publiczny i nieuwierzytelniony z definicji, bo raporty przysyła
 * przeglądarka. Dlatego ma limity: typ treści, rozmiar, liczba wpisów
 * i próbkowanie. Bez nich da się zaśmiecić dataset i wygenerować koszt.
 */

const MAX_BODY = 64 * 1024;
const MAX_ENTRIES = 50;
const DOZWOLONE_TYPY = ['application/csp-report', 'application/reports+json', 'application/json'];

export function parseReports(payload) {
  const entries = Array.isArray(payload) ? payload : [payload];
  return entries.slice(0, MAX_ENTRIES).map((entry) => {
    const r = entry?.body ?? entry?.['csp-report'] ?? entry ?? {};
    return {
      directive: String(r.effectiveDirective ?? r['effective-directive'] ?? r['violated-directive'] ?? 'unknown'),
      documentURL: String(r.documentURL ?? r['document-uri'] ?? ''),
      blockedURL: String(r.blockedURL ?? r['blocked-uri'] ?? ''),
      sourceFile: String(r.sourceFile ?? r['source-file'] ?? ''),
      disposition: String(r.disposition ?? ''),
      lineNumber: Number(r.lineNumber ?? r['line-number'] ?? 0) || 0,
    };
  });
}

export function typDozwolony(contentType) {
  const typ = (contentType ?? '').toLowerCase().split(';')[0].trim();
  return DOZWOLONE_TYPY.includes(typ);
}

export async function handleCspReport(request, env, ctx) {
  if (request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { allow: 'POST' } });
  }
  if (!typDozwolony(request.headers.get('content-type'))) {
    return new Response(null, { status: 415 });
  }
  const dlugosc = Number(request.headers.get('content-length') ?? 0);
  if (dlugosc > MAX_BODY) return new Response(null, { status: 413 });

  const zapis = async () => {
    try {
      const text = await request.text();
      if (text.length > MAX_BODY) return;
      const raporty = parseReports(JSON.parse(text));
      const host = String(request.headers.get('host') ?? '').slice(0, 256);

      for (const r of raporty) {
        env.CSP_REPORTS?.writeDataPoint({
          indexes: [r.directive.slice(0, 32)],
          blobs: [
            host,
            r.documentURL.slice(0, 512),
            r.blockedURL.slice(0, 512),
            r.directive.slice(0, 128),
            r.sourceFile.slice(0, 512),
            r.disposition.slice(0, 32),
          ],
          doubles: [r.lineNumber],
        });
      }
    } catch {
      // Błędny raport nie może niczego zepsuć ani zwrócić błędu przeglądarce.
    }
  };

  // Zapis nie blokuje odpowiedzi dla przeglądarki.
  if (ctx?.waitUntil) ctx.waitUntil(zapis());
  else await zapis();

  return new Response(null, { status: 204 });
}
