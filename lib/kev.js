// CISA Known Exploited Vulnerabilities (KEV) cross-check.
// Severity says what an attacker COULD do; the KEV catalog says what they
// ALREADY do. A vulnerability that sits in the catalog is a different class
// of urgency, so findings that match it get flagged above the rest.
// The catalog is fetched at most once a day and cached on disk (see state.js
// for the cache dir); offline runs degrade to a blind spot, never to silence.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

export const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CACHE_FILE = 'kev.json';
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

/** Pure: map the catalog JSON to a Set of CVE ids. Returns null if malformed. */
export function kevFromCatalog(json) {
  const vulns = json && Array.isArray(json.vulnerabilities) ? json.vulnerabilities : null;
  if (!vulns) return null;
  const ids = new Set();
  for (const v of vulns) {
    if (v && typeof v.cveID === 'string') ids.add(v.cveID);
  }
  return ids;
}

/**
 * Load the KEV catalog, using the on-disk cache when it is fresh enough.
 * `fetcher` (defaults to global fetch) and `now` are injectable for tests.
 * Never throws: returns { ids, ok, error } — ok=false means the caller must
 * report a blind spot, an empty KEV match proves nothing then.
 */
export async function loadKev({ cacheDir, fetcher = fetch, now = Date.now() } = {}) {
  const cachePath = cacheDir ? join(cacheDir, CACHE_FILE) : null;
  if (cachePath) {
    try {
      const cached = JSON.parse(readFileSync(cachePath, 'utf8'));
      const { json, fetchedAt } = cached;
      const ids = kevFromCatalog(json);
      if (ids && typeof fetchedAt === 'number' && now - fetchedAt < MAX_AGE_MS) {
        return { ids, ok: true };
      }
    } catch {
      /* no usable cache — fall through to the network */
    }
  }
  try {
    const res = await fetcher(KEV_URL, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    const ids = kevFromCatalog(json);
    if (!ids) throw new Error('malformed catalog');
    if (cachePath) {
      try {
        mkdirSync(cacheDir, { recursive: true });
        writeFileSync(cachePath, JSON.stringify({ fetchedAt: now, json }));
      } catch {
        /* cache write is best-effort */
      }
    }
    return { ids, ok: true };
  } catch (e) {
    return { ids: new Set(), ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/**
 * Pure: does an advisory (by OSV/GHSA id or CVE aliases) sit in the KEV set?
 * Used to upgrade matching findings to `fail` regardless of severity.
 */
export function isKnownExploited(id, aliases, kevIds) {
  if (!kevIds || !kevIds.size) return false;
  if (id && kevIds.has(id)) return true;
  if (Array.isArray(aliases)) {
    for (const a of aliases) if (kevIds.has(a)) return true;
  }
  return false;
}
