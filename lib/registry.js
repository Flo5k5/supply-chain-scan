// Publish-date lookups against the public npm and PyPI registries, using the
// built-in fetch (Node >=18). No data is sent beyond the package name.
const UA = 'supply-chain-scan (+https://github.com/Flo5k5/supply-chain-scan)';
const TIMEOUT_MS = 8000;

async function getJson(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': UA, Accept: 'application/json' },
      signal: ctrl.signal,
    });
    if (!res.ok) return null; // 404 (unknown), 429 (rate-limited) → treat as "unknown"
    return await res.json();
  } catch {
    return null; // network/timeout → unknown, never throw
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Returns the publish `Date` of a specific version, or null if unknown.
 * @param {'npm'|'PyPI'} ecosystem
 */
export async function publishDate(ecosystem, name, version) {
  if (ecosystem === 'npm') {
    // Scoped names (@scope/pkg) must keep the slash encoded as %2F.
    const enc = name.startsWith('@') ? name.replace('/', '%2F') : encodeURIComponent(name);
    const d = await getJson(`https://registry.npmjs.org/${enc}`);
    const t = d && d.time && d.time[version];
    return t ? new Date(t) : null;
  }
  if (ecosystem === 'PyPI') {
    const d = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    const files = d && d.releases && d.releases[version];
    const iso = Array.isArray(files) && files[0] && files[0].upload_time_iso_8601;
    return iso ? new Date(iso) : null;
  }
  return null;
}

/** Whole days between `date` and now (floored). */
export function ageInDays(date) {
  return Math.floor((Date.now() - date.getTime()) / 86_400_000);
}
