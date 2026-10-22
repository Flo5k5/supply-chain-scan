// OSV.dev REST client for the deployed-stack check. osv-scanner (the binary)
// judges lockfiles; this judges *pinned versions of deployed components*
// straight from a stack inventory, which no lockfile describes. Same API the
// veille tools use, zero dependencies, fetch injectable for tests.
const UA = 'supply-chain-scan (+https://github.com/Flo5k5/supply-chain-scan)';
const API = 'https://api.osv.dev/v1';
const TIMEOUT_MS = 10000;

// Ecosystems OSV can query by name+version and that this tool documents.
export const STACK_ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'crates.io', 'NuGet'];

async function call(path, body, fetcher) {
  const init = {
    headers: { 'User-Agent': UA, Accept: 'application/json' },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  };
  if (body !== undefined) {
    init.method = 'POST';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetcher(`${API}${path}`, init);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * Query OSV for several exact (ecosystem, name, version) pins in one call.
 * @param {Array<{eco:string,name:string,version:string}>} pins
 * @returns {Promise<Array<{ok:boolean, vulns?:string[], error?:string}>>}
 *   one result per pin, same order — a batch is all-or-nothing, so `ok:false`
 *   is reported once for every pin.
 */
export async function queryBatch(pins, fetcher = fetch) {
  const queries = pins.map((p) => ({
    package: { ecosystem: p.eco, name: p.name },
    version: p.version,
  }));
  const json = await call('/querybatch', { queries }, fetcher);
  const results = Array.isArray(json.results) ? json.results : [];
  return pins.map((_, i) => {
    const vulns = results[i] && Array.isArray(results[i].vulns)
      ? results[i].vulns.map((v) => v.id).filter((id) => typeof id === 'string')
      : [];
    return { ok: true, vulns };
  });
}

/** Map a CVSS score to a short label; null when no score is available. */
export function severityLabel(vuln) {
  const scores = [];
  for (const s of vuln.severity || []) {
    // score is "CVSS:3.1/..." vector text; the numeric score is in database_specific
    // or already parsed by OSV — read both shapes defensively.
    const n = typeof s.score === 'number' ? s.score : null;
    if (n != null) scores.push(n);
  }
  const ds = vuln.database_specific && vuln.database_specific.severity;
  if (ds === 'CRITICAL' || ds === 'HIGH') scores.push(ds === 'CRITICAL' ? 9.5 : 8.5);
  if (!scores.length) return null;
  const top = Math.max(...scores);
  if (top >= 9) return 'critical';
  if (top >= 7) return 'high';
  if (top >= 4) return 'medium';
  return 'low';
}

/** First "fixed" version OSV records for the package, or null. */
export function fixedVersion(vuln, eco, name) {
  for (const aff of vuln.affected || []) {
    const pkg = aff.package || {};
    if (pkg.ecosystem !== eco || pkg.name !== name) continue;
    for (const range of aff.ranges || []) {
      for (const ev of range.events || []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

/** Fetch one advisory's details (aliases, severity, fixed ranges). */
export async function vulnDetails(id, fetcher = fetch) {
  return call(`/vulns/${encodeURIComponent(id)}`, undefined, fetcher);
}
