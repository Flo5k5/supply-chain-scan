// The deployed-stack check. Everything else in this tool judges a *repo*
// (lockfiles, Dockerfiles, configs) — but the components that actually run in
// production are pinned versions that no lockfile describes: the Docker image
// tag you deploy, the CLI on the server, the framework version in prod. A
// stack inventory file (stack.yaml / stack.json) lists them; this check asks
// OSV.dev for each pin, diffs against the previous successful run (only NEW
// advisories make noise — first run is a baseline), and marks anything that
// sits in the CISA KEV catalog as known-exploited.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { queryBatch, vulnDetails, severityLabel, fixedVersion, STACK_ECOSYSTEMS } from './osvapi.js';
import { diffVulns, nextState } from './state.js';
import { isKnownExploited } from './kev.js';

export const STACK_FILES = ['stack.yaml', 'stack.yml', 'stack.json'];

export function findStackFile(dir) {
  for (const f of STACK_FILES) {
    try {
      readFileSync(join(dir, f));
      return f;
    } catch {
      /* try next */
    }
  }
  return null;
}

/**
 * Pure parser for the stack inventory. Accepted shape (either syntax):
 *   components:
 *     - name: litellm
 *       version: "1.106.2"
 *       ecosystem: PyPI
 * JSON variant: {"components":[{"name":…,"version":…,"ecosystem":…}]}
 * `ecosystem` must be one OSV can query (STACK_ECOSYSTEMS). Unknown keys and
 * comments are ignored; a malformed list yields {error}.
 */
export function parseStack(text, isJson) {
  let comps;
  if (isJson) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return { error: 'stack.json is not valid JSON' };
    }
    comps = parsed && Array.isArray(parsed.components) ? parsed.components : null;
  } else {
    comps = null;
    let inComponents = false;
    let current = null;
    for (const raw of text.split('\n')) {
      const line = raw.replace(/#.*$/, '').trimEnd();
      if (!line.trim()) continue;
      if (/^components:\s*$/.test(line)) { inComponents = true; comps = []; continue; }
      if (!inComponents) continue;
      const item = /^\s*-\s*/.test(line);
      const body = line.replace(/^\s*-\s*/, '').trim();
      const kv = /^([A-Za-z_]+)\s*:\s*(.+)$/.exec(body);
      if (item) {
        if (current) comps.push(current);
        current = {};
      }
      if (kv && current) {
        current[kv[1]] = kv[2].trim().replace(/^["']|["']$/g, '');
      } else if (!item && !kv && line && !/^\s/.test(raw)) {
        inComponents = false; // left the components block
      }
    }
    if (current) comps.push(current);
  }
  if (!comps) return { error: 'no "components:" list found' };
  const out = [];
  for (const c of comps) {
    if (!c || typeof c !== 'object') continue;
    const { name, version, ecosystem } = c;
    if (!name || !version || !ecosystem) {
      return { error: `component needs name, version and ecosystem (got ${JSON.stringify(c)})` };
    }
    if (!STACK_ECOSYSTEMS.includes(ecosystem)) {
      return { error: `ecosystem "${ecosystem}" not supported (one of: ${STACK_ECOSYSTEMS.join(', ')}) — for ${name}` };
    }
    out.push({ eco: ecosystem, name: String(name), version: String(version) });
  }
  if (!out.length) return { error: 'empty components list' };
  return { components: out };
}

/**
 * Run the deployed-stack check.
 * @returns {Promise<{title, lines, blindSpots:string[], nextState?}>}
 *   `nextState` is present only when the OSV data is trustworthy — the caller
 *   persists it, a failed run leaves the previous state untouched.
 */
export async function deployedCheck(dir, stackFile, { state, kev, fetcher = fetch, detailFetcher = fetch } = {}) {
  const title = `deployed stack — ${stackFile} vs OSV.dev`;
  const src = readFileSync(join(dir, stackFile), 'utf8');
  const parsed = parseStack(src, stackFile.endsWith('.json'));
  if (parsed.error) {
    return { title, lines: [{ status: 'warn', text: `${stackFile}: ${parsed.error}` }], blindSpots: [] };
  }
  const pins = parsed.components;

  let results;
  try {
    results = await queryBatch(pins, fetcher);
  } catch (e) {
    return {
      title,
      lines: [{ status: 'warn', text: `OSV.dev unreachable (${e.message}) — ${pins.length} pinned component(s) NOT checked` }],
      blindSpots: ['OSV.dev API unreachable — deployed-stack advisories not checked'],
    };
  }

  const lines = [{ status: 'info', text: `${pins.length} pinned component(s): ${pins.map((p) => `${p.name}@${p.version}`).join(', ')}` }];
  const blindSpots = [];
  const deltas = [];
  let anyFresh = false;

  for (let i = 0; i < pins.length; i++) {
    const p = pins[i];
    const r = results[i];
    if (!r.ok) continue; // batch-level failure already reported above
    const key = `${p.eco}:${p.name}@${p.version}`;
    const delta = diffVulns(key, r.vulns, state);
    deltas.push({ key, known: delta.known });

    if (!r.vulns.length) {
      lines.push({ status: 'ok', text: `${p.name}@${p.version} [${p.eco}] — no known advisories` });
      continue;
    }
    if (delta.firstRun) {
      lines.push({
        status: 'warn',
        text: `${p.name}@${p.version} [${p.eco}] — ${r.vulns.length} known advisories (first run: baseline, not new; re-run to persist)` ,
      });
      anyFresh = true;
      continue;
    }
    if (!delta.fresh.length) {
      lines.push({ status: 'ok', text: `${p.name}@${p.version} [${p.eco}] — ${r.vulns.length} known (already reported previously)` });
      continue;
    }
    anyFresh = true;
    for (const id of delta.fresh) {
      let text = `${p.name}@${p.version} [${p.eco}] — NEW ${id}`;
      try {
        const v = await vulnDetails(id, detailFetcher);
        const sev = severityLabel(v);
        const fixed = fixedVersion(v, p.eco, p.name);
        const aliasCves = (v.aliases || []).filter((a) => a.startsWith('CVE-'));
        const cve = aliasCves.length ? ` (aka ${aliasCves.slice(0, 2).join(', ')})` : '';
        const fx = fixed ? `, fixed in ${fixed}` : '';
        text = `${p.name}@${p.version} [${p.eco}] — NEW ${id}${cve}${sev ? ` [${sev}]` : ''}${fx}`;
        if (isKnownExploited(id, v.aliases, kev && kev.ids)) {
          lines.push({ status: 'fail', text: `${text} — KNOWN EXPLOITED (CISA KEV)` });
          continue;
        }
      } catch {
        /* details are enrichment — the id line stands without them */
      }
      lines.push({ status: 'warn', text });
    }
  }

  if (!kev || !kev.ok) {
    blindSpots.push('CISA KEV catalog unavailable — "no KEV match" does NOT mean not exploited');
  }
  if (anyFresh) {
    lines.push({ status: 'info', text: 'OSV ingests advisories with lag — for a same-day incident, also check the vendor channel directly' });
  }

  return { title, lines, blindSpots, nextState: nextState(state, deltas) };
}
