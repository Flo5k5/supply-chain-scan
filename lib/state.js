// Per-project delta state for the deployed-stack check. Without memory, a
// daily scan re-prints every known vulnerability every morning and the one
// that appeared overnight drowns in the noise. The state stores, per pinned
// component, the advisory ids already reported; only NEW ids make noise.
// Borrowed from proven digest-watch tooling: a run that fails never writes
// state (nothing gets marked "seen" that was never actually checked), and a
// first run is a baseline, not an alarm.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function cacheRoot() {
  if (process.env.SUPPLY_CHAIN_SCAN_CACHE) return process.env.SUPPLY_CHAIN_SCAN_CACHE;
  if (process.env.XDG_CACHE_HOME) return join(process.env.XDG_CACHE_HOME, 'supply-chain-scan');
  if (process.platform === 'win32') {
    return join(process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'supply-chain-scan');
  }
  return join(homedir(), '.cache', 'supply-chain-scan');
}

export function cacheDir() {
  return cacheRoot();
}

function statePath(dir) {
  const hash = createHash('sha256').update(dir).digest('hex').slice(0, 24);
  return join(cacheRoot(), `stack-${hash}.json`);
}

export function loadState(dir) {
  try {
    const raw = JSON.parse(readFileSync(statePath(dir), 'utf8'));
    if (raw && typeof raw === 'object' && raw.v === 1 && raw.osv && typeof raw.osv === 'object') {
      return raw;
    }
  } catch {
    /* missing or corrupt → fresh state */
  }
  return { v: 1, osv: {} };
}

/**
 * Pure delta used by the deployed check.
 * @returns {{ key:string, firstRun:boolean, known:string[], fresh:string[] }}
 *   `known` = everything OSV currently reports (for the baseline count),
 *   `fresh` = the subset never reported by a successful previous run.
 */
export function diffVulns(key, currentIds, state) {
  const seen = new Set(state.osv[key] || []);
  return {
    key,
    firstRun: !state.osv.hasOwnProperty(key),
    known: [...currentIds],
    fresh: currentIds.filter((id) => !seen.has(id)),
  };
}

/** Build the next state (pure): current ids replace seen ids per component. */
export function nextState(state, entries) {
  const osv = { ...state.osv };
  for (const { key, known } of entries) osv[key] = known;
  return { v: 1, updated: new Date().toISOString(), osv };
}

/** Persist only when the whole scan produced trustworthy data. Best-effort. */
export function saveState(dir, state) {
  const p = statePath(dir);
  try {
    mkdirSync(cacheRoot(), { recursive: true });
    writeFileSync(p, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}

export function resetState(dir) {
  try {
    const p = statePath(dir);
    if (existsSync(p)) rmSync(p);
    return true;
  } catch {
    return false;
  }
}
