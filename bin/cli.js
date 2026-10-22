#!/usr/bin/env node
// supply-chain-scan — morning supply-chain safety scan for npm / PyPI / Docker.
// Zero dependencies. Catches known-malicious packages + CVEs (osv-scanner),
// flags freshly-published deps, checks the release-cooldown / digest pinning.
import { resolve, basename } from 'node:path';
import { existsSync, statSync, readFileSync } from 'node:fs';
import { detect } from '../lib/detect.js';
import { osvScan, audit, pinning, installTimeProtection, freshness, dockerfile, imageScan, buildManifestScan, undeclaredLargeJsRoots, agentConfigScan } from '../lib/checks.js';
import { deployedCheck, findStackFile } from '../lib/deployed.js';
import { loadKev } from '../lib/kev.js';
import { cacheDir, loadState, saveState, resetState } from '../lib/state.js';
import { header, section, verdict, blindspots, c } from '../lib/output.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

function printHelp() {
  process.stdout.write(`supply-chain-scan v${pkg.version}

  Morning supply-chain safety scan for npm / PyPI / Docker projects.
  Known-malicious packages + CVEs, freshly-published deps, release-cooldown / digest pinning.

USAGE
  supply-chain-scan [project-dir] [options]

OPTIONS
  --fresh-days <N>   flag deps published less than N days ago (default 3)
  --max-js-mb <N>    flag undeclared root JS/TS files larger than N MB (default 0.5)
  --no-recursive     scan only the root dir, not nested packages (recursive by default)
  --depth <N>        max directory depth for the recursive scan (default 5)
  --no-agent-configs skip the agent/IDE auto-exec-on-open check (on by default)
  --images           also pull & scan Docker base images for CVEs (slow, opt-in)
  --stack <file>     scan a deployed-component inventory (default: auto-detect
                     stack.yaml / stack.yml / stack.json in the project root)
  --no-stack         skip the deployed-stack check even if an inventory exists
  --no-kev           skip the CISA KEV (known-exploited) cross-check
  --no-state         don't read/write the per-project delta state (report everything)
  --reset-state      drop the per-project state before scanning, then re-baseline
  --json             machine-readable output
  --no-color         disable ANSI colors
  -h, --help         show this help
  -v, --version      show version

Recursive scan finds lockfiles in nested packages / monorepos (skipping node_modules,
build output and vendored dirs). On a very large workspace it can be slow — use
--no-recursive or --depth to bound it.

EXIT CODES
  0  clean       1  review (findings)       2  setup (osv-scanner not installed)

Requires osv-scanner on PATH for the malicious/CVE layer:
  macOS/Linux  brew install osv-scanner
  Windows      winget install Google.OSVScanner
`);
}

// --- args ---
const argv = process.argv.slice(2);
let dir = null;
let freshDays = 3;
let maxJsMb = 0.5;
let agentConfigs = true;
let recursive = true;
let maxDepth = 5;
let images = false;
let json = false;
let stackFile = undefined;   // undefined = auto-detect; null = disabled
let kevOn = true;
let stateOn = true;
let resetStateFirst = false;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  else if (a === '--version' || a === '-v') { process.stdout.write(pkg.version + '\n'); process.exit(0); }
  else if (a === '--images') images = true;
  else if (a === '--json') json = true;
  else if (a === '--no-color') process.env.NO_COLOR = '1';
  else if (a === '--no-agent-configs') agentConfigs = false;
  else if (a === '--agent-configs') agentConfigs = true;
  else if (a === '--no-recursive') recursive = false;
  else if (a === '--recursive') recursive = true;
  else if (a === '--depth') maxDepth = parseInt(argv[++i], 10) || 5;
  else if (a.startsWith('--depth=')) maxDepth = parseInt(a.slice(8), 10) || 5;
  else if (a === '--fresh-days') freshDays = parseInt(argv[++i], 10) || 3;
  else if (a.startsWith('--fresh-days=')) freshDays = parseInt(a.slice(13), 10) || 3;
  else if (a === '--max-js-mb') maxJsMb = parseFloat(argv[++i]) || 0.5;
  else if (a.startsWith('--max-js-mb=')) maxJsMb = parseFloat(a.slice(12), 10) || 0.5;
  else if (a === '--stack') stackFile = argv[++i];
  else if (a.startsWith('--stack=')) stackFile = a.slice(8);
  else if (a === '--no-stack') stackFile = null;
  else if (a === '--no-kev') kevOn = false;
  else if (a === '--no-state') stateOn = false;
  else if (a === '--reset-state') resetStateFirst = true;
  else if (a.startsWith('-')) { process.stderr.write(`Unknown option: ${a}\n`); process.exit(2); }
  else if (!dir) dir = a;
}
dir = resolve(dir || process.cwd());
if (!existsSync(dir) || !statSync(dir).isDirectory()) {
  process.stderr.write(`Not a directory: ${dir}\n`);
  process.exit(2);
}

const name = basename(dir);
const d = detect(dir, { recursive, maxDepth });

// Deployed-stack inventory: explicit --stack wins, else auto-detected at root.
const stack = stackFile === null ? null : stackFile || findStackFile(dir);
if (stack && !existsSync(resolve(dir, stack))) {
  process.stderr.write(`Stack inventory not found: ${stack}\n`);
  process.exit(2);
}

if (d.empty && !stack) {
  // Absence of scope is NOT a clean bill of health — say so instead of a
  // green exit that reads as "checked and fine" (a Docker-compose deployment,
  // system packages or a deployed stack are simply not this scan's inputs).
  const msg = 'No lockfile, Dockerfile/compose, build manifest, agent config or stack inventory found — nothing was scanned. This is absence of scope, not a clean result: deployed services, system packages and images pinned outside this tree are NOT covered here.';
  if (json) process.stdout.write(JSON.stringify({ project: name, dir, ecosystems: [], results: [], blindSpots: [msg], code: 0 }) + '\n');
  else {
    header(`Supply-chain scan — ${name}`, dir);
    process.stdout.write(`  ${c.yellow('!')} ${msg}\n`);
  }
  process.exit(0);
}

// --- CISA KEV cross-check (cached 24h; failure = blind spot, never silence) ---
let kev = null;
const blindSpots = [];
if (kevOn) {
  kev = await loadKev({ cacheDir: cacheDir() });
  if (!kev.ok) blindSpots.push(`CISA KEV catalog unavailable (${kev.error}) — "no KEV match" does NOT mean not exploited`);
}

// --- run checks ---
const results = [];
results.push(osvScan(dir, d, kev));
results.push(audit(dir, d));
results.push(pinning(dir, d));
results.push(installTimeProtection(d));
results.push(buildManifestScan(dir, d));
results.push(undeclaredLargeJsRoots(dir, maxJsMb));
results.push(await freshness(dir, d, freshDays));
if (agentConfigs) results.push(agentConfigScan(dir, d));
if (d.docker) {
  results.push(dockerfile(d));
  if (images) results.push(imageScan(d));
}
let pendingState = null;
if (stack) {
  if (resetStateFirst) resetState(dir);
  const state = stateOn ? loadState(dir) : { v: 1, osv: {} };
  const dep = await deployedCheck(dir, stack, { state, kev });
  results.push(dep);
  blindSpots.push(...(dep.blindSpots || []));
  if (stateOn && dep.nextState) pendingState = dep.nextState; // persist only on success
}

// --- exit code ---
const lines = results.flatMap((r) => r.lines);
const review = lines.some((l) => l.status === 'fail' || l.status === 'warn');
const scannerMissing = results.some((r) => r.setup);
const code = review ? 1 : scannerMissing ? 2 : 0;

// Persist the delta state only when the run produced trustworthy data: never
// on a setup failure (the advisory layer didn't run) — that would mark
// everything as "seen" without having checked it.
if (pendingState && !scannerMissing) saveState(dir, pendingState);

// --- output ---
const ecosystems = [
  d.npm && `npm(${d.npm.pm})`,
  d.python && `PyPI${d.python.usesUv ? '(uv)' : ''}`,
  d.docker && `Docker(${d.docker.baseImages.length} img)`,
  d.goRust && `Go/Rust(${d.goRust.locks.length})`,
  stack && `stack(${stack})`,
  d.nestedLocks > 0 && `+${d.nestedLocks} nested lock(s)`,
  d.buildManifests.length && `build(${d.buildManifests.length})`,
  d.agentConfigs.length && `agent-cfg(${d.agentConfigs.length})`,
].filter(Boolean);

if (json) {
  process.stdout.write(JSON.stringify({ project: name, dir, ecosystems, results, blindSpots, kev: kevOn ? kev.ok : 'skipped', code }, null, 2) + '\n');
} else {
  header(`Supply-chain scan — ${name}`, dir);
  process.stdout.write(`   ${c.dim('detected:')} ${ecosystems.join(' · ')}\n`);
  for (const r of results) section(r);
  blindspots(blindSpots);
  verdict(code, name);
  if (scannerMissing) process.stdout.write(c.dim('\n  tip: install osv-scanner for the known-malicious + CVE layer.\n'));
}
process.exit(code);
