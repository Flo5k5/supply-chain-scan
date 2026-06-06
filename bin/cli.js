#!/usr/bin/env node
// supply-chain-scan — morning supply-chain safety scan for npm / PyPI / Docker.
// Zero dependencies. Catches known-malicious packages + CVEs (osv-scanner),
// flags freshly-published deps, checks the release-cooldown / digest pinning.
import { resolve, basename } from 'node:path';
import { existsSync, statSync, readFileSync } from 'node:fs';
import { detect } from '../lib/detect.js';
import { osvScan, audit, pinning, freshness, dockerfile, imageScan } from '../lib/checks.js';
import { header, section, verdict, c } from '../lib/output.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

function printHelp() {
  process.stdout.write(`supply-chain-scan v${pkg.version}

  Morning supply-chain safety scan for npm / PyPI / Docker projects.
  Known-malicious packages + CVEs, freshly-published deps, release-cooldown / digest pinning.

USAGE
  supply-chain-scan [project-dir] [options]

OPTIONS
  --fresh-days <N>   flag deps published less than N days ago (default 3)
  --images           also pull & scan Docker base images for CVEs (slow, opt-in)
  --json             machine-readable output
  --no-color         disable ANSI colors
  -h, --help         show this help
  -v, --version      show version

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
let images = false;
let json = false;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  else if (a === '--version' || a === '-v') { process.stdout.write(pkg.version + '\n'); process.exit(0); }
  else if (a === '--images') images = true;
  else if (a === '--json') json = true;
  else if (a === '--no-color') process.env.NO_COLOR = '1';
  else if (a === '--fresh-days') freshDays = parseInt(argv[++i], 10) || 3;
  else if (a.startsWith('--fresh-days=')) freshDays = parseInt(a.slice(13), 10) || 3;
  else if (a.startsWith('-')) { process.stderr.write(`Unknown option: ${a}\n`); process.exit(2); }
  else if (!dir) dir = a;
}
dir = resolve(dir || process.cwd());
if (!existsSync(dir) || !statSync(dir).isDirectory()) {
  process.stderr.write(`Not a directory: ${dir}\n`);
  process.exit(2);
}

const name = basename(dir);
const d = detect(dir);

if (d.empty) {
  if (json) process.stdout.write(JSON.stringify({ project: name, dir, ecosystems: [], results: [], code: 0 }) + '\n');
  else process.stdout.write(`No JS / Python / Docker project here — nothing to scan.\n`);
  process.exit(0);
}

// --- run checks ---
const results = [];
results.push(osvScan(dir, d));
results.push(audit(dir, d));
results.push(pinning(dir, d));
results.push(await freshness(dir, d, freshDays));
if (d.docker) {
  results.push(dockerfile(d));
  if (images) results.push(imageScan(d));
}

// --- exit code ---
const lines = results.flatMap((r) => r.lines);
const review = lines.some((l) => l.status === 'fail' || l.status === 'warn');
const scannerMissing = results.some((r) => r.setup);
const code = review ? 1 : scannerMissing ? 2 : 0;

// --- output ---
const ecosystems = [
  d.npm && `npm(${d.npm.pm})`,
  d.python && `PyPI${d.python.usesUv ? '(uv)' : ''}`,
  d.docker && `Docker(${d.docker.baseImages.length} img)`,
].filter(Boolean);

if (json) {
  process.stdout.write(JSON.stringify({ project: name, dir, ecosystems, results, code }, null, 2) + '\n');
} else {
  header(`Supply-chain scan — ${name}`, dir);
  process.stdout.write(`   ${c.dim('detected:')} ${ecosystems.join(' · ')}\n`);
  for (const r of results) section(r);
  verdict(code, name);
  if (scannerMissing) process.stdout.write(c.dim('\n  tip: install osv-scanner for the known-malicious + CVE layer.\n'));
}
process.exit(code);
