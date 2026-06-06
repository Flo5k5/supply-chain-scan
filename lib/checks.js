// The individual checks. Each returns { title, lines:[{status,text}], setup? }
// and never throws — a check that can't run degrades to a `skip` line.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { has, run } from './spawn.js';
import { publishDate, ageInDays } from './registry.js';

function read(dir, file) {
  try {
    return readFileSync(join(dir, file), 'utf8');
  } catch {
    return null;
  }
}

export function osvInstallHint() {
  if (process.platform === 'win32') return 'winget install Google.OSVScanner   (or: scoop install osv-scanner)';
  if (process.platform === 'darwin') return 'brew install osv-scanner';
  return 'brew install osv-scanner   (or a release binary from github.com/google/osv-scanner/releases, or: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)';
}

// ── 1) osv-scanner: known-malicious (MAL-) + CVE, across all lockfiles ──────
export function osvScan(dir, d) {
  const title = 'osv-scanner — known-malicious + CVE';
  if (!d.lockfiles.length) return { title, lines: [{ status: 'skip', text: 'no package lockfiles to scan' }] };
  if (!has('osv-scanner')) {
    return {
      title,
      setup: true,
      lines: [{ status: 'skip', text: `osv-scanner not installed → ${osvInstallHint()}` }],
    };
  }
  const args = ['scan', 'source'];
  for (const l of d.lockfiles) args.push(`--lockfile=${l}`);
  args.push('--format', 'json');
  const r = run('osv-scanner', args, { cwd: dir });

  if (r.status === 0) return { title, lines: [{ status: 'ok', text: 'no known-malicious or vulnerable packages' }] };

  let parsed = null;
  try {
    parsed = JSON.parse(r.stdout);
  } catch {
    /* fall through */
  }
  if (!parsed) {
    return { title, lines: [{ status: r.status === 1 ? 'fail' : 'skip', text: 'osv-scanner reported findings — run `osv-scanner scan source` for details' }] };
  }

  const malicious = [];
  const vulns = [];
  for (const res of parsed.results || []) {
    for (const pkg of res.packages || []) {
      const p = pkg.package || {};
      for (const v of pkg.vulnerabilities || []) {
        const entry = { eco: p.ecosystem, name: p.name, version: p.version, id: v.id };
        if (typeof v.id === 'string' && v.id.startsWith('MAL-')) malicious.push(entry);
        else vulns.push(entry);
      }
    }
  }
  const lines = [];
  if (malicious.length) {
    lines.push({ status: 'fail', text: `${malicious.length} MALICIOUS package(s) flagged:` });
    for (const m of malicious.slice(0, 10)) lines.push({ status: 'fail', text: `  ${m.name}@${m.version} (${m.id}) [${m.eco}]` });
  }
  if (vulns.length) {
    const uniqPkgs = new Set(vulns.map((v) => `${v.name}@${v.version}`)).size;
    lines.push({ status: 'warn', text: `${vulns.length} known vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} across ${uniqPkgs} package(s):` });
    for (const v of vulns.slice(0, 8)) lines.push({ status: 'warn', text: `  ${v.name}@${v.version} (${v.id}) [${v.eco}]` });
    if (vulns.length > 8) lines.push({ status: 'warn', text: `  …and ${vulns.length - 8} more` });
  }
  if (!lines.length) lines.push({ status: 'fail', text: 'osv-scanner reported findings — run it for details' });
  return { title, lines };
}

// ── 2) audit: native CVE advisories per ecosystem ──────────────────────────
export function audit(dir, d) {
  const title = 'audit — CVE advisories';
  const lines = [];
  if (d.npm) {
    const pm = d.npm.pm;
    const args =
      pm === 'yarn' ? ['audit', '--level', 'high'] :
      pm === 'bun' ? ['audit'] :
      ['audit', '--audit-level=high'];
    if (has(pm)) {
      const r = run(pm, args, { cwd: dir });
      lines.push(r.ok
        ? { status: 'ok', text: `${pm}: no high/critical advisories` }
        : { status: 'fail', text: `${pm} audit reported advisories — run \`${pm} ${args.join(' ')}\`` });
    } else {
      lines.push({ status: 'skip', text: `${pm} not on PATH — npm audit skipped` });
    }
  }
  if (d.python) {
    if (has('pip-audit')) {
      const r = run('pip-audit', ['--progress-spinner=off'], { cwd: dir });
      lines.push(r.ok
        ? { status: 'ok', text: 'pip-audit: no advisories' }
        : { status: 'fail', text: 'pip-audit reported advisories — run `pip-audit`' });
    } else {
      lines.push({ status: 'skip', text: 'pip-audit not installed — Python CVEs already covered by osv-scanner' });
    }
  }
  if (!lines.length) lines.push({ status: 'skip', text: 'no package manager to audit' });
  return { title, lines };
}

// ── 3) pinning / cooldown: control over fresh/mutable resolution ───────────
const NPM_COOLDOWN_RE = /^\s*(minimumReleaseAge\s*:|minimum-release-age\s*=)/m;
const UV_EXCLUDE_RE = /^\s*exclude-newer\s*=/m;

export function pinning(dir, d) {
  const title = 'pinning / cooldown';
  const lines = [];
  if (d.npm) {
    const ws = read(dir, 'pnpm-workspace.yaml') || '';
    const npmrc = read(dir, '.npmrc') || '';
    const hit = NPM_COOLDOWN_RE.exec(ws) || NPM_COOLDOWN_RE.exec(npmrc);
    if (hit) {
      lines.push({ status: 'ok', text: `npm: release cooldown configured (${hit[0].trim().replace(/[:=]$/, '')})` });
    } else if (d.npm.pm === 'pnpm') {
      lines.push({ status: 'warn', text: 'npm: no minimumReleaseAge — add to pnpm-workspace.yaml: `minimumReleaseAge: 4320` (3 days)' });
    } else {
      lines.push({ status: 'info', text: `${d.npm.pm}: no native release cooldown — this scan is the gate` });
    }
  }
  if (d.python) {
    if (d.python.usesUv) {
      const pp = read(dir, 'pyproject.toml') || '';
      const uvt = read(dir, 'uv.toml') || '';
      const has1 = UV_EXCLUDE_RE.test(pp) || UV_EXCLUDE_RE.test(uvt);
      lines.push(has1
        ? { status: 'ok', text: 'PyPI(uv): exclude-newer configured' }
        : { status: 'warn', text: 'PyPI(uv): no exclude-newer — add `exclude-newer = "<ISO date>"` under [tool.uv]' });
    } else {
      lines.push({ status: 'info', text: 'PyPI(pip/poetry): no native cooldown — this scan is the gate' });
    }
  }
  if (!lines.length) lines.push({ status: 'skip', text: 'nothing to check' });
  return { title, lines };
}

// ── 4) freshness: recently-changed deps published < freshDays ago ──────────
const NPM_SPEC = /(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+@\d+\.\d+\.\d+/gi;
const PY_SPEC = /[a-z0-9._-]+==\d+[\w.]*/gi;

export async function freshness(dir, d, freshDays) {
  const title = `freshness — deps changed recently & published < ${freshDays}d ago (zero-hour)`;
  if (!has('git')) return { title, lines: [{ status: 'skip', text: 'git not available — age check skipped' }] };
  const repo = run('git', ['rev-parse', '--is-inside-work-tree'], { cwd: dir });
  if (!repo.ok) return { title, lines: [{ status: 'skip', text: 'not a git repo — age check skipped' }] };

  const targets = [];
  if (d.npm) targets.push({ file: d.npm.lock, eco: 'npm', re: NPM_SPEC, sep: '@' });
  if (d.python) for (const f of d.python.reqFiles) targets.push({ file: f, eco: 'PyPI', re: PY_SPEC, sep: '==' });

  const candidates = new Map(); // key → {eco,name,version}
  for (const t of targets) {
    const diffs = [
      run('git', ['diff', 'HEAD', '--', t.file], { cwd: dir }).stdout,
      run('git', ['diff', 'HEAD~1', 'HEAD', '--', t.file], { cwd: dir }).stdout,
    ].join('\n');
    for (const raw of diffs.split('\n')) {
      if (!raw.startsWith('+') || raw.startsWith('+++')) continue;
      for (const m of raw.match(t.re) || []) {
        const at = m.lastIndexOf(t.sep);
        const name = m.slice(0, at);
        const version = m.slice(at + t.sep.length);
        candidates.set(`${t.eco}:${name}@${version}`, { eco: t.eco, name, version });
        if (candidates.size >= 40) break;
      }
    }
  }
  if (!candidates.size) return { title, lines: [{ status: 'ok', text: 'no recently-changed deps to age-check' }] };

  const lines = [];
  for (const { eco, name, version } of candidates.values()) {
    const date = await publishDate(eco, name, version);
    if (!date) continue;
    const age = ageInDays(date);
    if (age < freshDays) lines.push({ status: 'warn', text: `${name}@${version} [${eco}] — published ${age}d ago (fresh; vet before trusting)` });
  }
  if (!lines.length) lines.push({ status: 'ok', text: `recently-changed deps are all ≥ ${freshDays}d old` });
  return { title, lines };
}

// ── 5) Dockerfile hygiene: base images pinned by digest ────────────────────
export function dockerfile(d) {
  const title = 'Docker — base image pinning';
  const imgs = (d.docker && d.docker.baseImages) || [];
  if (!imgs.length) return { title, lines: [{ status: 'skip', text: 'no resolvable base images' }] };
  const unpinned = imgs.filter((i) => !i.pinned);
  if (!unpinned.length) return { title, lines: [{ status: 'ok', text: `all ${imgs.length} base image(s) pinned by @sha256: digest` }] };
  const lines = [{ status: 'warn', text: `${unpinned.length}/${imgs.length} base image(s) NOT pinned by digest (mutable tag — can be re-pointed):` }];
  for (const i of unpinned.slice(0, 10)) lines.push({ status: 'warn', text: `  ${i.ref}  (${i.file}) → pin to image@sha256:<digest>` });
  return { title, lines };
}

// ── 6) image scan (opt-in --images): CVEs in base image layers ─────────────
export function imageScan(d) {
  const title = 'Docker — base image vulnerabilities (--images)';
  const imgs = [...new Map((d.docker?.baseImages || []).map((i) => [i.ref, i])).values()];
  if (!imgs.length) return { title, lines: [{ status: 'skip', text: 'no base images to scan' }] };

  const tool = has('osv-scanner') ? 'osv-scanner' : has('trivy') ? 'trivy' : null;
  if (!tool) {
    return { title, lines: [{ status: 'skip', text: `need osv-scanner or trivy to scan images → ${osvInstallHint()}` }] };
  }
  const lines = [];
  for (const i of imgs) {
    const r =
      tool === 'osv-scanner'
        ? run('osv-scanner', ['scan', 'image', i.ref])
        : run('trivy', ['image', '--quiet', '--severity', 'HIGH,CRITICAL', i.ref]);
    if (r.missing) {
      lines.push({ status: 'skip', text: `${i.ref}: ${tool} could not run` });
    } else if (r.ok) {
      lines.push({ status: 'ok', text: `${i.ref}: no high/critical findings (${tool})` });
    } else {
      lines.push({ status: 'fail', text: `${i.ref}: vulnerabilities found — run \`${tool} ${tool === 'trivy' ? 'image' : 'scan image'} ${i.ref}\`` });
    }
  }
  return { title, lines };
}
