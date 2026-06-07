// The individual checks. Each returns { title, lines:[{status,text}], setup? }
// and never throws — a check that can't run degrades to a `skip` line.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
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

// ── 7) build manifests: code that runs at install/build time ───────────────
// Catches the "phantom gyp" vector (Miasma, 2026): a binding.gyp command
// substitution `"<!(node evil.js)"` executes during `npm install` without ever
// declaring a preinstall/postinstall script in package.json, so hook monitors
// miss it. We flag the high-signal substitution forms, not every Makefile $(VAR).
const BUILD_PATTERNS = [
  { re: /<!@?\s*\(/g, name: 'gyp shell-command  <!(...)' },
  { re: /\$\(\s*shell\s/g, name: 'make  $(shell …)' },
  { re: /`[^`\n]+`/g, name: 'backtick command' },
];

export function buildManifestScan(dir, d) {
  const title = 'build manifests — install/build-time code execution';
  const files = d.buildManifests || [];
  if (!files.length) return { title, lines: [{ status: 'skip', text: 'no build manifests (binding.gyp, setup.py, Makefile, …)' }] };
  const lines = [];
  for (const f of files) {
    const content = read(dir, f);
    if (content == null) continue;
    for (const { re, name } of BUILD_PATTERNS) {
      const m = content.match(re);
      if (m && m.length) {
        lines.push({ status: 'warn', text: `${f}: ${name} ×${m.length} — runs at install/build time; verify it's benign` });
        break; // one finding line per file
      }
    }
  }
  if (!lines.length) lines.push({ status: 'ok', text: `${files.length} build manifest(s) — no shell-command-substitution patterns` });
  return { title, lines };
}

// ── 8) undeclared large JS/TS at the repo root ─────────────────────────────
// Obfuscated worm payloads (e.g. Shai-Hulud's bun_environment.js) often sit as
// an oversized root JS file that isn't a declared entry point.
function declaredEntries(pkg) {
  const set = new Set();
  const add = (v) => { if (typeof v === 'string') set.add(basename(v)); };
  add(pkg.main);
  add(pkg.module);
  if (typeof pkg.bin === 'string') add(pkg.bin);
  else if (pkg.bin && typeof pkg.bin === 'object') for (const v of Object.values(pkg.bin)) add(v);
  const walk = (e) => {
    if (typeof e === 'string') add(e);
    else if (e && typeof e === 'object') for (const v of Object.values(e)) walk(v);
  };
  if (pkg.exports) walk(pkg.exports);
  if (pkg.scripts && typeof pkg.scripts === 'object') {
    for (const v of Object.values(pkg.scripts)) {
      for (const hit of String(v).match(/[\w./-]+\.(?:js|ts|mjs|cjs)\b/g) || []) set.add(basename(hit));
    }
  }
  return set;
}

export function undeclaredLargeJsRoots(dir, maxMb = 0.5) {
  const title = `large undeclared JS/TS at repo root (> ${maxMb} MB)`;
  let pkg = {};
  const raw = read(dir, 'package.json');
  if (raw) { try { pkg = JSON.parse(raw); } catch { pkg = {}; } }
  const declared = declaredEntries(pkg);
  const threshold = maxMb * 1024 * 1024;
  let entries;
  try { entries = readdirSync(dir); } catch { return { title, lines: [{ status: 'skip', text: 'cannot read directory' }] }; }
  const hits = [];
  for (const f of entries) {
    if (f.startsWith('.') || !/\.(js|ts|mjs|cjs)$/.test(f) || declared.has(f)) continue;
    let st;
    try { st = statSync(join(dir, f)); } catch { continue; }
    if (st.isFile() && st.size > threshold) hits.push({ f, mb: (st.size / 1048576).toFixed(2) });
  }
  if (!hits.length) return { title, lines: [{ status: 'ok', text: `no undeclared JS/TS file > ${maxMb} MB at root` }] };
  const lines = [{ status: 'warn', text: `${hits.length} undeclared large JS/TS file(s) at root (obfuscated-payload vector):` }];
  for (const h of hits.slice(0, 5)) lines.push({ status: 'warn', text: `  ${h.f} (${h.mb} MB) — not a declared entry point; verify intent` });
  if (hits.length > 5) lines.push({ status: 'warn', text: `  …and ${hits.length - 5} more` });
  return { title, lines };
}

// ── 9) agent / IDE configs that auto-execute on folder open ────────────────
// The Miasma "reaches Azure" wave (2026) planted repo config files that run when
// the folder is opened in Claude Code / Cursor / Gemini CLI / VS Code — no
// package install required. We flag only keys with implicit on-open execution.
function stripJsonc(text) {
  let out = '';
  let inStr = false, strCh = '', inLine = false, inBlock = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i], next = text[i + 1];
    if (inLine) { if (ch === '\n') { inLine = false; out += ch; } continue; }
    if (inBlock) { if (ch === '*' && next === '/') { inBlock = false; i++; } continue; }
    if (inStr) {
      out += ch;
      if (ch === '\\') { out += next ?? ''; i++; continue; }
      if (ch === strCh) inStr = false;
      continue;
    }
    if (ch === '"' || ch === "'") { inStr = true; strCh = ch; out += ch; continue; }
    if (ch === '/' && next === '/') { inLine = true; i++; continue; }
    if (ch === '/' && next === '*') { inBlock = true; i++; continue; }
    out += ch;
  }
  return out;
}
function parseJsonc(text) {
  if (text == null) return null;
  try { return JSON.parse(stripJsonc(text).replace(/,(\s*[}\]])/g, '$1')); } catch { return null; }
}

const DEVCONTAINER_EXEC_KEYS = ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'];

export function agentConfigScan(dir, d) {
  const title = 'agent/IDE configs — auto-exec on folder open';
  const files = d.agentConfigs || [];
  if (!files.length) return { title, lines: [{ status: 'skip', text: 'no agent/IDE config files' }] };
  const gitOk = has('git') && run('git', ['rev-parse', '--is-inside-work-tree'], { cwd: dir }).ok;
  const recent = (f) => {
    if (!gitOk) return false;
    const r = run('git', ['log', '-1', '--since=14.days', '--format=%h', '--', f], { cwd: dir });
    return r.ok && r.stdout.trim().length > 0;
  };
  const lines = [];
  const flag = (f, what) => lines.push({ status: 'warn', text: `${f}: ${what}${recent(f) ? ' [recently added/modified]' : ''}` });

  for (const f of files) {
    const base = basename(f);
    const data = parseJsonc(read(dir, f));
    if (!data || typeof data !== 'object') continue;
    if (base === 'devcontainer.json') {
      const keys = DEVCONTAINER_EXEC_KEYS.filter((k) => data[k]);
      if (keys.length) flag(f, `runs on container create/open via ${keys.join(', ')}`);
    } else if (base === 'tasks.json') {
      const tasks = Array.isArray(data.tasks) ? data.tasks : [];
      const auto = tasks.filter((t) => t && t.runOptions && t.runOptions.runOn === 'folderOpen');
      if (auto.length) flag(f, `${auto.length} task(s) set to run automatically on folderOpen`);
    } else if ((base === 'settings.json' && f.includes('.claude')) || base === 'settings.local.json') {
      if (data.hooks) flag(f, 'defines Claude Code hooks (shell commands the agent runs)');
    } else if (base === 'mcp.json' || base === '.mcp.json') {
      const servers = data.mcpServers || data.servers || {};
      const withCmd = Object.entries(servers).filter(([, s]) => s && s.command);
      if (withCmd.length) flag(f, `${withCmd.length} MCP server(s) with a command the agent may auto-start`);
    }
  }
  if (!lines.length) return { title, lines: [{ status: 'ok', text: `${files.length} agent/IDE config(s) — no auto-exec-on-open triggers` }] };
  lines.unshift({ status: 'info', text: 'opened in Claude Code / Cursor / Gemini CLI / VS Code, these can run before you read any code:' });
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
