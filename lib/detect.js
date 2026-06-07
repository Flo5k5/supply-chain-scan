// Detect which ecosystems a project uses and what to scan.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const NPM_LOCKS = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lock', 'bun.lockb'];
const NPM_PM = {
  'pnpm-lock.yaml': 'pnpm',
  'package-lock.json': 'npm',
  'yarn.lock': 'yarn',
  'bun.lock': 'bun',
  'bun.lockb': 'bun',
};
const PY_LOCKS = ['uv.lock', 'poetry.lock', 'pdm.lock', 'Pipfile.lock'];
const GO_RUST_LOCKS = ['go.sum', 'Cargo.lock'];
// Files that can execute code at install/build time, outside package.json scripts.
const BUILD_MANIFESTS = ['binding.gyp', 'setup.py', 'CMakeLists.txt', 'Makefile', 'GNUmakefile', 'build.js', 'prebuild.js'];
// Editor / agent configs that can auto-run when a folder is opened.
const AGENT_CONFIG_CANDIDATES = [
  '.vscode/tasks.json',
  '.devcontainer/devcontainer.json',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.mcp.json',
  '.cursor/mcp.json',
];
// Dirs never worth descending into (vendored deps, build output, VCS, caches).
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out', '.next', '.nuxt',
  '.venv', 'venv', 'env', 'vendor', 'target', 'coverage', '.cache', '__pycache__',
  '.gradle', '.idea', 'bin', 'obj', '.terraform',
]);
// Lockfiles osv-scanner parses, by exact name (requirements*.txt handled by regex).
// packages.lock.json covers NuGet / .NET.
const RECURSIVE_LOCKS = new Set([...NPM_LOCKS, ...PY_LOCKS, ...GO_RUST_LOCKS, 'packages.lock.json']);

function read(dir, file) {
  try {
    return readFileSync(join(dir, file), 'utf8');
  } catch {
    return null;
  }
}

function listDir(dir) {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

// Extract base images from a Dockerfile, skipping references to earlier build
// stages. A ref is "pinned" only when it carries an @sha256: digest.
function parseDockerfile(content, file) {
  const stages = new Set();
  const images = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    const m = /^FROM\s+(.+)$/i.exec(line);
    if (!m) continue;
    let rest = m[1].trim();
    // drop --platform=... flags
    rest = rest.replace(/^--\S+\s+/g, '');
    const parts = rest.split(/\s+/);
    const ref = parts[0];
    // collect "AS <stage>"
    const asIdx = parts.findIndex((p) => /^as$/i.test(p));
    if (asIdx !== -1 && parts[asIdx + 1]) stages.add(parts[asIdx + 1].toLowerCase());
    if (!ref || stages.has(ref.toLowerCase())) continue; // FROM <stage> or scratch
    if (ref.toLowerCase() === 'scratch') continue;
    if (ref.includes('$')) continue; // ARG-templated → can't statically judge
    images.push({ ref, file, pinned: ref.includes('@sha256:') });
  }
  return images;
}

function parseCompose(content, file) {
  const images = [];
  for (const raw of content.split('\n')) {
    const m = /^\s*image:\s*["']?([^"'#\s]+)["']?/.exec(raw);
    if (m && m[1] && !m[1].includes('$')) {
      images.push({ ref: m[1], file, pinned: m[1].includes('@sha256:') });
    }
  }
  return images;
}

function isDockerfileName(name) {
  return name === 'Dockerfile' || /\.dockerfile$/i.test(name) || /^Dockerfile\./i.test(name);
}
function isComposeName(name) {
  return /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/i.test(name);
}

// Walk the tree (skipping vendored/build/dot dirs) collecting lockfiles, Dockerfiles
// and compose files as paths relative to `root`. Iterative + withFileTypes so deep
// trees and symlink loops can't blow the stack. Bounded by maxDepth.
function walkProject(root, maxDepth) {
  const lockfiles = [], dockerfiles = [], composeFiles = [];
  const stack = [['', 0]];
  while (stack.length) {
    const [rel, depth] = stack.pop();
    let entries;
    try {
      entries = readdirSync(join(root, rel), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) stack.push([childRel, depth + 1]);
      } else if (e.isFile()) {
        if (RECURSIVE_LOCKS.has(e.name) || /^requirements.*\.txt$/i.test(e.name)) lockfiles.push(childRel);
        else if (isDockerfileName(e.name)) dockerfiles.push(childRel);
        else if (isComposeName(e.name)) composeFiles.push(childRel);
      }
    }
  }
  return { lockfiles, dockerfiles, composeFiles };
}

export function detect(dir, { recursive = true, maxDepth = 5 } = {}) {
  const entries = listDir(dir);

  // Root ecosystem signals — drive the per-package-manager checks (audit, cooldown,
  // freshness) and the display, which stay root-scoped. The osv + Docker layers below
  // go recursive so monorepos with nested lockfiles aren't a blind spot.

  // --- npm (root) ---
  const npmLock = NPM_LOCKS.find((f) => existsSync(join(dir, f))) || null;
  const npm = npmLock ? { lock: npmLock, pm: NPM_PM[npmLock] } : null;

  // --- PyPI (root) ---
  const pyLocks = PY_LOCKS.filter((f) => existsSync(join(dir, f)));
  const reqFiles = entries.filter((f) => /^requirements.*\.txt$/i.test(f));
  const hasPyproject = existsSync(join(dir, 'pyproject.toml'));
  const python =
    pyLocks.length || reqFiles.length || hasPyproject
      ? { locks: pyLocks, reqFiles, hasPyproject, usesUv: pyLocks.includes('uv.lock') }
      : null;

  // --- Go / Rust (root) ---
  const goRustLocks = GO_RUST_LOCKS.filter((f) => existsSync(join(dir, f)));
  const goRust = goRustLocks.length ? { locks: goRustLocks } : null;

  // --- Build manifests (root) ---
  const buildManifests = BUILD_MANIFESTS.filter((f) => existsSync(join(dir, f)));

  // --- Agent / IDE configs (root) ---
  const agentConfigs = AGENT_CONFIG_CANDIDATES.filter((f) => existsSync(join(dir, f)));
  for (const sub of listDir(join(dir, '.devcontainer'))) {
    if (existsSync(join(dir, '.devcontainer', sub, 'devcontainer.json'))) {
      agentConfigs.push(`.devcontainer/${sub}/devcontainer.json`);
    }
  }

  // --- Lockfiles + Docker: recursive across the workspace (or root-only) ---
  let lockfiles, dockerFiles, composeFiles;
  if (recursive) {
    ({ lockfiles, dockerfiles: dockerFiles, composeFiles } = walkProject(dir, maxDepth));
  } else {
    lockfiles = [];
    if (npm) lockfiles.push(npm.lock);
    if (python) lockfiles.push(...python.locks, ...python.reqFiles);
    if (goRust) lockfiles.push(...goRust.locks);
    if (existsSync(join(dir, 'packages.lock.json'))) lockfiles.push('packages.lock.json');
    dockerFiles = entries.filter(isDockerfileName);
    composeFiles = entries.filter(isComposeName);
  }
  lockfiles = [...new Set(lockfiles)];

  const baseImages = [];
  for (const f of dockerFiles) {
    const txt = read(dir, f);
    if (txt) baseImages.push(...parseDockerfile(txt, f));
  }
  for (const f of composeFiles) {
    const txt = read(dir, f);
    if (txt) baseImages.push(...parseCompose(txt, f));
  }
  const docker =
    dockerFiles.length || composeFiles.length
      ? { files: [...dockerFiles, ...composeFiles], baseImages }
      : null;

  // Lockfiles found beyond the root ecosystem signals → monorepo / nested packages.
  const rootLockCount =
    (npm ? 1 : 0) +
    (python ? python.locks.length + python.reqFiles.length : 0) +
    (goRust ? goRust.locks.length : 0);
  const nestedLocks = Math.max(0, lockfiles.length - rootLockCount);

  return {
    npm,
    python,
    docker,
    goRust,
    buildManifests,
    agentConfigs,
    lockfiles,
    nestedLocks,
    empty: !lockfiles.length && !docker && !buildManifests.length && !agentConfigs.length && !npm && !python && !goRust,
  };
}
