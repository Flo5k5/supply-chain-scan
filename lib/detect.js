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

export function detect(dir) {
  const entries = listDir(dir);

  // --- npm ---
  const npmLock = NPM_LOCKS.find((f) => existsSync(join(dir, f))) || null;
  const npm = npmLock ? { lock: npmLock, pm: NPM_PM[npmLock] } : null;

  // --- PyPI ---
  const pyLocks = PY_LOCKS.filter((f) => existsSync(join(dir, f)));
  const reqFiles = entries.filter((f) => /^requirements.*\.txt$/i.test(f));
  const hasPyproject = existsSync(join(dir, 'pyproject.toml'));
  const python =
    pyLocks.length || reqFiles.length || hasPyproject
      ? { locks: pyLocks, reqFiles, hasPyproject, usesUv: pyLocks.includes('uv.lock') }
      : null;

  // --- Docker ---
  const dockerFiles = entries.filter(
    (f) => f === 'Dockerfile' || /\.dockerfile$/i.test(f) || /^Dockerfile\./i.test(f)
  );
  const composeFiles = entries.filter((f) =>
    /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/i.test(f)
  );
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

  // Lockfiles to hand to osv-scanner (it parses these natively).
  const lockfiles = [];
  if (npm) lockfiles.push(npm.lock);
  if (python) lockfiles.push(...python.locks, ...python.reqFiles);

  return {
    npm,
    python,
    docker,
    lockfiles,
    empty: !npm && !python && !docker,
  };
}
