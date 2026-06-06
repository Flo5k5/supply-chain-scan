// Cross-platform process helpers. `shell: false` everywhere — never interpolate
// untrusted input through a shell.
import { spawnSync } from 'node:child_process';

const _hasCache = new Map();

/** True if `bin` is found on PATH (uses `where` on Windows, `which` elsewhere). */
export function has(bin) {
  if (_hasCache.has(bin)) return _hasCache.get(bin);
  const finder = process.platform === 'win32' ? 'where' : 'which';
  let ok = false;
  try {
    const r = spawnSync(finder, [bin], { encoding: 'utf8', shell: false });
    ok = r.status === 0;
  } catch {
    ok = false;
  }
  _hasCache.set(bin, ok);
  return ok;
}

/** Run a binary, capturing stdout/stderr/exit code. Never throws. */
export function run(bin, args, opts = {}) {
  const r = spawnSync(bin, args, {
    encoding: 'utf8',
    shell: false,
    maxBuffer: 32 * 1024 * 1024,
    ...opts,
  });
  return {
    status: r.status,
    stdout: r.stdout || '',
    stderr: r.stderr || '',
    ok: r.status === 0,
    missing: !!r.error && r.error.code === 'ENOENT',
    error: r.error,
  };
}
