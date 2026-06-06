// Unit tests for the pure logic (no network, no external binaries).
// Run with: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { detect } from '../lib/detect.js';
import { ageInDays } from '../lib/registry.js';
import { pinning } from '../lib/checks.js';

function fixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'scs-test-'));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
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

test('ageInDays: whole-day delta', () => {
  const fiveDaysAgo = new Date(Date.now() - 5 * 86_400_000 - 1000);
  assert.equal(ageInDays(fiveDaysAgo), 5);
  assert.equal(ageInDays(new Date()), 0);
});
