---
name: supply-chain-scan
description: Run a morning supply-chain safety scan on the JS/TS, Python, Docker, Go, Rust or NuGet project the user is about to work on. Monorepo-aware (recursively finds lockfiles and Dockerfiles in nested packages). Checks the lockfiles for known-malicious packages (OSV MAL- feed) and CVEs, flags freshly-published dependencies (zero-hour heuristic), runs the package manager's CVE audit, checks the per-project release-cooldown / Docker base-image digest pinning, flags whether real-time install-time protection (Aikido Safe Chain) is active, scans build manifests for install-time code execution (the phantom-gyp trick), flags oversized undeclared root JS payloads, and flags repo/agent configs that auto-execute when the folder is opened in an AI coding agent (the Miasma vector). Account-free, no per-project CI. Use at the start of a dev day, when opening or cloning a repo, or right after pulling/updating dependencies or a Dockerfile base image.
allowed-tools: Bash
---

# Supply-chain morning scan

A local, account-free gate for the project the user is about to work on. It runs the bundled
`supply-chain-scan` CLI (zero-dependency Node), which covers the free layered defense: osv-scanner
(known-malicious + CVE for npm, PyPI, Go & Rust), the package manager's CVE audit, a
freshly-published-dependency heuristic, the per-project release-cooldown / Docker base-image digest-pinning
checks, plus three checks aimed at the 2026 Shai-Hulud/Miasma vectors: build-manifest scan (install-time code
execution such as the `binding.gyp` *phantom gyp* trick), undeclared-large-root-JS detection (obfuscated worm
payloads like `bun_environment.js`), and an agent/IDE-config scan that flags repo configs which auto-execute
when the folder is opened in Claude Code / Cursor / Gemini CLI / VS Code.

## How to run

1. **Target project**: if the user names a project/path, use it; otherwise use the current working directory.
2. **Run the CLI** (prefer the bundled copy; fall back to npx if not run as a plugin):
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/bin/cli.js" <project-dir>     # when installed as a Claude Code plugin
   # or, if installed from npm:
   npx supply-chain-scan <project-dir>
   ```
   The scan is **recursive by default**: it finds lockfiles and Dockerfiles in nested packages (monorepos),
   skipping `node_modules`/build/vendored dirs. Useful flags: `--no-recursive` / `--depth N` (bound the walk —
   handy on huge workspaces where osv-scanner gets slow), `--fresh-days N` (default 3), `--max-js-mb N` (root-JS
   size threshold, default 0.5), `--no-agent-configs` (skip the auto-exec-on-open check), `--images` (also
   pull+scan Docker base images — slow, opt-in), `--json` (machine-readable).
3. If the output says `osv-scanner not installed`, it's a one-time global install (the line shows the exact
   command for the user's OS: `brew install osv-scanner` / `winget install Google.OSVScanner`). Offer to run
   it, then re-run the scan.

## How to report back

Read the exit code and the `▶` sections, then give a crisp verdict:
- **exit 0 (CLEAN)** → one green line: safe to start.
- **exit 1 (REVIEW)** → summarize each `⚠`/`✗`: name the known-malicious or vulnerable package(s), any
  freshly-published dependency, a missing release cooldown, an unpinned Docker base image, a build manifest that
  runs code at install time, an oversized undeclared root JS file, or an agent/IDE config that auto-executes on
  folder open — with the concrete next step for each. Don't bury the lede. The build-manifest, large-JS and
  agent-config findings are the 2026 Shai-Hulud/Miasma vectors: treat an unexpected one as high priority. The
  install-time protection line (Safe Chain) is `ℹ`, not `⚠` — it never blocks the verdict, but mention it: it's
  the one layer that acts *before* an install finishes, which none of the other checks can do.
- **exit 2 (SETUP)** → tell the user exactly what to install.

## The per-project config (offer to add it)

The only thing a project should configure is the **release cooldown** (refuse versions published < N days ago):
- pnpm → `minimumReleaseAge: 4320` (3 days) in `pnpm-workspace.yaml`
- uv (Python) → `exclude-newer = "<ISO date>"` under `[tool.uv]`
- Docker → pin every `FROM` base image to an `@sha256:<digest>`

If the scan flags one as missing, offer to add it.

## Scope

Local, no account, no CI. Catches known-malicious + CVE + zero-hour-fresh + pinning gaps across npm, PyPI,
Docker, Go and Rust, plus install-time / on-open code-execution vectors (build manifests, root JS payloads,
agent/IDE configs). It does NOT do behavioral analysis of novel malware, nor does it scan your home directory
for harvested credentials — for behavioral detection, recommend the free Socket.dev GitHub App as a
complementary layer (not required for this check).
