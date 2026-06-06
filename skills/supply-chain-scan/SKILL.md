---
name: supply-chain-scan
description: Run a morning supply-chain safety scan on the JS/TS, Python or Docker project the user is about to work on. Checks the lockfiles for known-malicious packages (OSV MAL- feed) and CVEs, flags freshly-published dependencies (zero-hour heuristic), runs the package manager's CVE audit, and checks the per-project release-cooldown / Docker base-image digest pinning. Account-free, no per-project CI. Use at the start of a dev day, when opening or cloning a repo, or right after pulling/updating dependencies or a Dockerfile base image.
allowed-tools: Bash
---

# Supply-chain morning scan

A local, account-free gate for the project the user is about to work on. It runs the bundled
`supply-chain-scan` CLI (zero-dependency Node), which covers the free layered defense: osv-scanner
(known-malicious + CVE for npm & PyPI), the package manager's CVE audit, a freshly-published-dependency
heuristic, and the per-project release-cooldown / Docker base-image digest-pinning checks.

## How to run

1. **Target project**: if the user names a project/path, use it; otherwise use the current working directory.
2. **Run the CLI** (prefer the bundled copy; fall back to npx if not run as a plugin):
   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/bin/cli.js" <project-dir>     # when installed as a Claude Code plugin
   # or, if installed from npm:
   npx supply-chain-scan <project-dir>
   ```
   Useful flags: `--fresh-days N` (default 3), `--images` (also pull+scan Docker base images — slow, opt-in),
   `--json` (machine-readable).
3. If the output says `osv-scanner not installed`, it's a one-time global install (the line shows the exact
   command for the user's OS: `brew install osv-scanner` / `winget install Google.OSVScanner`). Offer to run
   it, then re-run the scan.

## How to report back

Read the exit code and the `▶` sections, then give a crisp verdict:
- **exit 0 (CLEAN)** → one green line: safe to start.
- **exit 1 (REVIEW)** → summarize each `⚠`/`✗`: name the known-malicious or vulnerable package(s), any
  freshly-published dependency, a missing release cooldown, or an unpinned Docker base image — with the concrete
  next step for each. Don't bury the lede.
- **exit 2 (SETUP)** → tell the user exactly what to install.

## The per-project config (offer to add it)

The only thing a project should configure is the **release cooldown** (refuse versions published < N days ago):
- pnpm → `minimumReleaseAge: 4320` (3 days) in `pnpm-workspace.yaml`
- uv (Python) → `exclude-newer = "<ISO date>"` under `[tool.uv]`
- Docker → pin every `FROM` base image to an `@sha256:<digest>`

If the scan flags one as missing, offer to add it.

## Scope

Local, no account, no CI. Catches known-malicious + CVE + zero-hour-fresh + pinning gaps across npm, PyPI and
Docker. It does NOT do behavioral analysis of novel malware — for that, recommend the free Socket.dev GitHub App
as a complementary layer (not required for this check).
