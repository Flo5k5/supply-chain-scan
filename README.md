# supply-chain-scan

**A 5-second morning safety check for the project you're about to work on.** Before your first
`install`/`update` of the day, scan its dependencies for **known-malicious packages**, **CVEs**,
**freshly-published (zero-hour) deps**, and missing **release-cooldown / digest pinning** — across
**npm, PyPI and Docker**, in one command.

```
npx supply-chain-scan
```

- 🛡️ **Catches what `npm audit` misses** — known-*malicious* packages (the OSV `MAL-` feed), not just CVEs.
- 🌅 **Built for a morning routine** — point it at the repo you're opening; get a clear go / review verdict.
- 🧩 **npm + PyPI + Docker** in a single pass.
- 📦 **Zero runtime dependencies.** A supply-chain tool shouldn't be a supply-chain risk — read all of it in 5 minutes.
- 💻 **Cross-platform** (Windows / Linux / macOS), **no account, no CI, no telemetry.**

---

## Why

The 2025–26 wave of npm and PyPI supply-chain attacks (hijacked maintainers → malicious release → fast
adoption) and malicious/typosquatted Docker images all exploit the same blind spot: tools that only know about
*already-reported* CVEs. `supply-chain-scan` layers the **free** defenses that actually cover the gap:

| Threat | Defense in this tool |
|--------|----------------------|
| Known-malicious package (npm/PyPI) | **osv-scanner** + the OSV `MAL-` feed |
| Known CVE | osv-scanner + the package manager's `audit` |
| **Zero-hour** malicious release (not yet reported) | **freshness heuristic** (flag deps published < N days ago) + the **release-cooldown** config check |
| Mutable / hijackable Docker base image | **digest-pinning** check (`@sha256:`) + optional image CVE scan |

No single open-source CLI combined these into a one-command morning verdict across all three ecosystems — so here it is.

---

## Install

### One-time: the scan engine

`supply-chain-scan` drives Google's free [osv-scanner](https://github.com/google/osv-scanner) for the
malicious/CVE layer. Install it once, globally:

| OS | Command |
|----|---------|
| macOS / Linux | `brew install osv-scanner` |
| Windows | `winget install Google.OSVScanner` *(or `scoop install osv-scanner`)* |
| Any | a release binary from [osv-scanner/releases](https://github.com/google/osv-scanner/releases), or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` |

*(If it's missing, the scan tells you the exact command for your OS and still runs the other checks.)*

### The tool — pick one

**As an npm CLI** (any editor / terminal):
```bash
npx supply-chain-scan [project-dir]      # no install
npm install -g supply-chain-scan         # or install globally
```

**As a Claude Code plugin** (adds a `/supply-chain-scan` skill to your morning routine):
```
/plugin marketplace add Flo5k5/supply-chain-scan
/plugin install supply-chain-scan@flo5k5-tools
```

---

## Usage

```bash
supply-chain-scan [project-dir]      # defaults to the current directory

  --fresh-days <N>   flag deps published less than N days ago   (default 3)
  --images           also pull & scan Docker base images for CVEs (slow, opt-in)
  --json             machine-readable output
  --no-color         disable ANSI colors
  -h, --help / -v, --version
```

Exit codes (scriptable): **`0`** clean · **`1`** review (findings) · **`2`** setup (osv-scanner not installed).

### Example

```
🔒 Supply-chain scan — acme-api
   /home/you/code/acme-api
────────────────────────────────────────────────────────────
   detected: npm(pnpm) · Docker(1 img)

▶ osv-scanner — known-malicious + CVE
  ⚠ 3 known vulnerabilities across 1 package(s):
      axios@1.6.0 (GHSA-8hc4-vh64-cxmj) [npm]
      …and 2 more
▶ audit — CVE advisories
  ✓ pnpm: no high/critical advisories
▶ pinning / cooldown
  ⚠ npm: no minimumReleaseAge — add to pnpm-workspace.yaml: `minimumReleaseAge: 4320` (3 days)
▶ freshness — deps changed recently & published < 3d ago (zero-hour)
  ⚠ left-pad@9.9.9 [npm] — published 1d ago (fresh; vet before trusting)
▶ Docker — base image pinning
  ⚠ 1/1 base image(s) NOT pinned by digest (mutable tag — can be re-pointed):
      node:22-alpine  (Dockerfile) → pin to image@sha256:<digest>

────────────────────────────────────────────────────────────
⚠️  REVIEW — see the ⚠/✗ lines above before installing or updating dependencies.
```

---

## The one thing to configure per project: a release cooldown

The cheapest, highest-leverage defense is to **refuse versions published in the last few days**, so a
compromised release is detected and pulled before it lands in your lockfile. The scan checks for it and offers
the snippet:

- **pnpm** → `pnpm-workspace.yaml`: `minimumReleaseAge: 4320` *(3 days; pnpm 11 defaults this on at 1 day)*
- **uv (Python)** → `pyproject.toml` `[tool.uv]`: `exclude-newer = "2026-01-01T00:00:00Z"`
- **Docker** → pin every `FROM` to a digest: `FROM node:22-alpine@sha256:…`

---

## How it fits a layered defense

1. **Release cooldown** (above) — keeps brand-new, most-likely-malicious versions out long enough to be caught.
2. **`supply-chain-scan`** (this tool) — the morning gate: known-malicious + CVE + fresh-dep + pinning.
3. *(optional, free)* the [Socket.dev](https://socket.dev) GitHub App — **behavioral** detection of *novel*
   malware. This tool catches *known* and *fresh*; Socket adds the *unknown-behavioral* layer.

## Privacy

No telemetry. The only network calls are public lookups: `registry.npmjs.org` / `pypi.org` for publish dates,
and OSV.dev (via osv-scanner) for advisories. Nothing about your project is uploaded.

## Roadmap

- Auto-download a pinned, checksum-verified osv-scanner binary (`--install-scanner`).
- Go (`go.sum`) and Rust (`Cargo.lock`) — osv-scanner already supports them.
- A GitHub Action / pre-commit recipe for teams that want this in CI too.

## License

[MIT](LICENSE) © Flo5k5
