# Nass — Software Supply Chain Security Lab

![CI](https://github.com/nassim7792/Nass_software-supply-chain-security-lab/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![SBOM: CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX-blueviolet)
![Tests](https://img.shields.io/badge/tests-30%20passing-success)

An **educational, fully local** lab that demonstrates the **dependency
confusion** attack vector end to end — and then detects it, prevents it, and
enforces security as a **gate on delivery** in a DevSecOps pipeline.

It covers both sides of the discipline: the **offensive** simulation (the
technique Alex Birsan used in 2021 to breach Apple, Microsoft, PayPal and ~35
others, earning US$130k+ in bounties) and the **defensive / DevSecOps**
response (detection, hardening, SBOM, CVE scanning, and a configurable CI
security gate).

> ⚠️ **Ethics & safety.** Everything runs against a *local* registry on
> `127.0.0.1`. **Nothing is ever published to a real registry.** The
> demonstration package only collects non-sensitive host metadata (hostname,
> username, Python version, cwd) and sends it to a monitoring server on
> `localhost` — it never touches the internet, never reads secrets, never
> persists outside this repo. Use it only on machines you own, for learning.
> A unit test (`tests/test_demo_package_is_benign.py`) enforces that the payload
> stays benign.

---

## What this project shows a reviewer

1. **Simulate** a dependency-confusion attack in an isolated environment.
2. **Analyse** how it works and which weaknesses it exploits.
3. **Detect** it in Python (hash, network, filesystem monitors).
4. **Prevent** it (lockfile + hash pinning, scoped registries, namespace
   reservation, signature verification, policy-as-code).
5. **Automate** the controls in **GitLab CI/CD** so a release is blocked when a
   security check fails.
6. **Report** on attacks vs. defenses, plus three personal DevSecOps features:
   - **CycloneDX SBOM** generation,
   - **CVE scanning** via **OSV** (with a **Trivy** path),
   - a **configurable Security Gate** that blocks delivery by policy.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the diagrams.

## Repository layout

```
Nass_software-supply-chain-security-lab/
├── packages/internal-auth-utils/   # the demonstration "impostor" package (benign)
├── target-app/                     # intentionally vulnerable FastAPI app
├── monitoring/                     # dashboard that captures the attack beacons
├── detection/                      # hash / network / filesystem detectors
├── defenses/                       # 5 preventive controls + policy scanner
├── security/                       # DevSecOps: SBOM, CVE scan, security gate
│   ├── sbom.py                     #   CycloneDX 1.5 generator
│   ├── cve_scan.py                 #   OSV / Trivy scanner
│   ├── gate.py                     #   configurable delivery gate
│   └── security-policy.yml         #   the gate's rules (edit to tune strictness)
├── scsim/                          # interactive CLI runner (attack demo)
├── report/                         # auto-generated analysis report
├── tests/                          # offline pytest suite
├── docs/ARCHITECTURE.md            # mermaid architecture + data-flow diagrams
├── .gitlab-ci.yml                  # build → test → sbom → scan → policy → gate → deploy
└── requirements.txt
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install uv            # for realistic dependency resolution
```

### A) Run the attack demo (offensive plane)

```bash
python -m scsim.runner run --narrated           # guided end-to-end demo
# offline-safe variant (drives the hooks directly, no uv/network):
python -m scsim.runner run --narrated --simulate
```

Open the monitor at `http://127.0.0.1:8888/` and the timeline at
`/timeline` to watch build → install → import for a single careless dependency.

### B) Run the DevSecOps chain (defensive plane)

```bash
python -m security.sbom                          # 1. CycloneDX SBOM
python -m security.cve_scan                       # 2. OSV CVE scan of the SBOM
python -m security.gate                           # 3. security gate -> exit 1 blocks delivery
```

With the shipped (vulnerable) config, the gate **blocks** delivery:

```
PASS ✅  require_sbom           valid CycloneDX
FAIL ❌  dependency_confusion   2 critical finding(s)
PASS ✅  cve                    within policy
DELIVERY BLOCKED ⛔
```

Fix the target app's config (scope the internal name to a private index, drop
`unsafe-best-match` — see `defenses/scoped_registry.py`) and the gate turns
green. That green/red flip is the whole point of the pipeline.

### C) Tests

```bash
pytest -q         # 30 offline tests: benign-payload guard, detectors,
                  # defenses, SBOM, CVE scan, gate, monitor
```

### D) Web console

Start the monitor (`python -m scsim.runner monitor`) and open:

- `http://127.0.0.1:8888/` — attack monitor (the impostor's beacons)
- `http://127.0.0.1:8888/timeline` — attack timeline
- `http://127.0.0.1:8888/security` — **security console**: gate verdict, CVE
  table (severity badges, donut chart, filters, search, sort), and SBOM

## CI/CD

The pipeline runs on **both GitLab and GitHub**:

```
build → test → sbom → scan (OSV + optional Trivy) → policy → security gate → deploy
```

- `.gitlab-ci.yml` — GitLab pipeline.
- `.github/workflows/ci.yml` — GitHub Actions equivalent.

Because this lab's `target-app` is **intentionally vulnerable**, the security
gate is *expected* to block delivery. The CI is green when the gate **correctly
blocks** it (that is the demonstration) and all tests pass. In a real downstream
project you would instead let a non-zero gate fail the pipeline and stop the
deploy. The SBOM and CVE report are uploaded as pipeline artifacts.

## The three personal DevSecOps features

- **SBOM (CycloneDX 1.5)** — `security/sbom.py` inventories dependencies as a
  valid CycloneDX document (a `pkg:pypi/...` purl each), flagging internal-looking
  names. The built-in generator (direct deps, zero extra dependencies) is the
  default; `python -m security.sbom --real` switches to the official
  **`cyclonedx-py`** tool for the full **transitive** dependency tree, and
  `--real --requirements <hash-pinned file>` adds artifact **hashes** (SLSA-grade
  provenance).
- **CVE scanning (OSV / Trivy)** — `security/cve_scan.py` looks up each SBOM
  component in the OSV database, normalises severity (CVSS → label), and writes
  a JSON report. The transport is injectable, so the suite tests it offline;
  on your machine it queries live OSV. `--trivy` delegates to the Trivy CLI.
- **Configurable Security Gate** — `security/gate.py` reads
  `security-policy.yml` (CVE severity thresholds, per-severity caps, an
  allowlist with justifications, the dependency-confusion rule, SBOM
  requirement) and returns a CI exit code. Tune the policy without touching code.

## Key concepts

Dependency resolution & version precedence · dependency confusion &
typosquatting · post-install hook execution · lockfile pinning, hash
verification, reproducible builds · network/filesystem anomaly detection · SBOM
& CycloneDX · CVE/OSV vulnerability intelligence · policy-as-code security gates
· SLSA & NIST SSDF · responsible disclosure.

## Responsible use

This is a controlled, defensive lab. Never point the publish step at any
registry other than the bundled localhost one; never reuse the metadata snippet
in a distributed package; test only systems you own. Full ethics discussion in
[`report/analysis_report.md`](report/analysis_report.md) §6.
