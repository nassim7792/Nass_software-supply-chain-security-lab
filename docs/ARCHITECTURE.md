# Architecture

The lab has two planes — an **offensive** plane that stages a dependency
confusion attack in isolation, and a **defensive / DevSecOps** plane that
detects it, prevents it, and enforces security as a gate on delivery.

## System overview

```mermaid
flowchart TB
    subgraph OFFENSE["🔴 Offensive plane (isolated, localhost only)"]
        direction TB
        REG["Local private index<br/>pypiserver :8080"]
        IMP["Impostor package<br/>internal-auth-utils 99.0.0<br/>(post-install + import hooks)"]
        APP["Target FastAPI app<br/>unsafe index config"]
        MON["Monitoring dashboard<br/>:8888 + SQLite + timeline"]
        IMP -->|published to| REG
        APP -->|uv sync picks highest version| REG
        REG -->|installs impostor| APP
        APP -->|hooks fire: benign beacons| MON
    end

    subgraph DEFENSE["🔵 Defensive plane"]
        direction TB
        DET["Detection<br/>hash · network · filesystem"]
        DEF["Defenses<br/>lockfile · namespace · scoped index<br/>signing · policy-as-code"]
    end

    subgraph DEVSECOPS["⚙️ DevSecOps pipeline (GitLab CI/CD)"]
        direction LR
        B["build"] --> T["test<br/>pytest"] --> S["sbom<br/>CycloneDX"]
        S --> C["scan<br/>OSV / Trivy"]
        C --> P["policy<br/>dep-confusion"]
        P --> G{"security gate<br/>policy.yml"}
        G -->|PASS| D["deploy"]
        G -->|FAIL| X["⛔ delivery blocked"]
    end

    APP -.audited by.-> DET
    APP -.hardened by.-> DEF
    APP -.inventoried by.-> S
    DEF -.policy reused by.-> P
    DET -.evidence for.-> G
```

## Data flow through the pipeline

```mermaid
flowchart LR
    SRC["repo<br/>pyproject.toml<br/>requirements.txt"] --> SBOM["sbom.cyclonedx.json"]
    SBOM --> SCAN["cve_report.json<br/>(OSV lookups)"]
    POLICY["security-policy.yml"] --> GATE{"gate.py"}
    SBOM --> GATE
    SCAN --> GATE
    SRC --> PSCAN["policy_scanner<br/>(internal names)"] --> GATE
    GATE -->|exit 0| SHIP["deploy ✅"]
    GATE -->|exit 1| STOP["blocked ⛔"]
```

## Components

| Layer | Path | Responsibility |
|---|---|---|
| Registry | `scripts/`, runner | Local private index (pypiserver) |
| Impostor | `packages/internal-auth-utils/` | Demonstrates the attack mechanism (benign) |
| Target | `target-app/` | Intentionally vulnerable consumer app |
| Monitor | `monitoring/` | Captures + visualises the "exfil" beacons |
| Detection | `detection/` | Hash, network, filesystem detectors |
| Defenses | `defenses/` | Five preventive controls + policy scanner |
| SBOM | `security/sbom.py` | CycloneDX inventory |
| CVE scan | `security/cve_scan.py` | OSV / Trivy vulnerability lookup |
| Gate | `security/gate.py`, `security-policy.yml` | Configurable delivery gate |
| CI/CD | `.gitlab-ci.yml` | Enforces the chain, blocks deploy on failure |
| Orchestrator | `scsim/runner.py` | One-command narrated demo |
| Tests | `tests/` | Offline pytest suite |
```
