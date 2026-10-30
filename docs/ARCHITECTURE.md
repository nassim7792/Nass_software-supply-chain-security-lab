# Architecture

Le laboratoire s'organise en deux plans complémentaires : un plan **offensif**,
qui met en scène l'attaque par confusion de dépendances en vase clos, et un plan
**défensif / DevSecOps**, qui la détecte, la prévient et l'arrête au niveau de la
livraison.

## Vue système

```mermaid
flowchart TB
    subgraph OFF["Plan offensif (isolé, localhost uniquement)"]
        direction TB
        REG["Registre privé local<br/>pypiserver : 8080"]
        IMP["Paquet imposteur<br/>internal-auth-utils 99.0.0<br/>(hooks build / post-install / import)"]
        APP["Application cible FastAPI<br/>configuration d'index non sûre"]
        MON["Supervision<br/>:8888 + SQLite + timeline"]
        IMP -->|publié sur| REG
        APP -->|résolution : version la plus élevée| REG
        REG -->|installe l'imposteur| APP
        APP -->|les hooks émettent des balises inoffensives| MON
    end

    subgraph DEF["Plan défensif"]
        direction TB
        DET["Détection<br/>intégrité, réseau, fichiers"]
        DEFS["Défenses<br/>lockfile, espace de noms, index scopé,<br/>signature, policy-as-code"]
    end

    subgraph OPS["Chaîne DevSecOps (CI/CD)"]
        direction LR
        B["build"] --> T["test<br/>pytest"] --> S["sbom<br/>CycloneDX"]
        S --> C["scan<br/>OSV / Trivy"]
        C --> P["policy<br/>confusion de dép."]
        P --> G{"porte de sécurité<br/>security-policy.yml"}
        G -->|PASS| D["deploy"]
        G -->|FAIL| X["livraison bloquée"]
    end

    APP -.auditée par.-> DET
    APP -.durcie par.-> DEFS
    APP -.inventoriée par.-> S
    DEFS -.politique réutilisée par.-> P
    DET -.preuves pour.-> G
```

## Flux de données dans le pipeline

```mermaid
flowchart LR
    SRC["dépôt<br/>pyproject.toml<br/>requirements.txt"] --> SBOM["sbom.cyclonedx.json"]
    SBOM --> SCAN["cve_report.json<br/>(interrogations OSV)"]
    POLICY["security-policy.yml"] --> GATE{"gate.py"}
    SBOM --> GATE
    SCAN --> GATE
    SRC --> PSCAN["policy_scanner<br/>(noms internes)"] --> GATE
    GATE -->|code 0| SHIP["déploiement"]
    GATE -->|code 1| STOP["livraison bloquée"]
```

## À quelle étape chaque défense agit

L'attaque progresse de gauche à droite, de la publication à l'exécution. Plus une
défense agit tôt, meilleure est la garantie, puisque l'imposteur n'est même pas
sélectionné.

```mermaid
flowchart LR
    S1["publication"] --> S2["résolution"] --> S3["téléchargement"] --> S4["build / install"] --> S5["exécution / import"]

    NR["Réservation d'espace de noms"] -.bloque.-> S1
    SC["Registre scopé"] -.bloque.-> S2
    PS["Policy-as-code"] -.bloque.-> S2
    LP["Lockfile + empreintes"] -.bloque.-> S4
    SG["Vérification de signature"] -.bloque.-> S4
```

## Composants

| Couche | Chemin | Responsabilité |
|---|---|---|
| Registre | `scsim/runner.py` | Index privé local (pypiserver) |
| Imposteur | `packages/internal-auth-utils/` | Démontre le mécanisme d'attaque (inoffensif) |
| Cible | `target-app/` | Application consommatrice volontairement vulnérable |
| Supervision | `monitoring/` | Capture et visualise les balises, console de sécurité |
| Détection | `detection/` | Détecteurs intégrité, réseau, système de fichiers |
| Défenses | `defenses/` | Cinq contrôles préventifs et scanner de politique |
| SBOM | `security/sbom.py` | Inventaire CycloneDX |
| Scan CVE | `security/cve_scan.py` | Corrélation OSV / Trivy |
| Porte | `security/gate.py`, `security/security-policy.yml` | Porte de livraison configurable |
| CI/CD | `.gitlab-ci.yml`, `.github/workflows/ci.yml` | Enchaîne la chaîne et bloque le déploiement en cas d'échec |
| Orchestrateur | `scsim/runner.py` | Démonstration narrée en une commande |
| Tests | `tests/` | Suite pytest hors ligne |
