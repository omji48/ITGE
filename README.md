# ITGE - Identity & Trust Graph Engine

Strategic attack-path modeling for red teams, adversary simulation, and security architecture review.

ITGE turns HTTP traffic and discovery data into an identity-and-trust graph, then ranks the paths that matter most:

- where trust is issued
- where trust is validated
- where privilege can be escalated
- where trust boundaries are crossed
- where sensitive data is reachable

This is not a scanner and not an exploit framework. It is a graph-based reasoning engine for understanding how an attacker could move through a system.

## What It Supports

### Ingestion

- Burp Suite XML exports
- OWASP ZAP XML/session exports
- Amass JSON exports
- Nmap XML exports

### Detection

- JWT issuance and validation patterns
- OAuth authorization flow signals
- Missing `state` / missing PKCE heuristics
- Header-based trust assumptions
- Role misuse via query/body/header/JWT claims
- Sensitive endpoint and data exposure heuristics
- Wildcard CORS trust

### Graph Modeling

- `Endpoint`
- `Service`
- `DataStore`
- `IdentityProvider`
- `Token`
- `Role`
- `UserPersona`

### Relationships

- `ISSUES_TOKEN`
- `VALIDATES_TOKEN`
- `TRUSTS`
- `ACCESSES`
- `REQUIRES_ROLE`
- `ESCALATES_TO`
- `CROSSES_BOUNDARY`

### Outputs

- ranked attack paths
- explainable markdown and JSON reports
- CSV exports
- optional FastAPI surface for integrations

## Installation

```bash
git clone https://github.com/omji48/ITGE.git
cd itge
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### 1. Configure Neo4j

```bash
itge config --neo4j-uri bolt://localhost:7687 \
            --neo4j-user neo4j \
            --neo4j-password password \
            --save config.json
```

### 2. Ingest Data

```bash
itge ingest --burp burp_export.xml
itge ingest --zap zap_session.xml
itge ingest --amass amass.json
itge ingest --nmap scan.xml
```

You can mix sources in one run:

```bash
itge ingest --burp burp_export.xml --amass amass.json --nmap scan.xml
```

### 3. Analyze Paths

```bash
itge analyze --persona "Unauthenticated Attacker" \
             --trust-zone external \
             --target-type DataStore \
             --target-sensitivity confidential
```

Privilege-focused analysis:

```bash
itge analyze --persona "Low-Privilege User" \
             --trust-zone internal \
             --target-type Role \
             --min-target-privilege 80
```

### 4. Review Results

```bash
itge show-paths --top 10 --sort-by risk
itge export --format json --output report.json
itge export --format markdown --output report.md
itge export --format csv --output report.csv
```

### 5. Serve API

```bash
itge serve-api --host 127.0.0.1 --port 8000
```

Available endpoints:

- `GET /health`
- `GET /config`
- `GET /analysis/latest`

### 6. Run Preflight Checks

```bash
itge doctor
```

This verifies output directories, API wiring, and attempts a Neo4j connectivity check.

## Architecture

```text
itge/
├── api/               # Optional FastAPI integration surface
├── application/       # Orchestration services
├── cli/               # Typer CLI
├── domain/            # Core models and relationship schema
├── infrastructure/
│   ├── analyzers/     # Trust analyzers
│   ├── detectors/     # Pattern detection in raw traffic
│   ├── graph/         # Neo4j persistence and path search
│   ├── normalizers/   # Conversion into graph-ready entities
│   └── parsers/       # Burp/ZAP/Amass/Nmap adapters
└── tests/             # Focused unit tests
```

## Example Flow

1. Parse Burp, ZAP, Amass, and Nmap artifacts.
2. Detect trust and authorization signals.
3. Normalize them into graph entities.
4. Store them in Neo4j with deduplicated nodes and relationships.
5. Simulate paths from attacker personas to high-value targets.
6. Export explainable reports.

## Development

```bash
pytest
ruff check itge tests
black itge tests
```

## Operations

See [`docs/OPERATIONS.md`](./docs/OPERATIONS.md) for the launch checklist and container-based Neo4j setup.

## Disclaimer

Use only for authorized security testing and defensive research.
