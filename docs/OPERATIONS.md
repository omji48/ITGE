# Operations Guide

## Local Launch

1. Start Neo4j:

```bash
docker compose up -d neo4j
```

2. Verify the environment:

```bash
itge doctor
```

3. Ingest data:

```bash
itge ingest --burp burp_export.xml --amass amass.json --nmap scan.xml
```

4. Run analysis:

```bash
itge analyze --persona "Unauthenticated Attacker" --trust-zone external
```

5. Serve API if needed:

```bash
itge serve-api --host 0.0.0.0 --port 8000
```

## Expected Artifacts

- `itge_output/analysis_result.json`
- `itge_output/explanation_path_*.json`
- `itge_output/explanation_path_*.md`

## Pre-Launch Checklist

- `pytest` passes
- `itge doctor` shows Neo4j connectivity as OK
- ingestion completes on representative sample data
- analysis produces ranked paths
- exported markdown/json artifacts are reviewed
