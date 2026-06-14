# Project Report: Identity & Trust Graph Engine (ITGE)

An advanced security architecture review, red teaming, and adversary simulation modeling engine designed to convert network footprinting and application traffic data into a strategic identity-and-trust relationship graph.

---

## 1. Executive Summary & Core Objective

### What is ITGE?
The **Identity & Trust Graph Engine (ITGE)** is a security reasoning platform that ingests network scanning outputs, subdomain discovery assets, and raw HTTP traffic logs to build a unified graph representation of an environment. By analyzing how different entities—such as **Services**, **Endpoints**, **DataStores**, **Identity Providers**, **Tokens**, and **Roles**—are wired together, the engine identifies and ranks multi-step attack paths that an adversary could exploit.

### The "Why": Why Graph-Based Attack Path Modeling Matters
Traditional security tools focus on local vulnerability scanning (e.g., CVE matching) or active exploitation:
- **Scanners** identify missing patches but fail to understand context (e.g., "service A has no vulnerabilities but trusts token B, which is issued by an unauthenticated portal").
- **Exploit Frameworks** (like Metasploit) execute actual payloads, which is risky in production and restricted to known active vulnerabilities.
- **ITGE's Approach** is passive, architectural, and systemic. It models **implicit and explicit trust**. It calculates how an unauthenticated external attacker can chain minor, non-vuln configurations (like wildcard CORS, missing token audience validation, or role-based header parsing) to escalate privileges and access sensitive internal datastores.

---

## 2. Technical Architecture

ITGE is structured as a decoupled, multi-tier intelligence pipeline:

```
+------------------+     +------------------------+     +-------------------------+
|  Input Sources   | --> |   Ingestion & parsing  | --> | Trust Pattern Detection |
| (Burp, ZAP,      |     | (BaseParser, XML/JSON) |     |   (PatternDetector)     |
|  Amass, Nmap)    |     +------------------------+     +-------------------------+
+------------------+                                                 |
                                                                     v
+------------------+     +------------------------+     +-------------------------+
|   Interactive    | <-- |    FastAPI Backend     | <-- |   Neo4j Graph Database  |
|   Dashboard      |     |  (Export API, Server)  |     |   (GraphRepository)     |
| (D3.js Graphing) |     +------------------------+     +-------------------------+
+------------------+                                                 |
                                                                     v
                                                        +-------------------------+
                                                        |   Path Finding/Scoring  |
                                                        |  (ShortestPath Cypher)  |
                                                        +-------------------------+
```

### Flow Sequence:
1. **Ingest & Parse**: XML/JSON data from external security tools are parsed into standard `RawHTTPTransaction` structures.
2. **Detect & Normalize**: The `PatternDetector` scans transactions for micro-signatures (JWTs, parameters, CORS headers, roles). The `TrafficNormalizer` maps these into domain-specific entities.
3. **Persist (Neo4j)**: Normalized nodes and relationships are written to Neo4j. Unique constraints, schemas, and property sanitizations are applied.
4. **Reason & Score**: The `GraphPathFinder` queries Neo4j using Cypher to calculate shortest paths from target attacker personas (e.g. Unauthenticated Attacker) to high-value assets.
5. **Explain & Format**: Paths are evaluated by the `ExplainabilityService` to assess token reuse, boundary crossings, and risk. Explanations are compiled into Markdown and JSON.
6. **Serve & Visualize**: A FastAPI server hosts the API, which serves the interactive, D3.js-powered HTML dashboard allowing users to visualize the graph and download reports.

---

## 3. Core Feature Details & Functional Status

This section details the specific features implemented in the codebase, detailing what works and what represents planned enhancements or current limitations.

### Ingestion Subsystem
- **Burp Suite XML Exports (`BurpXMLParser`)**
  - **How it works**: Parses Burp Proxy history and scanner XML logs. Decodes base64-encoded requests/responses and parses HTTP headers and bodies.
  - **Status**: **Fully Working**. Handles full base64 decode fallbacks and request/response line parsing.
- **OWASP ZAP XML Exports (`ZAPXMLParser`)**
  - **How it works**: Supports two modes: ZAP session XML (history items containing headers and bodies) and ZAP report XML (alert items containing evidence and vulnerabilities).
  - **Status**: **Fully Working**. Automatically detects format types.
- **OWASP Amass JSON Exports (`AmassJSONParser`)**
  - **How it works**: Ingests domain and asset discovery records (domains, ports, IP addresses) and infers public services and potential databases.
  - **Status**: **Fully Working**. Flattens subdomains and tagging configurations.
- **Nmap XML Scan Output (`NmapXMLParser`)**
  - **How it works**: Reads port and service details from Nmap XML files. Automatically registers open ports as Services and maps known ports (e.g. 3306, 5432, 27017) to DataStores.
  - **Status**: **Fully Working**. Filters only open ports and parses product/version banners.

### Pattern Detection System (`PatternDetector`)
Analyzes HTTP headers, parameters, and bodies to extract implicit architectural facts:
- **JWT Pattern Auditing**: Extracts JWT claims (header/payload/cookie) to discover user signatures, token structures, and signing algorithms. (**Working**)
- **OAuth Flow Auditing**: Audits auth endpoints, checking for authorization code parameters, missing `state` CSRF protections, and missing PKCE heuristics. (**Working**)
- **Token Flow Detection**: Tracks where tokens are issued (e.g. `/login`, `/oauth/token`) and validated (e.g. API endpoints). (**Working**)
- **Role Exposure Detection**: Scans query parameters, HTTP headers (e.g., `X-Role`, `X-Admin`), and JSON body keys for roles like "admin" or "privilege_level". (**Working**)
- **CORS Wildcard Auditing**: Audits wildcard headers (`Access-Control-Allow-Origin: *`) combined with credentials checks. (**Working**)
- **Proxy Header Auditing**: Detects headers representing proxy trust constraints (e.g., `X-Forwarded-For`, `X-Real-IP`). (**Working**)
- **Sensitive Data Endpoint Heuristics**: Flags endpoints returning passwords, API keys, credentials, or SSNs. (**Working**)

### Neo4j Persistence Engine (`GraphRepository`)
- **How it works**: Sets up Neo4j unique constraints on node IDs and indices for URLs, trust zones, sensitive flags, token issuers, and role privileges. Coerces complex nested properties into Neo4j primitives.
- **Status**: **Fully Working**. Includes batch processing APIs for high-volume ingestions.

### Path-Traversal & Mathematical Risk Scoring
- **Shortest-Path Traversal (`GraphPathFinder`)**: Uses Neo4j Cypher queries to compute paths from starting trust boundaries (`public`/`external`) or attacker personas to critical targets. (**Working**)
- **Mathematical Risk Scoring**: Attack paths are scored dynamically based on a composite formula:
  
  $$\text{Risk Score} = \min((\text{Confidence} \times \text{Exploitability} \times \text{Impact}) \times \text{Trust Gap Multiplier} \times \text{Exposure Multiplier}, 1.0)$$
  
  - **Confidence**: Mean confidence of path relationships (based on parser certainty).
  - **Exploitability**: Mean of relationship ease of exploit (e.g., unauthenticated vs authenticated).
  - **Impact**: Score (0.0 - 1.0) based on target sensitivity (`critical` / `confidential` / `internal`) or role privilege.
  - **Trust Gap Multiplier**: Increases score if crossing multiple trust barriers (e.g., external -> internal -> privileged).
  - **Exposure Multiplier**: Multiplies risk based on unauthenticated nodes and high-exploitability links along the path.
  - **Status**: **Fully Working**.

### Explainability & Reporting Engine (`ExplainabilityService`)
- **How it works**: Profiles attack paths to extract strategic explanations, identifying exploited trust assumptions, boundary crossings, token reuse risks (tokens accepted across different audiences enabling lateral movement), and comparative rankings. Outputs detailed markdown summaries.
- **Status**: **Fully Working**. Serves as the report generator.

### API & Visualization Dashboard (`FastAPI` & `D3.js`)
- **FastAPI Endpoints**: Serves `/health`, `/config`, `/analysis/latest`, `/export/json`, `/export/markdown`. (**Working**)
- **D3.js UI Dashboard**: Loads D3 force-directed interactive graphs, node labels with zoom/pan, detail view side-panels showing security context, lists of top paths and trust violations, and client-server export controls. (**Working**)
- **Threat View (Intentional Design)**: The dashboard intentionally renders only the nodes and edges that form active, computed attack paths — not all nodes in the database. For example, even if a scan produces 627 graph nodes, the UI may display only 6 if there are 3 identified attack paths involving 6 unique entities. This eliminates the "hairball" problem of unreadable, cluttered graphs and keeps the executive focus on the actual threat, not the noise.
- **Analyst Filter Parameters**: Attack path computation is driven by CLI parameters that analysts can tune per engagement:
  - `--persona` — The attacker's profile (e.g., `"Unauthenticated Attacker"`, `"Malicious Employee"`)
  - `--trust-zone` — Starting trust boundary (e.g., `external`, `dmz`, `internal`)
  - `--target-type` — Asset class to compromise (e.g., `DataStore`, `Role`, `Endpoint`)
  - `--target-sensitivity` — Classification threshold (e.g., `confidential`, `restricted`)
  - `--max-hops` — Maximum adversarial chain length (default: `10`)

---

## 4. Gaps, Limitations & Areas for Improvement

To ensure the director has a transparent assessment of the system, note these limitations and future roadmap recommendations:

| Component / Feature | Current Status / Limitation | Recommended Roadmap Solution |
| :--- | :--- | :--- |
| **Data Streaming** | **Static Files Only**: Relies on manual tool exports (XML, JSON). Cannot monitor live traffic. | Implement active proxies or syslog listener endpoints to process live JSON streams. |
| **Authentication & AuthZ** | **No API/UI Security**: Dashboard is open to anyone with local port access. Single-tenant model. | Add OAuth2/OIDC login middleware (FastAPI security) and multi-tenant project separation. |
| **DB Dependency** | **Neo4j Hard Requirement**: If Neo4j goes down, path analyses fail completely. | Add a local SQLite fallback for offline parsing and basic tree-based path routing. |
| **XML Memory Footprint** | **DOM Parsing**: Large XML imports (>500MB) can cause high memory usage due to DOM loading. | Rewrite parsers using Python's SAX or `ElementTree.iterparse` for stream processing. |
| **Exploit Validation** | **Heuristics only**: Identifies potential paths, but does not verify if they are actively exploitable. | Integrate a validation pipeline to perform safe HTTP verification requests (e.g., token test requests). |

---

## 5. Operations & Setup Guide

> **Note on CLI Design**: ITGE ships with a top-level `itge` command registered as a console script entry point. All operations are accessible via short, memorable sub-commands — no need to invoke Python modules directly.

### Local Launch Checklist
1. **Start the Neo4j Graph Database**:
   ```bash
   docker compose up -d neo4j
   ```
2. **Run Environment Diagnostics**:
   ```bash
   itge doctor
   ```
   *(Checks Neo4j connectivity, output directories, and tool availability.)*

3. **Ingest Security Scan Files**:
   ```bash
   itge ingest --burp burp_export.xml --zap zap_report.xml --amass amass.json --nmap scan.xml
   ```
   *(Supports any combination of Burp Suite, OWASP ZAP, Amass, and Nmap outputs.)*

4. **Run Attack Path Analysis**:
   ```bash
   itge analyze --persona "Unauthenticated Attacker" --trust-zone external --target-type DataStore --target-sensitivity confidential
   ```
   *(Tune `--persona`, `--trust-zone`, `--target-type`, and `--target-sensitivity` per engagement.)*

5. **Launch the API Server**:
   ```bash
   itge serve-api --host 127.0.0.1 --port 8000
   ```

6. **Open the Interactive Dashboard**:
   Serve the dashboard HTML from the project root:
   ```bash
   python -m http.server 8080
   ```
   Then open `http://localhost:8080/dashboard.html` in a browser.

---

## 6. Future Product Roadmap

The following planned enhancements represent the next evolution of ITGE from an analyst tool into a full-scale enterprise security intelligence platform. These features are prioritized by impact and implementation complexity.

### 🔴 High Priority

| Feature | Description |
| :--- | :--- |
| **Graph Explorer Toggle** | Add a UI toggle to switch between **Threat View** (attack paths only — current default) and **Explorer View** (all ingested nodes, grouped and clustered by trust zone). This gives analysts the full network topology picture while keeping the default executive-friendly. |
| **Interactive Analysis Sandbox** | Replace CLI-only filter parameters with live dashboard controls — dropdowns for attacker persona, target asset type, sensitivity, and trust zone. Analysts can ask *"What if the attacker is an internal employee?"* and watch the graph update in real-time without touching the terminal. |

### 🟡 Medium Priority

| Feature | Description |
| :--- | :--- |
| **Live Traffic Streaming** | Replace manual XML/JSON export imports with an active proxy listener or syslog endpoint. ITGE would continuously ingest and re-analyze traffic in real time, turning it from a post-engagement tool into a live monitoring platform. |
| **Dashboard Authentication & Authorization** | Secure the web UI and API with an OAuth2/OIDC login layer (FastAPI security middleware). Support role-based access — e.g., *Viewer* (read-only graphs) vs. *Analyst* (trigger analysis runs). |
| **Automated PDF/HTML Report Export** | Generate polished, board-ready PDF reports directly from the dashboard with a single click, embedding the graph visualization, top paths, and risk scoring narrative. |

### 🟢 Lower Priority (Longer-term Vision)

| Feature | Description |
| :--- | :--- |
| **Multi-tenant Client Projects** | Support separate Neo4j namespaces or databases per client engagement, enabling ITGE to serve as a shared SaaS platform for security consulting teams. |
| **Exploit Validation Pipeline** | After identifying a theoretical attack path, perform a safe, controlled HTTP probe (e.g., send a crafted token request) to confirm whether the path is actively exploitable — bridging the gap between heuristic modeling and real-world confirmation. |
| **SQLite Offline Fallback** | Add a lightweight local database backend for environments where Neo4j cannot be deployed, enabling offline analysis and basic tree-based path routing without Docker. |
| **CI/CD Integration Plugin** | Provide a GitHub Actions / GitLab CI plugin that runs `itge ingest` + `itge analyze` automatically on every deployment, blocking merges if new critical attack paths are introduced. |

---
*Report generated for company director review on May 23, 2026.*
