# Sentry — Dynamic Application Security Testing

A graph-driven DAST tool that ingests API specifications, builds a knowledge graph in Memgraph, actively scans live targets for zombie APIs and shadow endpoints, passively collects real-world traffic via Kafka, and uses statistical anomaly detection to surface threats.

---

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────────┐
│  OpenAPI/Swagger │────▶│  Parser (Go)     │────▶│  Memgraph (Graph DB)  │
│  Specification   │     │  openapi3/swagger2│     │  Attack Surface Graph │
└─────────────────┘     └──────────────────┘     └───────────┬───────────┘
                                                             │
                         ┌───────────────────────────────────┘
                         ▼
                  ┌──────────────┐     ┌──────────────────┐
                  │ Scan Engine  │────▶│ Findings Report  │
                  │ (5 Strategies)│     │ (Table / JSON)   │
                  └──────────────┘     └──────────────────┘

┌─────────────┐     ┌──────────────────┐     ┌────────────────────────┐
│ API Gateway │────▶│  Kafka Consumer  │────▶│  SQLite (traffic.db)   │
│ Traffic Logs │     │  (Go)            │     │  Historical API Traffic│
└─────────────┘     └──────────────────┘     └───────────┬────────────┘
                                                          │
                         ┌────────────────────────────────┘
                         ▼
                  ┌──────────────────────┐     ┌──────────────────┐
                  │  Anomaly Detector    │────▶│  POST /predict   │
                  │  (Python + FastAPI)  ├─┐   │  Model Registry  │
                  └──────────────────────┘ │   └──────────────────┘
                                           ▼
                                    ┌─────────────┐
                                    │ Redis Cache │
                                    │ (LFU + TTL) │
                                    └─────────────┘
```

## Features

### 1. Spec Ingestion & Knowledge Graph
- **OpenAPI 3.x & Swagger 2.0** parsing (Swagger auto-converts to 3.0)
- **Memgraph integration** — builds a lean topological graph where Paths and Operations are nodes, and schema details (parameters, request bodies, responses) are stored as JSON properties
- **Idempotent** — MERGE semantics prevent duplicates on re-import

### 2. Active DAST Scanner (5 Strategies)
| Strategy | What it does |
|:---|:---|
| `deprecated_alive` | Probes endpoints marked `deprecated: true` in the spec to see if they still respond |
| `version_probe` | Tries older/newer API version prefixes (e.g. `/v1/` when spec defines `/v2/`) |
| `method_probe` | Sends undocumented HTTP methods (e.g. `DELETE` on a `GET`-only endpoint) |
| `shadow_path` | Probes ~46 common shadow paths (`/debug/pprof/`, `/actuator/env`, `/swagger.json`, etc.) |
| `auth_bypass` | Re-tests zombie findings WITHOUT auth headers to detect unauthenticated access |

### 3. Deep Inspection & False-Positive Suppression
- **Baseline Differential Analysis** — probes a guaranteed non-existent path on startup to fingerprint catch-all routes, suppressing false positives from WAFs and wildcard handlers
- **JSON Schema Validation** — validates response bodies against the OpenAPI schema using `jsonschema/v6`. Schema-matching responses are `CRITICAL`; non-matching responses are downgraded to `MEDIUM`
- **Retirement Keyword Heuristics** — detects gracefully retired endpoints by scanning response bodies for keywords like "deprecated", "sunset", "retired"
- **Graph-Calculated Blast Radius** — The threat classification engine now calculates the dynamic risk score using the actual downstream dependency chain traversed from the target endpoint in the graph database.

### 4. Kafka Traffic Consumer
- Consumes real-time API gateway traffic logs from a Kafka topic
- **Live Graph-Context Resolving** — When a log packet arrives via Kafka, the Go engine now runs a high-speed, constant-time Cypher traversal against the graph before talking to Python. It resolves the exact path template, verifies if the route is marked deprecated, and extracts the expected SecurityScheme and associated Tag.
- Stores raw request/response data in a local **SQLite** database (`traffic.db`) with batched transactions for high throughput
- Query parameters are stored in a separate column for easy filtering

### 5. Python Anomaly Detection API
- **Statistical engine** using only Python's standard library (`statistics`, `sqlite3`) — no NumPy/Pandas/Scikit-Learn
- **Categorical anomalies** — flags unseen `(method, path)` combinations as Shadow APIs
- **Numerical anomalies** — Z-score analysis on request/response body lengths per endpoint
- **Topology-Aware Machine Learning** — The Isolation Forest model now accepts live Graph Topology Features (e.g., whether the endpoint is deprecated in the graph, whether it requires authentication, and its downstream microservice dependency count).
- **Model Registry** — every trained model is serialized to JSON and persisted in SQLite with a unique version ID
- **Zero-downtime model swaps** — Python's GIL guarantees atomic pointer assignment; in-flight predictions finish on the old model while new requests route to the freshly trained model
- **24-hour auto-retraining** via `APScheduler`
- **Redis Caching Layer** — Integrates a Redis cache to store non-anomalous results. Programmatically configures `maxmemory` and `allkeys-lfu` eviction to bypass re-evaluation for hot known-normal traffic, with a 5-minute TTL staleness guard.

---

## Quick Start

### Prerequisites

- **Go 1.23+**
- **Python 3.10+**
- **Memgraph** running on `bolt://localhost:7687`
- **Redis** (optional, for anomaly detector caching — auto-degrades if down)
- **Kafka** (optional, for traffic consumption)

### Build the Go binary

```bash
go build -o sentry ./cmd/sentry
```

### 1. Ingest a Spec

```bash
# Ingest the Petstore spec
./sentry ingest --file swagger.json --clean

# Custom Memgraph URI
./sentry ingest --file openapi.yaml --memgraph-uri bolt://db:7687
```

### 2. Scan a Live Target

```bash
# Full scan with table output
./sentry scan --target https://api.example.com

# Scan with auth headers and higher concurrency
./sentry scan --target https://api.example.com \
  --header "Authorization: Bearer token123" \
  --workers 10 --rps 20

# Dry run (see what would be probed without sending requests)
./sentry scan --target https://api.example.com --dry-run

# JSON output
./sentry scan --target https://api.example.com --output json

# Run specific strategies only
./sentry scan --target https://api.example.com \
  --strategies deprecated_alive,shadow_path
```

### 3. Consume Traffic from Kafka

```bash
./sentry consume-traffic \
  --kafka-brokers localhost:9092 \
  --kafka-topic api-gateway-logs \
  --sqlite-db traffic.db
```

### 4. Run the Anomaly Detector

```bash
cd anomaly-detector
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 5001
```

**API Endpoints:**

| Method | Path | Description |
|:---|:---|:---|
| `POST` | `/predict` | Analyze a single traffic event for anomalies |
| `GET` | `/models` | List all historically trained model versions |
| `POST` | `/models/retrain` | Force immediate background retraining |
| `GET` | `/health` | Health check with active model info |

**Example prediction request:**
```bash
curl -X POST http://127.0.0.1:5001/predict \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "abc-123",
    "method": "DELETE",
    "path": "/api/users",
    "status_code": 200,
    "timestamp": "2024-01-01T12:00:00Z"
  }'
```

---

## Graph Schema

### Nodes

| Label | Description |
|:---|:---|
| `Spec` | Root node for an imported API specification |
| `Server` | Base URL / server entry |
| `Path` | URL path template (e.g. `/users/{id}`) |
| `Operation` | HTTP operation with full schema details as JSON properties |
| `SecurityScheme` | Authentication mechanism (apiKey, oauth2, etc.) |
| `Tag` | Logical grouping of operations |
| `Scan` | Metadata about a completed scan run |
| `Finding` | A security finding discovered during scanning |

### Relationships

```
Spec ──HAS_SERVER──▶ Server
Spec ──HAS_PATH──▶ Path
Spec ──DEFINES_SECURITY──▶ SecurityScheme
Spec ──HAS_TAG──▶ Tag
Path ──HAS_OPERATION──▶ Operation
Operation ──TAGGED──▶ Tag
Operation ──REQUIRES_SECURITY──▶ SecurityScheme
Finding ──BELONGS_TO_SCAN──▶ Scan
Finding ──FOUND_ON──▶ Operation
```

### Example Cypher Queries

```cypher
-- All operations with their paths
MATCH (s:Spec)-[:HAS_PATH]->(p:Path)-[:HAS_OPERATION]->(o:Operation)
RETURN s.title, p.template, o.method, o.operationId;

-- Find deprecated operations
MATCH (o:Operation) WHERE o.deprecated = true
RETURN o.path, o.method, o.summary;

-- View scan findings
MATCH (f:Finding)-[:BELONGS_TO_SCAN]->(s:Scan)
RETURN f.severity, f.title, f.path, f.method, s.target
ORDER BY f.severity;
```

---

## Configuration

### Go CLI Flags

| Flag | Env Variable | Default | Description |
|:---|:---|:---|:---|
| `--memgraph-uri` | `SENTRY_MEMGRAPH_URI` | `bolt://localhost:7687` | Memgraph Bolt URI |
| `--memgraph-user` | `SENTRY_MEMGRAPH_USER` | (empty) | Memgraph username |
| `--memgraph-pass` | `SENTRY_MEMGRAPH_PASS` | (empty) | Memgraph password |
| `--verbose`, `-v` | — | `false` | Enable verbose output |
| `--target`, `-t` | — | — | Base URL of the live API to scan |
| `--workers`, `-w` | — | `5` | Number of concurrent workers |
| `--rps`, `-r` | — | `10` | Maximum requests per second |
| `--dry-run` | — | `false` | Print probe plan without sending requests |
| `--insecure`, `-k` | — | `false` | Skip TLS verification |
| `--output`, `-o` | — | `table` | Output format (`table` or `json`) |

### Python Environment Variables

| Variable | Default | Description |
|:---|:---|:---|
| `SENTRY_DB_PATH` | `../traffic.db` | Path to the SQLite database |
| `SENTRY_REDIS_URL` | `redis://localhost:6379` | URL to the Redis instance |
| `SENTRY_CACHE_TTL` | `300` | TTL in seconds for cached predictions |
| `SENTRY_REDIS_MAXMEMORY` | `64mb` | Limit for the Redis memory usage configuration |

---

## Project Structure

```
├── cmd/sentry/main.go            — CLI entry point (ingest, scan, consume-traffic)
├── internal/
│   ├── config/config.go          — Configuration with env var support
│   ├── parser/                   — OpenAPI/Swagger parsing
│   │   ├── parser.go             — Parser interface + format auto-detection
│   │   ├── openapi3.go           — OpenAPI 3.x implementation
│   │   └── swagger2.go           — Swagger 2.0 → 3.0 conversion
│   ├── model/                    — Internal representation structs
│   │   ├── spec.go               — API spec, path, operation models
│   │   ├── finding.go            — Finding, Scan, Probe, ScanConfig
│   │   ├── probe_util.go         — URL building, dummy values, evidence formatting
│   │   └── traffic.go            — TrafficEvent model for Kafka
│   ├── graph/                    — Memgraph operations
│   │   ├── client.go             — Connection management
│   │   ├── schema.go             — Index creation
│   │   ├── ingestor.go           — Model → Cypher ingestion
│   │   └── reader.go             — Graph queries + scan/finding persistence
│   ├── scanner/                  — DAST scanning engine
│   │   ├── engine.go             — Orchestrator (worker pool, rate limiting, 2-phase scan)
│   │   ├── analyzer.go           — Finding evaluation with deep inspection
│   │   ├── schema_cache.go       — Thread-safe JSON schema validation cache
│   │   ├── http.go               — Tuned HTTP client for probing
│   │   ├── reporter.go           — Table and JSON report formatters
│   │   └── strategies/           — Detection strategies
│   │       ├── deprecated.go     — Deprecated endpoint detection
│   │       ├── version.go        — API version variant probing
│   │       ├── methods.go        — Undocumented HTTP method detection
│   │       ├── shadow.go         — Shadow/undocumented path discovery
│   │       └── authbypass.go     — Authentication bypass testing
│   ├── consumer/kafka.go         — Kafka traffic consumer with batching
│   └── storage/sqlite.go         — SQLite storage for API traffic
├── anomaly-detector/             — Python anomaly detection microservice
│   ├── app.py                    — FastAPI server with APScheduler
│   ├── detector.py               — ModelVersion, ModelRegistry, DetectorService
│   ├── seed_db.py                — Test data seeder
│   └── requirements.txt          — Python dependencies
└── testdata/                     — Sample specs for testing
```

---

## Tech Stack

| Component | Technology |
|:---|:---|
| Core CLI & Scanner | Go |
| Graph Database | Memgraph (Neo4j Bolt protocol) |
| Spec Parsing | `kin-openapi` |
| Message Queue | Apache Kafka (`segmentio/kafka-go`) |
| Traffic Storage | SQLite (`modernc.org/sqlite`, CGO-free) |
| Schema Validation | `santhosh-tekuri/jsonschema/v6` |
| Anomaly Detection | Python 3 + FastAPI |
| Model Scheduling | APScheduler |
| Result Caching | Redis (LFU eviction policy) |
