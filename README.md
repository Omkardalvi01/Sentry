# Sentry — Dynamic Application Security Testing

A Go-based DAST tool that builds a graph-based representation of your API's attack surface from OpenAPI/Swagger specifications.

## Features

- **OpenAPI 3.x & Swagger 2.0** — Parses both formats (Swagger 2.0 auto-converts to 3.0)
- **Memgraph Integration** — Ingests API structure into a graph database for rich querying
- **Lean Topological Graph** — Paths and operations are nodes; schema details (parameters, request bodies, responses) are stored as JSON properties
- **Idempotent** — Uses MERGE semantics, safe to re-import without duplicates
- **Fast** — Batched transaction, indexed lookups

## Quick Start

### Prerequisites

- **Go 1.23+**
- **Memgraph** running on `bolt://localhost:7687`

### Build

```bash
go build -o sentry ./cmd/sentry
```

### Ingest a spec

```bash
# Ingest the sample Petstore spec
./sentry ingest --file testdata/petstore.yaml --verbose

# Clean existing data before import
./sentry ingest --file testdata/petstore.yaml --clean

# Custom Memgraph URI
./sentry ingest --file testdata/petstore.yaml --memgraph-uri bolt://db:7687
```

### Query the graph

```cypher
-- Show all operations with their paths
MATCH (s:Spec)-[:HAS_PATH]->(p:Path)-[:HAS_OPERATION]->(o:Operation)
RETURN s.title, p.template, o.method, o.operationId;

-- Find operations requiring authentication
MATCH (o:Operation)-[:REQUIRES_SECURITY]->(sc:SecurityScheme)
RETURN o.operationId, sc.name, sc.type;

-- View schema details on an operation
MATCH (o:Operation {operationId: "createPet"})
RETURN o.requestBody, o.responses;

-- Count nodes by type
MATCH (n) RETURN labels(n) AS label, count(n) AS cnt;
```

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

### Relationships

```
Spec --HAS_SERVER--> Server
Spec --HAS_PATH--> Path
Spec --DEFINES_SECURITY--> SecurityScheme
Spec --HAS_TAG--> Tag
Path --HAS_OPERATION--> Operation
Operation --TAGGED--> Tag
Operation --REQUIRES_SECURITY--> SecurityScheme
```

## Configuration

| Flag | Env Variable | Default | Description |
|:---|:---|:---|:---|
| `--memgraph-uri` | `SENTRY_MEMGRAPH_URI` | `bolt://localhost:7687` | Memgraph Bolt URI |
| `--memgraph-user` | `SENTRY_MEMGRAPH_USER` | (empty) | Memgraph username |
| `--memgraph-pass` | `SENTRY_MEMGRAPH_PASS` | (empty) | Memgraph password |
| `--verbose`, `-v` | — | `false` | Enable verbose output |
| `--clean` | — | `false` | Wipe graph before import |

## Project Structure

```
├── cmd/sentry/main.go       — CLI entry point
├── internal/
│   ├── parser/               — OpenAPI/Swagger parsing
│   │   ├── parser.go         — Parser interface + auto-detection
│   │   ├── openapi3.go       — OpenAPI 3.x implementation
│   │   └── swagger2.go       — Swagger 2.0 → 3.0 conversion
│   ├── model/spec.go         — Internal representation structs
│   ├── graph/                — Memgraph operations
│   │   ├── client.go         — Connection management
│   │   ├── schema.go         — Index creation
│   │   └── ingestor.go       — Model → Cypher ingestion
│   └── config/config.go      — Configuration
└── testdata/petstore.yaml    — Sample spec for testing
```
