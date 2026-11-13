# TTP Tool Mapper

A Go API for exploring MITRE ATT&CK techniques and maintaining evidence-backed mappings to tools, procedures, and detections. Designed for research, purple-team planning, and detection engineering; it does not execute procedures.

## Features

- Import the official ATT&CK STIX JSON bundle from a local file.
- Store tactics and platforms as searchable relationships.
- Track sub-technique parents, deprecation/revocation, import versions, and SHA-256 checksums.
- Add tools, procedure mappings, and detections with source, confidence, and review date.
- Paginate and filter API results.
- Secure write endpoints with bearer-token authentication and request-size/rate limits.
- Serve read-only API requests on loopback by default.

## Requirements

- Go 1.22 or newer
- SQLite support via `go-sqlite3` (CGO and a C compiler are needed to build from source)

## Import ATT&CK data

Download an official ATT&CK STIX bundle and import it locally. For example, the Enterprise dataset is published in the [MITRE attack-stix-data repository](https://github.com/mitre-attack/attack-stix-data):

```bash
curl -L \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
  -o /tmp/enterprise-attack.json

go run ./cmd/attack-import \
  --file /tmp/enterprise-attack.json \
  --version snapshot-2026-11-13
```

The version label is required; replace the example with the release or snapshot you downloaded. Imports are transactional and repeatable: re-importing the same version updates the import checksum and timestamp without duplicating techniques. Removed techniques are retained rather than deleted, preserving existing mappings.

Options:

- `--file`: STIX JSON bundle path (required)
- `--version`: release or snapshot label (required)
- `--db`: SQLite path (default `data/ttp_tool_mapper.db`)

## Run the API

Write endpoints are disabled unless an `API_TOKEN` is configured. Generate one and start the server:

```bash
export API_TOKEN="$(openssl rand -hex 32)"
go run ./cmd/server
```

The server listens on `127.0.0.1:8080` by default. Configuration:

| Variable | Default | Description |
| --- | --- | --- |
| `API_ADDR` | `127.0.0.1:8080` | Listen address. Non-loopback addresses require `API_TOKEN`. |
| `API_TOKEN` | unset | Bearer token required for all write endpoints. |
| `API_RATE_LIMIT_PER_MIN` | `600` | Per-client request limit per minute. |
| `DB_PATH` | `data/ttp_tool_mapper.db` | SQLite database path. |

If you expose the service beyond loopback, use a trusted network and a TLS-terminating reverse proxy. Read endpoints are not authenticated; the token protects writes only.

## API

See [`docs/openapi.yaml`](docs/openapi.yaml) for the OpenAPI specification. All endpoints are under `/api/v1`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `GET` | `/techniques` | Search/filter techniques (`q`, `tactic`, `platform`, `deprecated`, `revoked`) |
| `GET` | `/techniques/{attack_id}` | Get a technique by ATT&CK ID, e.g. `T1059.001` |
| `GET` | `/tools` | List/search tools |
| `GET` | `/tools/{id}` | Get a tool and its mappings |
| `GET` | `/mappings` | Filter mappings by ATT&CK ID and/or tool ID/name |
| `GET` | `/imports` | List import versions and checksums |
| `POST` | `/tools` | Add a tool (bearer token required) |
| `POST` | `/procedures` | Add a procedure mapping (bearer token required) |
| `POST` | `/detections` | Add a detection mapping (bearer token required) |

List endpoints support `limit` (1–100, default 20) and `offset` (default 0); responses include a `page` object with the total number of matches. Errors use a consistent `{ "error": { "code": "...", "message": "..." } }` shape.

Example read:

```bash
curl 'http://127.0.0.1:8080/api/v1/techniques?platform=Windows&limit=20'
curl 'http://127.0.0.1:8080/api/v1/techniques/T1059.001'
```

Example write (use internal numeric IDs from the API responses):

```bash
curl -X POST http://127.0.0.1:8080/api/v1/tools \
  -H "Authorization: Bearer $API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Example research tool","category":"analysis","description":"Lab catalog entry"}'
```

Procedure/detection mappings require a `source` and accept `confidence` from 0 to 1 and an optional RFC 3339 `reviewed_at` timestamp.

## Development

```bash
go test ./...
```

SQLite is used for local development. The API does not execute command examples or imported procedures.
