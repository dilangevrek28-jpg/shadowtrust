# ShadowTrust Backend

Explainable account-takeover detection API. The backend accepts canonical
security events, evaluates versioned rules, and persists each event together
with its auditable risk decision.

## Local setup (PowerShell)

```powershell
uv sync --all-groups
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\shadowtrust-api.exe
```

The API binds to `127.0.0.1:8000` by default. Useful local endpoints:

- OpenAPI UI: `http://127.0.0.1:8000/docs`
- Liveness: `http://127.0.0.1:8000/health/live`
- Readiness: `http://127.0.0.1:8000/health/ready`

The application deliberately does not create tables at startup. Alembic owns
the database schema, so a missing or outdated schema is detected by readiness
instead of being silently changed by the web process.

## Request correlation and JSON logs

Every HTTP response contains an `X-Request-ID` UUID. A caller may provide its
own valid UUID in the same header; invalid values are replaced. All ShadowTrust
application logs are single-line JSON and carry that request ID, allowing one
request to be followed across access and security-decision records.

Security-event logs intentionally contain decision metadata but omit raw event
payloads, source IP addresses, transfer amounts, and credentials.

## HTTP safety boundary

Request bodies are capped at 1 MiB by default and oversized requests receive a
structured `413` response before domain processing. Validation errors use a
stable `422` contract that reports locations and error types without echoing
the submitted values. Responses include `no-store`, anti-sniffing,
anti-framing, referrer, and browser-permission headers. Unexpected exceptions
are logged internally but returned as a generic structured `500` response.

## Runtime environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `SHADOWTRUST_ENVIRONMENT` | `development` | Runtime label: `development`, `test`, or `production`. |
| `SHADOWTRUST_DATABASE_URL` | `sqlite+pysqlite:///./shadowtrust.db` | SQLAlchemy database URL. |
| `SHADOWTRUST_DATABASE_ECHO` | `false` | Enables SQL statement logging when `true`. |
| `SHADOWTRUST_API_HOST` | `127.0.0.1` | Network interface used by Uvicorn. |
| `SHADOWTRUST_API_PORT` | `8000` | API port from 1 through 65535. |
| `SHADOWTRUST_MAX_REQUEST_BODY_BYTES` | `1048576` | Maximum buffered HTTP request body (1 KiB to 10 MiB). |
| `SHADOWTRUST_INGESTION_API_KEYS` | empty | Comma-separated event-producer API keys; required in production. |
| `SHADOWTRUST_ANALYST_API_KEYS` | empty | Comma-separated read-only analyst API keys; required in production. |
| `SHADOWTRUST_METRICS_API_KEYS` | empty | Comma-separated monitoring API keys; required in production. |
| `SHADOWTRUST_RATE_LIMIT_REQUESTS` | `120` | Requests allowed per producer in one window. |
| `SHADOWTRUST_RATE_LIMIT_WINDOW_SECONDS` | `60` | Fixed rate-limit window in seconds. |
| `SHADOWTRUST_LOG_LEVEL` | `info` | Uvicorn log level. |

In development, empty API-key lists keep local synthetic workflows convenient.
Production configuration is rejected unless all three roles have at least one key
of 16 or more characters. During rotation, old and new keys can be supplied as
a comma-separated list. Event producers use `X-API-Key`; analyst reads use the
separate `X-Analyst-API-Key` header; monitoring systems use
`X-Metrics-API-Key`.

## Operational metrics

`GET /metrics` returns Prometheus 0.0.4 counter data for processed events,
created decisions, opened analyst cases, and successful case-status
transitions. Labels are deliberately limited to bounded values such as outcome,
risk level, and case status; user, session, event, and case identifiers are not
labels. This prevents sensitive identifiers from leaking and avoids unbounded
metric cardinality.

The registry is process-local and thread-safe. Prometheus should aggregate
counters from every API replica in a multi-process deployment. The Compose web
gateway does not proxy `/metrics`; an internal monitoring service must scrape
`http://api:8000/metrics` with `X-Metrics-API-Key`. Empty metrics keys are only
permitted for convenient local development.

The Compose stack includes Prometheus 3.13 LTS and a provisioned Grafana
dashboard. Prometheus evaluates starter alerts for metrics outage, security
bursts, event-replay spikes, and decision-replay mismatches. Grafana visualizes
target health, event throughput, decisions by risk level, opened cases, case
transitions, and replay outcomes.

## Analyst read API

- `GET /api/v1/analyst/sessions` returns one latest risk snapshot per session.
- `minimum_risk`, `risk_level`, `page`, and `page_size` query parameters support
  filtering and pagination.
- `case_status` filters by workflow state or the special `unassigned` value.
- Queue responses include per-status `case_counts` plus the case ID, status, and
  version attached to each session summary.
- `GET /api/v1/analyst/decisions/{decision_id}` returns the complete rule trace.
- `POST /api/v1/analyst/decisions/{decision_id}/replay` rebuilds the historical
  context and compares a fresh result with the stored decision.
- Existing event and session-timeline reads also require analyst access when
  analyst authentication is configured.

The session list defaults to `minimum_risk=1`, so zero-risk sessions stay out
of the analyst queue unless the caller explicitly requests `minimum_risk=0`.

Decision replay uses the recorded `risk_before` and exact baseline version. It
executes only when the active engine version, rule-set version, and ordered rule
identities match the stored decision. The result is `reproduced` for an exact
semantic match, `drifted` when compatible identities produce different scores,
rule traces, explanations, or actions, and `incompatible` when faithful
execution is impossible. Replays are read-only and never insert another
decision row.

The current rate limiter is deliberately process-local and intended for the
single-process MVP. A multi-replica deployment must replace its in-memory
buckets with a shared atomic store such as Redis or a gateway-level limiter.

## Analyst case workflow

Risk decisions can be promoted into a durable analyst case:

- `POST /api/v1/analyst/cases` opens one case for a session that has a decision.
- `GET /api/v1/analyst/cases/{case_id}` reads the current case and full audit trail.
- `GET /api/v1/analyst/sessions/{session_id}/case` finds the case for a session.
- `POST /api/v1/analyst/cases/{case_id}/transitions` changes case status.

Mutations require both `X-Analyst-API-Key` and `X-Analyst-ID`. The API key
authorizes the request but is never stored; the validated analyst ID is written
to the audit entry. Case states are `open`, `investigating`,
`confirmed_takeover`, `false_positive`, and `closed`.

Every transition requires a human-readable note and the caller's
`expected_version`. A stale version receives `409 case_version_conflict` rather
than overwriting another analyst's work. Audit rows are only appended by the
application, their sequence is unique per case, and the database prevents a
case from being deleted while its audit history exists.

Opening and transitioning cases emits structured `analyst_case_opened` and
`analyst_case_transitioned` records. Logs contain identifiers, status, version,
and request correlation metadata but deliberately omit API keys and analyst
notes.

## Docker Compose with PostgreSQL

Run these commands from the project root, one directory above this README:

```powershell
Copy-Item .env.example .env
# Replace the placeholder passwords and role-specific API keys inside .env.
docker compose up --build
```

For the local Compose stack, set `SHADOWTRUST_PROMETHEUS_API_KEY` to one exact
key also present in `SHADOWTRUST_METRICS_API_KEYS`. Compose mounts that value
only into Prometheus as a read-only secret file. Set a strong
`SHADOWTRUST_GRAFANA_ADMIN_PASSWORD`; Grafana reads it through the same
file-secret mechanism. The operations dashboard is available only on the local
machine at `http://127.0.0.1:3000` by default.

Compose starts PostgreSQL first, waits for its health check, runs Alembic in a
one-shot `migrate` container, and starts the API only after the migration exits
successfully. The non-root Nginx frontend starts after the API is healthy and
publishes the complete application at `http://127.0.0.1:8080` by default.
PostgreSQL, the API, and Prometheus stay on the internal Compose network; Nginx
proxies `/api` and `/health` to the API. Grafana is bound specifically to the
host loopback interface. PostgreSQL, Prometheus, and Grafana use named volumes
so their state survives a normal restart.

The PostgreSQL password is interpolated into a SQLAlchemy URL, so the local
Compose password must be URL-safe unless it is percent-encoded. Never commit
the generated `.env` file; only `.env.example` belongs in source control.

Stop containers without deleting database data:

```powershell
docker compose down
```

Example override:

```powershell
$env:SHADOWTRUST_API_PORT = "9000"
$env:SHADOWTRUST_DATABASE_ECHO = "true"
.\.venv\Scripts\shadowtrust-api.exe
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Detection-quality report

Run the independent evaluation split and write a deterministic JSON report:

```powershell
.\.venv\Scripts\shadowtrust-evaluate.exe `
  --split evaluation `
  --minimum-recall 1.0 `
  --maximum-false-positive-rate 0.0 `
  --output ..\outputs\evaluation-report.json
```

The report records corpus, engine, rule-set and threshold identity; the
confusion matrix; precision, recall and false-positive rate; average detection
latency; unnecessary step-up count; and every scenario timeline. An unmet
quality gate returns process exit code `1`, so CI blocks a rule change that
silently reduces holdout recall or increases false positives.
