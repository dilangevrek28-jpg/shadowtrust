# ShadowTrust

ShadowTrust is an explainable banking account-takeover detection system. Event
producers send canonical security events to the API; deterministic rules create
auditable risk decisions; analysts investigate the latest risky sessions in the
React console.

## Why this project exists

Account-takeover controls must do more than emit an opaque score. ShadowTrust is
designed to preserve the evidence, rule trace, historical context, engine
identity, and response recommendation behind every decision. The result is a
defensive-security portfolio system that can explain a decision to an analyst,
replay it later, and track the human investigation without silently overwriting
concurrent work.

## Key capabilities

- Strict, versioned security-event contracts with idempotent ingestion and
  out-of-order event protection.
- Deterministic signal, contradiction, and recovery rules with bounded scoring,
  evidence event IDs, and adaptive response actions.
- Historical decision replay that reports exact reproduction, semantic drift,
  or version incompatibility without inserting a new operational decision.
- Paginated analyst risk queue, session timeline, rule trace, and an append-only
  case workflow protected by optimistic concurrency.
- SQLite-backed local testing and PostgreSQL production persistence with
  version-controlled Alembic migrations.
- Role-separated API keys, request limits, structured errors and logs, security
  headers, health endpoints, and protected Prometheus metrics.
- Non-root Docker images, an internal-service Compose network, provisioned
  Prometheus alerts and Grafana dashboard, and frozen-lockfile CI builds.

## Technology

- Backend: Python 3.12+, FastAPI, Pydantic, SQLAlchemy, Alembic, PostgreSQL
- Frontend: React, TypeScript, Vite, Vitest, Nginx
- Operations: Docker Compose, Prometheus, Grafana, GitHub Actions
- Quality: pytest, deterministic synthetic evaluation, dependency audits,
  container contract tests

## Architecture at a glance

```text
Producer -> FastAPI -> ingestion service -> context + baseline -> rule engine
                    -> atomic event/decision persistence -> PostgreSQL

Analyst -> Nginx/React -> protected analyst API -> timeline/replay/case audit

API metrics -> Prometheus -> Grafana + security alert rules
```

The complete component boundaries and event, case, and replay sequences are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Verified quality snapshot

- 202 backend unit, integration, API, migration, security, and deployment tests
- 4 frontend API-client tests plus strict TypeScript and production Vite build
- Evaluation split: precision 1.0, recall 1.0, false-positive rate 0.0, with the
  synthetic-corpus limitations documented explicitly
- CI validation for Python 3.12 and 3.14, frontend build, Compose configuration,
  application image builds, and weekly production-dependency audits

These evaluation values are regression evidence for the small synthetic corpus,
not a claim of production banking accuracy. See
[`docs/EVALUATION.md`](docs/EVALUATION.md) for the exact limitations.

## Production-style local stack

```powershell
Copy-Item .env.example .env
# Add database, API, Prometheus, and Grafana secrets.
docker compose up --build
```

Open `http://127.0.0.1:8080`. This Nginx gateway serves the analyst console and
proxies API traffic. PostgreSQL and the Python API are intentionally not
published directly to the host.

The startup order is:

1. PostgreSQL becomes healthy.
2. Alembic applies the database migration.
3. The API starts and passes readiness.
4. Prometheus begins protected internal metric collection.
5. Grafana loads the provisioned operations dashboard.
6. The web gateway starts and exposes the analyst application.

Use an ingestion key in `X-API-Key` when sending events and an analyst key in
`X-Analyst-API-Key` when reading protected investigation data. Never commit the
generated `.env` file.

Prometheus-compatible operational counters are available only on the internal
API service at `/metrics` and require `X-Metrics-API-Key`; the public Nginx
gateway intentionally does not proxy this endpoint.

The stack scrapes those counters with an internal Prometheus service and loads
a ready-made Grafana dashboard at `http://127.0.0.1:3000`. Set
`SHADOWTRUST_PROMETHEUS_API_KEY` to one value from
`SHADOWTRUST_METRICS_API_KEYS`, and choose a strong
`SHADOWTRUST_GRAFANA_ADMIN_PASSWORD` before startup. Prometheus itself is not
published to the host network.

Analysts can replay any stored decision from the investigation panel. The API
reconstructs the historical baseline and event context, verifies engine and
rule identity, and reports whether the result was reproduced, drifted, or is
incompatible with the currently active detector.

Analyst case mutations additionally require `X-Analyst-ID`. This identifier is
recorded in the append-only case history; API keys and raw credentials are not.
The analyst console exposes this workflow directly in each session's
investigation panel and refreshes stale cases on optimistic-lock conflicts.

See `backend/README.md` and `frontend/README.md` for component-level development
commands and architecture notes.

Portfolio and governance references:

- `docs/ARCHITECTURE.md` traces the event, decision, replay, case, and operations
  flows across the system's component boundaries.
- `docs/EVALUATION.md` explains the current metrics and their limitations.
- `SECURITY.md` defines the authorized lab boundary and disclosure process.
- `CONTRIBUTING.md` defines rule-versioning, testing, migration, and telemetry
  requirements for future changes.
- `CHANGELOG.md` records the v0.1.0 MVP capability set.
- `docs/RELEASE_CHECKLIST.md` separates completed automated checks from the two
  environment-dependent acceptance checks.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request. The backend is
tested on the minimum supported Python 3.12 and the current Python 3.14,
frontend dependencies are installed from the frozen pnpm lockfile before tests
and a production build, and a final dependent job validates the Compose model
and builds both application images. Workflow permissions are read-only.

`.github/workflows/security.yml` runs weekly and on manual dispatch. It audits
the installed locked Python environment with a pinned `pip-audit` release and
audits frontend production dependencies through pnpm. The workflow has the same
read-only repository permission and does not receive application secrets.
