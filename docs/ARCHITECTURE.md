# ShadowTrust architecture

ShadowTrust is a deterministic, explainable account-takeover detection system.
It accepts canonical banking security events, reconstructs recent user and
session context, evaluates versioned rules, stores auditable decisions, and
presents prioritized investigations to an analyst.

## System context

```text
Event producer
    |
    | POST /api/v1/events + X-API-Key
    v
FastAPI ingestion boundary
    |
    v
Application ingestion service
    |-------------------------------|
    v                               v
PostgreSQL repositories       Detection engine
    |                               |
    | event history + baseline      | versioned rule evaluations
    |                               |
    |<------------------------------|
    |
    v
Stored decision + event result
    |
    | protected analyst API
    v
React analyst console
    |
    | open/transition case, replay decision
    v
Append-only case audit and replay result

API metrics --> Prometheus --> Grafana
```

## Component boundaries

### Domain

The domain layer defines canonical events, risk levels, recommended actions,
rule evaluations, decisions, baselines, session context, and analyst case
states. These objects express business meaning without depending on FastAPI,
SQLAlchemy, React, or a particular database.

### Detection engine

The engine evaluates every active rule against the current event and its
historical context. Each rule returns a bounded score delta, a human-readable
reason, and evidence event identifiers. The engine combines signal,
contradiction, and recovery effects, clamps the risk score to its valid range,
derives a risk level, and selects adaptive response actions.

Rules and the engine carry explicit versions. Stored decisions retain those
versions so a later replay can distinguish an exact reproduction from semantic
drift or an incompatible implementation.

### Application services

Application services coordinate use cases rather than HTTP details. Ingestion
validates idempotency and event ordering, loads historical state, calls the
engine, and atomically persists the event and decision. Replay reconstructs the
recorded decision inputs without inserting a new operational decision. Case
services enforce the workflow, append audit entries, and use an expected
version to prevent concurrent analysts from silently overwriting each other.

### Persistence

Repository interfaces isolate application logic from storage. SQLAlchemy
implementations support SQLite for local tests and PostgreSQL for the deployed
stack. Alembic owns schema evolution. Unique event identifiers enforce
idempotency at the database boundary as well as in application behavior.

### HTTP API

FastAPI routes expose ingestion, analyst reads, case mutations, replay, health,
and metrics. Strict request models reject unknown fields. Role-specific API
keys separate producers, analysts, and monitoring. Body limits, rate limiting,
request correlation, structured errors, and security headers form the HTTP
safety boundary.

### Analyst console

The React application shows a paginated risk queue and loads decision detail,
timeline evidence, replay state, and case state for the selected session. The
connected mode calls the protected API; the clearly labelled demo mode runs on
synthetic in-browser data. Case transitions include the displayed case version
and recover from optimistic-lock conflicts by loading the newest server state.

### Operations

Docker Compose starts PostgreSQL, runs a one-shot migration, starts the API only
after migration success, and exposes the system through a non-root Nginx web
gateway. PostgreSQL, the API, and Prometheus remain internal. Prometheus scrapes
the protected metrics endpoint and evaluates starter security alerts. Grafana
loads an immutable dashboard from version-controlled provisioning files.

## Event-to-decision sequence

1. A producer sends a versioned canonical event with an ingestion key.
2. The API authenticates the producer, applies request controls, and creates a
   correlation context.
3. The ingestion service checks whether the event identifier already exists.
4. For a new event, repositories load the relevant user baseline, prior risk,
   session events, and recent user events.
5. The engine evaluates every active rule and records both matches and
   non-matches.
6. Score deltas are combined and bounded; risk level and response actions are
   derived deterministically.
7. Event and decision state are committed atomically. A repeated event returns
   the stored result rather than creating a second decision.
8. Operational counters are updated without high-cardinality or sensitive
   labels.
9. The analyst queue exposes the latest risky session snapshot. Selecting a row
   retrieves the full decision trace and session timeline.

## Case-management sequence

1. An analyst authenticates with an analyst key and supplies an analyst ID for
   mutations.
2. A risky session can be promoted into a case with an optional opening note.
3. Later transitions must follow the case state machine and include a decision
   note.
4. Every mutation appends an audit record containing the actor, previous state,
   next state, sequence, note, and timestamp.
5. The client sends `expected_version`. A stale writer receives a structured
   conflict instead of overwriting a newer decision.

## Decision-replay sequence

1. The analyst requests replay for a stored decision.
2. The replay service loads the trigger event, historical event window,
   recorded baseline, prior risk, engine version, and rule versions.
3. Compatible rule implementations execute against the reconstructed context.
4. The replayed score, evaluations, explanation, and actions are compared with
   the original decision.
5. The result is classified as `reproduced`, `drifted`, or `incompatible`.
6. Replay remains read-only and does not create a new operational decision.

## Core guarantees

- The same compatible input and versions produce the same decision.
- Every matched contribution includes a reason and evidence identifiers.
- Duplicate event delivery does not duplicate operational decisions.
- Event and decision persistence is atomic.
- Risk remains inside its defined bounds.
- Case history is append-only and concurrent writes cannot silently overwrite.
- Secrets and raw sensitive fields are excluded from logs and metric labels.
- Production services run as non-root users and internal services are not
  unnecessarily published to the host.

## Deliberate limitations

The current detector is evaluated on a small synthetic corpus and does not
claim production banking accuracy. API keys and process-local rate limiting are
appropriate to this MVP boundary, not a substitute for OIDC, RBAC, distributed
rate limiting, or a managed secrets platform. Prometheus evaluates alerts, but
an Alertmanager integration is still required for external paging. See
`EVALUATION.md` and `SECURITY.md` for the explicit evidence and trust boundary.
