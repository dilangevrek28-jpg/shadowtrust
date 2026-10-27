# ShadowTrust Analyst Console

This React application is the analyst-facing view of ShadowTrust. It reads the
protected analyst API, shows the latest risk snapshot for each session, and
keeps every score explainable through rule evaluations and the session timeline.

## Local development

Start the backend on `127.0.0.1:8000`, then run:

```powershell
pnpm install
pnpm dev
```

Open `http://127.0.0.1:5173`. Vite proxies `/api` and `/health` to the backend,
so the browser uses a same-origin path during local development.

Enter a value configured in `SHADOWTRUST_ANALYST_API_KEYS`. The key is kept in
`sessionStorage`, which means it belongs only to the current browser tab/session
and is removed when the analyst leaves the workspace. It is not persisted in
`localStorage`.

The explicitly labelled synthetic demo workspace can be used when no backend is
running. Demo data never leaves the browser and is never sent to the API.

## Analyst case workflow

Connected analysts provide both an API key and an analyst ID. The key authorizes
requests; the ID is sent only on case mutations and becomes the audit actor.
Both values are kept in `sessionStorage`.

For a selected risky session, the investigation panel can open a case, apply a
valid next status with a required decision note, and display the newest audit
entry first. Every transition sends the displayed case version as
`expected_version`. If another browser changes the case first, the API returns a
version conflict and the console reloads the newest case instead of overwriting
it.

Demo mode implements the same interaction locally so the workflow can be
inspected without writing to the API.

The queue exposes case-state tabs with backend-calculated counts. Each row shows
its current case state, and analysts can isolate unassigned, open,
investigating, confirmed, false-positive, or closed sessions without changing
the active risk filters.

## Decision replay

The investigation panel can replay the selected decision without changing its
case or inserting a new decision. A reproduced result proves that the recorded
event history, baseline version, risk input, engine version, and rule versions
still produce the same rule trace, explanation, score, and response actions.
The UI distinctly reports semantic drift and version incompatibility so an
analyst cannot mistake a best-effort rerun for forensic reproducibility.

## Verification

```powershell
pnpm typecheck
pnpm test
pnpm build
```

Set `VITE_API_BASE_URL` only when the API is hosted at a different origin. In
that case the backend or reverse proxy must also apply the intended CORS policy.

## Production container

The production image builds the static Vite bundle and serves it from a
non-root Nginx process on port `8080`. Nginx proxies `/api` and `/health` to the
internal Compose service named `api`, so the browser and API share one origin.

From the project root, copy `.env.example` to `.env`, provide the PostgreSQL
password, ingestion/analyst/metrics keys, Prometheus scrape key, and Grafana
administrator password, then run `docker compose up --build`. Open
`http://127.0.0.1:8080`; only this gateway is published to the host.
