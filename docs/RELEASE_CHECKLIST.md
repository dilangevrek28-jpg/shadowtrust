# ShadowTrust v0.1.0 release checklist

## Completed locally

- [x] Backend unit, integration, API, persistence, migration, security, and
  deployment-contract suite: 202 tests passing.
- [x] Frontend API-client suite: 4 tests passing.
- [x] TypeScript type check and production Vite build.
- [x] Browser QA for queue filters, case workflow, and decision replay.
- [x] Evaluation holdout quality gate and deterministic JSON report.
- [x] Python dependency audit with no known vulnerabilities after upgrading
  pytest to 9.1.1.
- [x] Frontend production dependency audit with no known vulnerabilities.
- [x] Source secret-pattern scan with no matches.

## Environment-dependent acceptance

- [ ] On a machine with Docker, copy `.env.example` to `.env`, set unique
  secrets, run `docker compose up --build`, and verify API readiness,
  Prometheus target health, Grafana provisioning, and web gateway access.
- [ ] Push to the intended GitHub repository and verify `ci.yml` plus
  `security.yml` on GitHub-hosted runners.

These unchecked items validate external tooling and hosting state. They do not
represent missing application code, but the release should not be tagged until
both have been observed successfully.
