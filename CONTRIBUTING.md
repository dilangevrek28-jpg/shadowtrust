# Contributing to ShadowTrust

ShadowTrust favors explainable, deterministic security behavior over opaque
complexity. Contributions must remain usable with completely synthetic data.

## Required checks

Backend changes:

```powershell
cd backend
uv sync --all-groups
uv run pytest -q
```

Frontend changes:

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm test
pnpm build
```

## Detection-rule changes

A rule change must:

1. Keep a stable uppercase rule code.
2. Increment the rule version when behavior changes.
3. Produce a bounded score delta and a human-readable reason.
4. Reference evidence event IDs only when matched.
5. Add positive, negative, and sequence-boundary tests.
6. Run the independent evaluation split and review false positives, recall,
   detection latency, and unnecessary step-up actions.

Never tune a rule against the evaluation split and then describe that split as
unseen holdout evidence. Add a new holdout variant instead.

## Persistence and API changes

- Schema changes require an Alembic migration and migration tests.
- Public request and response models stay strict (`extra="forbid"`).
- Mutations must remain atomic and return structured errors.
- Logs and metrics must not include credentials, raw IP addresses, transfer
  amounts, free-form analyst notes, or unbounded identifier labels.
- Update component documentation when behavior or configuration changes.
