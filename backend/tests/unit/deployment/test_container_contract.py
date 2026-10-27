import json
from importlib.util import find_spec
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[3]
PROJECT_ROOT = BACKEND_ROOT.parent


def test_postgresql_driver_is_installed() -> None:
    assert find_spec("psycopg") is not None


def test_runtime_image_uses_non_root_user_and_healthcheck() -> None:
    dockerfile = (BACKEND_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "USER shadowtrust" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert 'CMD ["shadowtrust-api"]' in dockerfile
    assert 'CMD ["alembic", "upgrade", "head"]' not in dockerfile


def test_compose_runs_migration_before_api_and_does_not_publish_postgres() -> None:
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    postgres_section, remainder = compose.split("  migrate:", maxsplit=1)
    migrate_section, api_section = remainder.split("  api:", maxsplit=1)

    assert "ports:" not in postgres_section
    assert 'command: ["alembic", "upgrade", "head"]' in migrate_section
    assert "condition: service_healthy" in migrate_section
    assert "condition: service_completed_successfully" in api_section
    assert "SHADOWTRUST_ENVIRONMENT: production" in api_section
    assert "SHADOWTRUST_INGESTION_API_KEYS:?" in api_section
    assert "SHADOWTRUST_ANALYST_API_KEYS:?" in api_section
    assert "SHADOWTRUST_METRICS_API_KEYS:?" in api_section


def test_docker_context_excludes_local_state_and_tests() -> None:
    dockerignore = (BACKEND_ROOT / ".dockerignore").read_text(encoding="utf-8")

    for excluded_path in (".venv", ".pytest_cache", "tests", "*.db"):
        assert excluded_path in dockerignore


def test_example_environment_does_not_ship_working_secrets() -> None:
    example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")

    assert "SHADOWTRUST_POSTGRES_PASSWORD=\n" in example
    assert "SHADOWTRUST_INGESTION_API_KEYS=\n" in example
    assert "SHADOWTRUST_ANALYST_API_KEYS=\n" in example
    assert "SHADOWTRUST_METRICS_API_KEYS=\n" in example
    assert "SHADOWTRUST_PROMETHEUS_API_KEY=\n" in example
    assert "SHADOWTRUST_GRAFANA_ADMIN_PASSWORD=\n" in example


def test_frontend_runtime_is_non_root_and_proxies_only_to_internal_api() -> None:
    frontend_root = PROJECT_ROOT / "frontend"
    dockerfile = (frontend_root / "Dockerfile").read_text(encoding="utf-8")
    nginx = (frontend_root / "nginx.conf").read_text(encoding="utf-8")

    assert "pnpm install --frozen-lockfile" in dockerfile
    assert "USER nginx" in dockerfile
    assert "EXPOSE 8080" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "proxy_pass http://api:8000" in nginx
    assert "location = /metrics" not in nginx
    assert "try_files $uri $uri/ /index.html" in nginx
    assert "Content-Security-Policy" in nginx
    assert "server_tokens off" in nginx


def test_compose_exposes_only_web_and_loopback_grafana() -> None:
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    api_section, prometheus_remainder = compose.split("  prometheus:", maxsplit=1)
    prometheus_section, grafana_remainder = prometheus_remainder.split(
        "  grafana:", maxsplit=1
    )
    grafana_section, web_section = grafana_remainder.split("  web:", maxsplit=1)
    api_service = api_section.split("  api:", maxsplit=1)[1]

    assert "    ports:" not in api_service
    assert '      - "8000"' in api_service
    assert "    ports:" not in prometheus_section
    assert '      - "9090"' in prometheus_section
    assert '127.0.0.1:${SHADOWTRUST_GRAFANA_PORT:-3000}:3000' in grafana_section
    assert '      - "${SHADOWTRUST_WEB_PORT:-8080}:8080"' in web_section
    assert "condition: service_healthy" in web_section


def test_monitoring_services_use_pinned_images_and_scoped_secrets() -> None:
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")
    prometheus_section = compose.split("  prometheus:", maxsplit=1)[1].split(
        "  grafana:", maxsplit=1
    )[0]
    grafana_section = compose.split("  grafana:", maxsplit=1)[1].split(
        "  web:", maxsplit=1
    )[0]

    assert "prom/prometheus:v3.13.5" in prometheus_section
    assert "shadowtrust_prometheus_api_key" in prometheus_section
    assert "shadowtrust_grafana_admin_password" not in prometheus_section
    assert "grafana/grafana:13.2.1" in grafana_section
    assert "GF_AUTH_ANONYMOUS_ENABLED: \"false\"" in grafana_section
    assert "GF_SECURITY_ADMIN_PASSWORD__FILE" in grafana_section
    assert "shadowtrust_grafana_admin_password" in grafana_section
    assert "shadowtrust_prometheus_api_key" not in grafana_section


def test_prometheus_scrapes_internal_metrics_with_secret_header_and_loads_rules() -> None:
    config = (PROJECT_ROOT / "monitoring" / "prometheus" / "prometheus.yml").read_text(
        encoding="utf-8"
    )
    rules = (
        PROJECT_ROOT
        / "monitoring"
        / "prometheus"
        / "rules"
        / "shadowtrust-alerts.yml"
    ).read_text(encoding="utf-8")

    assert "api:8000" in config
    assert "X-Metrics-API-Key:" in config
    assert "/run/secrets/shadowtrust_prometheus_api_key" in config
    assert "/etc/prometheus/rules/*.yml" in config
    for alert in (
        "ShadowTrustMetricsTargetDown",
        "ShadowTrustCriticalDecisionBurst",
        "ShadowTrustConfirmedTakeoverBurst",
        "ShadowTrustEventReplaySpike",
        "ShadowTrustDecisionReplayMismatch",
    ):
        assert f"alert: {alert}" in rules


def test_grafana_dashboard_is_valid_json_and_uses_provisioned_prometheus() -> None:
    monitoring_root = PROJECT_ROOT / "monitoring" / "grafana"
    datasource = (
        monitoring_root / "provisioning" / "datasources" / "prometheus.yml"
    ).read_text(encoding="utf-8")
    provider = (
        monitoring_root / "provisioning" / "dashboards" / "shadowtrust.yml"
    ).read_text(encoding="utf-8")
    dashboard = json.loads(
        (monitoring_root / "dashboards" / "shadowtrust-overview.json").read_text(
            encoding="utf-8"
        )
    )

    assert "uid: shadowtrust-prometheus" in datasource
    assert "url: http://prometheus:9090" in datasource
    assert "path: /etc/grafana/dashboards" in provider
    assert dashboard["uid"] == "shadowtrust-security-operations"
    assert dashboard["editable"] is False
    assert len(dashboard["panels"]) == 6
    assert all(
        panel["datasource"]["uid"] == "shadowtrust-prometheus"
        for panel in dashboard["panels"]
    )


def test_frontend_docker_context_excludes_generated_state() -> None:
    dockerignore = (PROJECT_ROOT / "frontend" / ".dockerignore").read_text(
        encoding="utf-8"
    )

    for excluded_path in ("node_modules", "dist", ".vite", "*.log"):
        assert excluded_path in dockerignore


def test_ci_runs_cross_version_backend_frontend_and_container_checks() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "permissions:\n  contents: read" in workflow
    assert 'python-version: ["3.12", "3.14"]' in workflow
    assert "uv sync --frozen --all-groups" in workflow
    assert "uv run pytest -q" in workflow
    assert "uv run shadowtrust-evaluate" in workflow
    assert "--minimum-recall 1.0" in workflow
    assert "pnpm install --frozen-lockfile" in workflow
    assert "pnpm test" in workflow
    assert "pnpm build" in workflow
    assert "docker compose config --quiet" in workflow
    assert "docker compose build api web" in workflow
    assert "needs: [backend, frontend]" in workflow


def test_scheduled_security_workflow_audits_both_dependency_trees() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "security.yml"
    ).read_text(encoding="utf-8")

    assert "schedule:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "pip-audit==2.10.1" in workflow
    assert "--local --skip-editable" in workflow
    assert "pnpm audit --prod --audit-level=moderate" in workflow
    assert "pnpm install --frozen-lockfile" in workflow
