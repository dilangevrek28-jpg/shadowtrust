from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


BACKEND_ROOT = Path(__file__).resolve().parents[3]


def alembic_config(database_path: Path) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_initial_migration_upgrades_an_empty_database(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-test.sqlite"
    config = alembic_config(database_path)

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database_path.as_posix()}")
    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {
        "alembic_version",
        "analyst_cases",
        "case_audit_entries",
        "detection_decisions",
        "rule_evaluations",
        "security_events",
        "user_baselines",
    }
    assert {column["name"] for column in inspector.get_columns("security_events")} >= {
        "id",
        "session_id",
        "event_type",
        "document",
    }
    foreign_keys = inspector.get_foreign_keys("detection_decisions")
    assert foreign_keys[0]["referred_table"] == "security_events"
    case_foreign_keys = inspector.get_foreign_keys("case_audit_entries")
    assert case_foreign_keys[0]["referred_table"] == "analyst_cases"
    assert case_foreign_keys[0]["options"].get("ondelete") == "RESTRICT"
    case_checks = {
        item["name"] for item in inspector.get_check_constraints("analyst_cases")
    }
    assert "ck_analyst_cases_status" in case_checks
    assert "ck_analyst_cases_version_positive" in case_checks
    engine.dispose()


def test_initial_migration_can_downgrade_to_base(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-downgrade.sqlite"
    config = alembic_config(database_path)

    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = create_engine(f"sqlite+pysqlite:///{database_path.as_posix()}")
    remaining_tables = set(inspect(engine).get_table_names())
    assert remaining_tables <= {"alembic_version"}
    engine.dispose()


def test_environment_database_url_overrides_alembic_ini(
    tmp_path: Path,
    monkeypatch,
) -> None:
    configured_path = tmp_path / "configured.sqlite"
    environment_path = tmp_path / "environment.sqlite"
    config = alembic_config(configured_path)
    environment_url = f"sqlite+pysqlite:///{environment_path.as_posix()}"
    monkeypatch.setenv("SHADOWTRUST_DATABASE_URL", environment_url)

    command.upgrade(config, "head")

    environment_engine = create_engine(environment_url)
    assert "security_events" in inspect(environment_engine).get_table_names()
    assert not configured_path.exists()
    environment_engine.dispose()
