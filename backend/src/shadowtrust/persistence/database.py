"""SQLAlchemy engine, schema, and session construction."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine as sqlalchemy_create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Declarative base shared by every ShadowTrust persistence model."""


def create_database_engine(
    url: str = "sqlite+pysqlite:///:memory:",
    *,
    echo: bool = False,
) -> Engine:
    """Create an engine with SQLite foreign-key enforcement enabled."""

    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine_options: dict[str, object] = {"connect_args": connect_args}
    if url in {"sqlite://", "sqlite+pysqlite:///:memory:"}:
        engine_options["poolclass"] = StaticPool
    engine = sqlalchemy_create_engine(url, echo=echo, **engine_options)

    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def create_schema(engine: Engine) -> None:
    """Create tables for tests and local bootstrap; deployments use Alembic."""

    from shadowtrust.persistence import models  # noqa: F401

    Base.metadata.create_all(engine)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def transactional_session(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Commit a unit of work or roll it back on any exception."""

    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
