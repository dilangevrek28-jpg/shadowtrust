"""SQLite/PostgreSQL-compatible persistence adapters for ShadowTrust."""

from shadowtrust.persistence.database import (
    Base,
    build_session_factory,
    create_database_engine,
    create_schema,
    transactional_session,
)
from shadowtrust.persistence.repositories import (
    AnalystCaseRepository,
    ConcurrentCaseUpdateError,
    DetectionDecisionRepository,
    SecurityEventRepository,
    UserBaselineRepository,
)

__all__ = [
    "Base",
    "AnalystCaseRepository",
    "ConcurrentCaseUpdateError",
    "DetectionDecisionRepository",
    "SecurityEventRepository",
    "UserBaselineRepository",
    "build_session_factory",
    "create_database_engine",
    "create_schema",
    "transactional_session",
]
