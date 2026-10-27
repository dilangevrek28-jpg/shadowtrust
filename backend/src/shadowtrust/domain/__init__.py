"""Framework-independent domain models used by ShadowTrust."""

from shadowtrust.domain.baselines import UserBaseline
from shadowtrust.domain.cases import AnalystCase, CaseAuditEntry, CaseStatus
from shadowtrust.domain.decisions import DetectionDecision, RuleEvaluation
from shadowtrust.domain.events import SecurityEvent, parse_security_event

__all__ = [
    "DetectionDecision",
    "AnalystCase",
    "CaseAuditEntry",
    "CaseStatus",
    "RuleEvaluation",
    "SecurityEvent",
    "UserBaseline",
    "parse_security_event",
]
