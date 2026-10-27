"""Detection orchestration for ShadowTrust."""

from shadowtrust.detection.context import DetectionContext
from shadowtrust.detection.default_engine import build_default_detection_engine
from shadowtrust.detection.engine import DetectionEngine, DetectionRule, actions_for

__all__ = [
    "DetectionContext",
    "DetectionEngine",
    "DetectionRule",
    "actions_for",
    "build_default_detection_engine",
]
