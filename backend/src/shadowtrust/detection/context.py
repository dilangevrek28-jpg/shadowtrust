"""Validated input context passed to every detection rule."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from shadowtrust.domain.baselines import UserBaseline
from shadowtrust.domain.decisions import RiskScore
from shadowtrust.domain.events import SecurityEvent


class DetectionContext(BaseModel):
    """Immutable session context for evaluating one trigger event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trigger_event: SecurityEvent
    prior_events: tuple[SecurityEvent, ...] = ()
    risk_before: RiskScore
    baseline: UserBaseline | None = None
    baseline_version: str | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def validate_event_relationships(self) -> DetectionContext:
        trigger_session_id = self.trigger_event.session_id
        if trigger_session_id is None:
            raise ValueError("trigger event must belong to a session")

        if self.baseline is not None:
            if self.baseline.user_id != self.trigger_event.user_id:
                raise ValueError("baseline must belong to the trigger user")
            if (
                self.baseline_version is not None
                and self.baseline_version != self.baseline.version
            ):
                raise ValueError("baseline version does not match the baseline snapshot")

        seen_ids = {self.trigger_event.id}
        for event in self.prior_events:
            if event.id in seen_ids:
                raise ValueError("detection context cannot contain duplicate event ids")
            seen_ids.add(event.id)

            if event.user_id != self.trigger_event.user_id:
                raise ValueError("all context events must belong to the same user")
            if event.session_id not in (None, trigger_session_id):
                raise ValueError("session-bound context events must share the trigger session")
        return self

    @property
    def decision_baseline_version(self) -> str | None:
        if self.baseline is not None:
            return self.baseline.version
        return self.baseline_version
