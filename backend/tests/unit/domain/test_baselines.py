from uuid import UUID

import pytest
from pydantic import ValidationError

from shadowtrust.domain.baselines import UserBaseline


USER_ID = UUID("232dd896-4bfa-4b90-86cf-11ce7c9bd742")
DEVICE_ID = UUID("7bd829e0-0d04-496b-b621-9a08cb00b404")


def test_baseline_normalizes_countries_and_is_immutable() -> None:
    baseline = UserBaseline(
        user_id=USER_ID,
        version="baseline-7",
        generated_at="2026-10-24T08:00:00+03:00",
        sample_size=42,
        known_device_ids={DEVICE_ID},
        known_countries={"tr", "de"},
    )

    assert baseline.known_countries == frozenset({"TR", "DE"})
    assert baseline.known_device_ids == frozenset({DEVICE_ID})
    with pytest.raises(ValidationError, match="Instance is frozen"):
        baseline.sample_size = 43  # type: ignore[misc]


def test_baseline_rejects_timestamp_without_timezone() -> None:
    with pytest.raises(ValidationError, match="timezone offset"):
        UserBaseline(
            user_id=USER_ID,
            version="baseline-7",
            generated_at="2026-10-24T08:00:00",
            sample_size=0,
        )


def test_baseline_rejects_invalid_country_code() -> None:
    with pytest.raises(ValidationError):
        UserBaseline(
            user_id=USER_ID,
            version="baseline-7",
            generated_at="2026-10-24T08:00:00+03:00",
            sample_size=1,
            known_countries={"TUR"},
        )
