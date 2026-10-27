import pytest

from shadowtrust.api.access_control import (
    ApiKeyAccessController,
    InvalidApiKeyError,
    MissingApiKeyError,
    RateLimitExceededError,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    ("request_limit", "window_seconds"),
    [(0, 60), (10, 0)],
)
def test_rate_limiter_rejects_non_positive_configuration(
    request_limit: int,
    window_seconds: int,
) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        ApiKeyAccessController(
            (),
            request_limit=request_limit,
            window_seconds=window_seconds,
        )


def test_enabled_authentication_rejects_missing_and_invalid_keys() -> None:
    controller = ApiKeyAccessController(
        ("correct-api-key-value",),
        request_limit=10,
        window_seconds=60,
    )

    with pytest.raises(MissingApiKeyError):
        controller.authorize(None, anonymous_identity="client")
    with pytest.raises(InvalidApiKeyError):
        controller.authorize("wrong-api-key-value", anonymous_identity="client")


def test_valid_key_is_represented_by_a_non_secret_fingerprint() -> None:
    raw_key = "correct-api-key-value"
    controller = ApiKeyAccessController(
        (raw_key,),
        request_limit=10,
        window_seconds=60,
    )

    decision = controller.authorize(raw_key, anonymous_identity="client")

    assert decision.identity.startswith("api_key:")
    assert raw_key not in decision.identity
    assert raw_key not in repr(vars(controller))


def test_rate_limit_is_isolated_by_identity_and_resets_after_window() -> None:
    clock = FakeClock()
    controller = ApiKeyAccessController(
        (),
        request_limit=2,
        window_seconds=10,
        clock=clock,
    )

    first = controller.authorize(None, anonymous_identity="client-a")
    second = controller.authorize(None, anonymous_identity="client-a")
    other_client = controller.authorize(None, anonymous_identity="client-b")

    assert first.remaining == 1
    assert second.remaining == 0
    assert other_client.remaining == 1
    with pytest.raises(RateLimitExceededError) as error:
        controller.authorize(None, anonymous_identity="client-a")
    assert error.value.retry_after_seconds == 10

    clock.now += 10
    reset = controller.authorize(None, anonymous_identity="client-a")
    assert reset.remaining == 1
