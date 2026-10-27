"""API-key authentication and in-memory fixed-window rate limiting."""

from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from threading import Lock
from time import monotonic


class MissingApiKeyError(PermissionError):
    """Raised when authentication is enabled but no API key was supplied."""


class InvalidApiKeyError(PermissionError):
    """Raised when a supplied API key does not match an allowed digest."""


@dataclass(frozen=True, slots=True)
class RateLimitExceededError(RuntimeError):
    retry_after_seconds: int


@dataclass(frozen=True, slots=True)
class AccessDecision:
    identity: str
    limit: int
    remaining: int
    retry_after_seconds: int


@dataclass(slots=True)
class _RateBucket:
    started_at: float
    request_count: int


class FixedWindowRateLimiter:
    """Thread-safe per-identity request counter for one application process."""

    def __init__(
        self,
        request_limit: int,
        window_seconds: int,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if request_limit < 1:
            raise ValueError("request_limit must be positive")
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        self._request_limit = request_limit
        self._window_seconds = window_seconds
        self._clock = clock
        self._buckets: dict[str, _RateBucket] = {}
        self._lock = Lock()

    def check(self, identity: str) -> AccessDecision:
        now = self._clock()
        with self._lock:
            self._remove_expired_buckets(now)
            bucket = self._buckets.get(identity)
            if bucket is None:
                bucket = _RateBucket(started_at=now, request_count=0)
                self._buckets[identity] = bucket

            elapsed = now - bucket.started_at
            retry_after = max(1, math.ceil(self._window_seconds - elapsed))
            if bucket.request_count >= self._request_limit:
                raise RateLimitExceededError(retry_after)

            bucket.request_count += 1
            return AccessDecision(
                identity=identity,
                limit=self._request_limit,
                remaining=self._request_limit - bucket.request_count,
                retry_after_seconds=retry_after,
            )

    def _remove_expired_buckets(self, now: float) -> None:
        expired = [
            identity
            for identity, bucket in self._buckets.items()
            if now - bucket.started_at >= self._window_seconds
        ]
        for identity in expired:
            del self._buckets[identity]


class ApiKeyAccessController:
    """Authenticate an API client and apply its request budget."""

    def __init__(
        self,
        api_keys: Sequence[str],
        *,
        request_limit: int,
        window_seconds: int,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._allowed_key_digests = tuple(self._digest(key) for key in api_keys)
        self._rate_limiter = FixedWindowRateLimiter(
            request_limit,
            window_seconds,
            clock=clock,
        )

    @property
    def authentication_enabled(self) -> bool:
        return bool(self._allowed_key_digests)

    def authorize(
        self,
        api_key: str | None,
        *,
        anonymous_identity: str,
    ) -> AccessDecision:
        if not self.authentication_enabled:
            identity = f"anonymous:{anonymous_identity}"
            return self._rate_limiter.check(identity)

        if api_key is None:
            raise MissingApiKeyError

        candidate_digest = self._digest(api_key)
        matches = tuple(
            hmac.compare_digest(candidate_digest, allowed_digest)
            for allowed_digest in self._allowed_key_digests
        )
        if not any(matches):
            raise InvalidApiKeyError

        identity = f"api_key:{candidate_digest.hex()[:16]}"
        return self._rate_limiter.check(identity)

    @staticmethod
    def _digest(api_key: str) -> bytes:
        return hashlib.sha256(api_key.encode("utf-8")).digest()
