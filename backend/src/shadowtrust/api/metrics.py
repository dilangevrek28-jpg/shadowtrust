"""Protected Prometheus scrape endpoint."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from shadowtrust.api.dependencies import get_metrics_registry, require_metrics_access
from shadowtrust.observability import MetricsRegistry


metrics_router = APIRouter(tags=["operations"])


@metrics_router.get("/metrics", response_class=PlainTextResponse)
def metrics(
    registry: Annotated[MetricsRegistry, Depends(get_metrics_registry)],
    _access: Annotated[None, Depends(require_metrics_access)],
) -> PlainTextResponse:
    return PlainTextResponse(
        registry.render(),
        media_type="text/plain; version=0.0.4",
    )
