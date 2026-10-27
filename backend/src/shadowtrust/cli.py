"""Console entry point for running the ShadowTrust API."""

import uvicorn

from shadowtrust.bootstrap import build_application
from shadowtrust.settings import RuntimeSettings


def run() -> None:
    settings = RuntimeSettings.from_environment()
    app = build_application(settings)
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level,
        access_log=False,
    )
