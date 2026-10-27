"""ASGI import target for servers that expect ``shadowtrust.main:app``."""

from shadowtrust.bootstrap import build_application


app = build_application()
