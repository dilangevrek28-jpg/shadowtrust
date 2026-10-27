FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN python -m venv /opt/shadowtrust-venv
ENV PATH="/opt/shadowtrust-venv/bin:${PATH}"

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install .


FROM python:3.12-slim AS runtime

ENV PATH="/opt/shadowtrust-venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 shadowtrust \
    && useradd --uid 10001 --gid shadowtrust --create-home \
        --shell /usr/sbin/nologin shadowtrust

WORKDIR /app
COPY --from=builder /opt/shadowtrust-venv /opt/shadowtrust-venv
COPY alembic.ini ./alembic.ini
COPY migrations ./migrations

USER shadowtrust
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"]

CMD ["shadowtrust-api"]
