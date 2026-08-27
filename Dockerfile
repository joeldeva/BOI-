FROM python:3.12-slim-bookworm AS builder

ENV BUILD_VIRTUAL_ENV=/opt/fraudshield-build-venv \
    VIRTUAL_ENV=/opt/fraudshield-venv \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$BUILD_VIRTUAL_ENV" \
    && python -m venv "$VIRTUAL_ENV"

COPY requirements-build.lock ./
RUN "$BUILD_VIRTUAL_ENV/bin/python" -m pip install --require-hashes -r requirements-build.lock

COPY pyproject.toml README.md LICENSE ./
COPY fraudshield ./fraudshield

RUN "$BUILD_VIRTUAL_ENV/bin/python" -m build --wheel --no-isolation --outdir /build/dist \
    && "$VIRTUAL_ENV/bin/python" -m pip install --upgrade "pip>=25.0" "setuptools>=78.1.1" wheel \
    && "$VIRTUAL_ENV/bin/python" -m pip install --no-cache-dir $(ls /build/dist/fraudshield_backend-*.whl)[production,analysis] "msgpack>=1.2.1"



FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="FraudShield Backend" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.description="Multi-engine defensive Android APK intelligence API and worker"

ENV VIRTUAL_ENV=/opt/fraudshield-venv \
    PATH=/opt/fraudshield-venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FRAUDSHIELD_ENV=production \
    FRAUDSHIELD_DATA_DIR=/var/lib/fraudshield \
    FRAUDSHIELD_APKSIGNER_PATH=/usr/bin/apksigner

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends apksigner curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 fraudshield \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin fraudshield \
    && mkdir -p /var/lib/fraudshield /tmp/fraudshield \
    && chown -R 10001:10001 /var/lib/fraudshield /tmp/fraudshield

COPY --from=builder /opt/fraudshield-venv /opt/fraudshield-venv

WORKDIR /app
USER 10001:10001
EXPOSE 8000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)" || exit 1

CMD ["fraudshield", "serve", "--host", "0.0.0.0", "--port", "8000"]

