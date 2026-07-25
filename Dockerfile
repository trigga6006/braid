# syntax=docker/dockerfile:1.7
FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY . .
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    BRAID_HOME=/data/runtime

RUN groupadd --gid 10001 braid \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin braid \
    && mkdir -p /data \
    && chown 10001:10001 /data
COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/*.whl \
    && rm -rf /wheels

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8787
ENTRYPOINT ["braid-hub", "--data-dir", "/data"]
CMD ["serve", "--bind", "0.0.0.0", "--port", "8787", "--allow-insecure-http"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3))['status']=='ok'"]
