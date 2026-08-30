# syntax=docker/dockerfile:1.20@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.7@sha256:95f2aa1fe59274951cfe9b0cbc7972e879ff1004bc8945d130a32eb0dbd85945
ARG BASE_IMAGE=ghcr.io/tesserix/base-python-adk-3.14:20260829@sha256:5a6fd1863ed7f37f3929cc596d0ec063c3077c11713cd334f14d1df2b30ef386

FROM ${UV_IMAGE} AS uv

FROM ${BASE_IMAGE} AS build
ARG PACKAGE_VERSION=0.0.1.dev0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${PACKAGE_VERSION} \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
USER root
WORKDIR /build
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY packages/tesserix-mcp-manifest/pyproject.toml packages/tesserix-mcp-manifest/pyproject.toml
COPY packages/tesserix-mcp-publisher/pyproject.toml packages/tesserix-mcp-publisher/pyproject.toml
COPY packages/tesserix-mcp-testkit/pyproject.toml packages/tesserix-mcp-testkit/pyproject.toml
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv build --wheel --package tesserix-mcp-runtime --out-dir /wheels

FROM ${BASE_IMAGE} AS runtime
ARG EXPECTED_ADK_VERSION=v0.53.1
USER root
WORKDIR /app
COPY --from=build /wheels/ /tmp/wheels/
COPY --chown=10001:10001 compatibility/server.py /app/server.py
RUN test "$TESSERIX_ADK_VERSION" = "$EXPECTED_ADK_VERSION" \
 && /opt/adk-venv/bin/python -m pip install --no-cache-dir --no-deps \
      /tmp/wheels/tesserix_mcp_runtime-*.whl \
 && /opt/adk-venv/bin/python -m pip check \
 && /opt/adk-venv/bin/python -m pip uninstall --yes pip \
 && /usr/local/bin/python -m pip uninstall --yes pip \
 && rm -rf /tmp/wheels \
    && rm -f /bin/sh /bin/dash /bin/bash /usr/bin/dash /usr/bin/bash \
    && test ! -e /bin/sh
ENV HOME=/home/app \
    TMPDIR=/tmp
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/adk-venv/bin/python", "/app/server.py"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--allowed-host", "127.0.0.1", "--allowed-origin", "https://gateway.invalid"]
