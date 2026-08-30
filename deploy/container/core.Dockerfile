# syntax=docker/dockerfile:1.20@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.7@sha256:95f2aa1fe59274951cfe9b0cbc7972e879ff1004bc8945d130a32eb0dbd85945
ARG BASE_IMAGE=ghcr.io/tesserix/base-python-runtime-3.14:20260829@sha256:3854f5d9d00705b14077bf6715feb9c3bd6d1ad2e41d5594b3c09c0a74c22add

FROM ${UV_IMAGE} AS uv

FROM ${BASE_IMAGE} AS build
ARG PACKAGE_VERSION=0.0.1.dev0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${PACKAGE_VERSION} \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/app
USER root
WORKDIR /build
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY packages/tesserix-mcp-manifest/pyproject.toml packages/tesserix-mcp-manifest/pyproject.toml
COPY packages/tesserix-mcp-publisher/pyproject.toml packages/tesserix-mcp-publisher/pyproject.toml
COPY packages/tesserix-mcp-testkit/pyproject.toml packages/tesserix-mcp-testkit/pyproject.toml
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --package tesserix-mcp-runtime

FROM ${BASE_IMAGE} AS runtime
USER root
WORKDIR /app
COPY --from=build --chown=10001:10001 /opt/app /opt/app
COPY --chown=10001:10001 compatibility/server.py /app/server.py
RUN /usr/local/bin/python -m pip uninstall --yes pip \
 && rm -f /bin/sh /bin/dash /bin/bash /usr/bin/dash /usr/bin/bash \
 && test ! -e /bin/sh
ENV HOME=/home/app \
    PATH=/opt/app/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TMPDIR=/tmp \
    VIRTUAL_ENV=/opt/app
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/app/bin/python", "/app/server.py"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--allowed-host", "127.0.0.1", "--allowed-origin", "https://gateway.invalid"]
