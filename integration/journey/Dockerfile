# syntax=docker/dockerfile:1.20@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

ARG CORE_IMAGE=scratch
FROM ${CORE_IMAGE}

COPY --chown=10001:10001 integration /app/integration

USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/app/bin/python", "-m"]
CMD ["integration.journey.reference_server"]
