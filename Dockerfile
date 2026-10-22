# Base images are pinned to exact versions; pin them by digest (`image@sha256:...`) too for
# fully reproducible builds.

# web UI
FROM node:22.23.2-alpine3.24 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# registry
FROM rust:1.95.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock LICENSE ./
COPY crates ./crates
COPY --from=web /web/dist ./web/dist
RUN cargo build --release --locked

# runtime
FROM debian:bookworm-20260918-slim
# tini: PID 1 that forwards SIGTERM to kontainer and reaps the processes builds and scans leave.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git tini postgresql-client \
    && rm -rf /var/lib/apt/lists/*
# Builds from Git (`builds.backend = "buildctl"`) talk to a separate buildkitd.
COPY --from=moby/buildkit:v0.17.3 /usr/bin/buildctl /usr/local/bin/buildctl
# trivy for scanning: a pinned release, checked against the checksums below (from the release's
# trivy_<version>_checksums.txt). Changing the version means changing them too; an empty
# TRIVY_VERSION leaves trivy out. Any failure fails the build.
ARG TARGETARCH
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
RUN set -eu; \
    if [ -z "${TRIVY_VERSION}" ]; then echo "trivy left out"; exit 0; fi; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=64bit; sum="${TRIVY_SHA256_AMD64}" ;; \
      arm64) arch=ARM64; sum="${TRIVY_SHA256_ARM64}" ;; \
      *) echo "no trivy checksum for ${TARGETARCH}; build with --build-arg TRIVY_VERSION=" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"; \
    echo "${sum}  /tmp/trivy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz; \
    trivy --version
COPY --from=build /src/target/release/kontainer /usr/local/bin/kontainer
COPY config.example.toml /etc/kontainer/config.toml
# Runs unprivileged; the data directory (a volume) is its home, so scanner caches land there too.
RUN useradd --system --uid 1000 --user-group --home-dir /var/lib/registry kontainer \
    && mkdir -p /var/lib/registry && chown kontainer:kontainer /var/lib/registry
ENV KONTAINER_CONFIG=/etc/kontainer/config.toml \
    KONTAINER_STORAGE_ROOT=/var/lib/registry \
    KONTAINER_UPLOAD_DIR=/var/lib/registry/_uploads \
    KONTAINER_AUTH_DATABASE=/var/lib/registry/auth.db
USER 1000:1000
VOLUME /var/lib/registry
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD curl -fsS http://127.0.0.1:5000/readyz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "kontainer"]
CMD ["serve"]
