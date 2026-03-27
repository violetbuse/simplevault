# Build stage
# Version is passed as build-arg from build-all.sh (reads VERSION file)
ARG SIMPLEVAULT_VERSION=0.1.0
FROM rust:1.85-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main to cache dependencies (Cargo.lock may not exist yet)
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only
RUN cargo build --release 2>/dev/null || true

# Remove dummy and copy actual source
RUN rm -rf src
COPY src ./src

# Build the actual binary (reuse cached deps if unchanged), strip to reduce size
RUN touch src/main.rs && cargo build --release && \
    strip /app/target/release/simplevault

# Runtime stage - minimal debian-slim
FROM debian:bookworm-slim
ARG SIMPLEVAULT_VERSION=0.1.0
LABEL org.opencontainers.image.version="${SIMPLEVAULT_VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    acl \
    bash \
    ca-certificates \
    jq \
    libsodium23 \
    netcat-openbsd \
    passwd \
    util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app

WORKDIR /app

COPY --from=builder /app/target/release/simplevault /app/simplevault
COPY docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chown root:root /app/simplevault /usr/local/bin/docker-entrypoint.sh && \
    chmod 0111 /app/simplevault && \
    chmod 0500 /usr/local/bin/docker-entrypoint.sh && \
    chmod 0711 /app

# Config must be provided via --config-env (JSON or base64-encoded JSON) or a mounted config file
# Example: docker run -e SIMPLEVAULT_CONFIG="<json-or-base64>" simplevault --config-env SIMPLEVAULT_CONFIG
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--config-env", "SIMPLEVAULT_CONFIG"]
