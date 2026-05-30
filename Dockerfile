# SPDX-License-Identifier: MIT
# syntax=docker/dockerfile:1.7

# -----------------------------------------------------------------------------
# Build stage: compile vaa from source.
# -----------------------------------------------------------------------------
FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY . .

# Drop any user-specific .cargo overrides that may have shipped in the COPY.
RUN rm -rf .cargo

RUN cargo build -p vaa-cli --release --locked

# -----------------------------------------------------------------------------
# Runtime stage: thin Debian image with the vaa binary as entrypoint.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 vaa

COPY --from=builder /src/target/release/vaa /usr/local/bin/vaa

# Bring the deterministic vectors and the example data into the image so
# `vaa reproduce` and the sample bundle verification work out of the box.
COPY --from=builder /src/vectors  /opt/vaa/vectors
COPY --from=builder /src/examples /opt/vaa/examples

WORKDIR /opt/vaa
USER vaa

ENTRYPOINT ["vaa"]
CMD ["selftest"]
