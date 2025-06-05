FROM playwright_oidc_warden_prebuilt AS prebuilt

FROM node:18-bookworm AS build

ARG REPO_URL
ARG COMMIT_HASH

ENV REPO_URL=${REPO_URL:-https://github.com/Timshel/oidc_web_vault}
ENV COMMIT_HASH=$COMMIT_HASH

COPY --from=prebuilt /web-vault_button /web-vault_button
COPY --from=prebuilt /web-vault_override /web-vault_override

COPY build.sh /build.sh
RUN /build.sh

######################## RUNTIME IMAGE  ########################
FROM docker.io/library/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Create data folder and Install needed libraries
RUN mkdir /data && \
    apt-get update && apt-get install -y \
        --no-install-recommends \
        ca-certificates \
        curl \
        libmariadb-dev-compat \
        libpq5 \
        openssl && \
    rm -rf /var/lib/apt/lists/*

# Copies the files from the context (Rocket.toml file and web-vault)
# and the binary from the "build" stage to the current stage
WORKDIR /

COPY --from=prebuilt /start.sh .
COPY --from=prebuilt /oidcwarden .

COPY --from=build /web-vault_button ./web-vault_button
COPY --from=build /web-vault_override ./web-vault_override

ENTRYPOINT ["/start.sh"]
