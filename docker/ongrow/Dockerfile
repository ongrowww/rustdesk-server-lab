FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

ARG SOURCE_REVISION

LABEL org.opencontainers.image.title="OnGROW RustDesk Server"
LABEL org.opencontainers.image.description="RustDesk Server OSS with signed OnGROW custom IDs"
LABEL org.opencontainers.image.source="https://github.com/ongrowww/rustdesk-server-lab"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="1.1.16-ongrow.1"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY target/release/hbbs /usr/local/bin/hbbs
COPY target/release/hbbr /usr/local/bin/hbbr

WORKDIR /root
