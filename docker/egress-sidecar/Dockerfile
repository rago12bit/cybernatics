FROM debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends nftables=1.0.6-2+deb12u2 \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["nft"]
