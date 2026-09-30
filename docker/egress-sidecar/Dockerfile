FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nftables=1.0.6-2+deb12u2 \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["nft"]
