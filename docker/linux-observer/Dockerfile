FROM debian:stable-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      file \
      strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
