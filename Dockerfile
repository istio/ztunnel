# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Base image: cc-debian12 provides glibc + libgcc_s + CA certificates.
# Use :nonroot for production, :debug for a busybox shell.
ARG BASE_IMAGE=gcr.io/distroless/cc-debian12:nonroot

FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source="https://github.com/cilium/ztunnel"
LABEL org.opencontainers.image.description="Cilium ztunnel - ambient mesh proxy"

WORKDIR /

ARG TARGETARCH
COPY ${TARGETARCH:-amd64}/ztunnel /usr/local/bin/ztunnel

ENTRYPOINT ["/usr/local/bin/ztunnel"]
