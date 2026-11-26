FROM rust:slim-trixie AS chef
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS deps
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json \
      -p kletka_control -p kletka_vm_agent -p kletka_image_builder

FROM deps AS build
ARG KLETKA_VERSION=dev
ENV KLETKA_VERSION=${KLETKA_VERSION}
COPY . .
RUN cargo build --release \
      -p kletka_control --bin kletka-control \
      -p kletka_vm_agent --bin kletka-vm-agent \
      -p kletka_image_builder --bin kletka-image-builder \
 && cp target/release/kletka-control target/release/kletka-vm-agent \
       target/release/kletka-image-builder /usr/local/bin/ \
 && mkdir -p docker/guest-default

FROM debian:trixie-slim AS api
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/kletka-control /usr/local/bin/kletka-control
LABEL org.opencontainers.image.source="https://github.com/kletka-dev/kletka" \
      org.opencontainers.image.description="kletka hosted control plane: REST API + WS relay + web panel (k8s provisioner)" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV HOME=/var/lib/kletka
WORKDIR /var/lib/kletka
USER 65532:65532
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/kletka-control"]

FROM debian:trixie-slim AS vm-agent
ARG FIRECRACKER_VERSION=v1.18.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash python3 iproute2 slirp4netns openssh-client e2fsprogs \
      util-linux coreutils tini curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) fc_arch=x86_64 ;; \
      arm64) fc_arch=aarch64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/firecracker.tgz \
      "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${fc_arch}.tgz" \
 && tar --no-same-owner -xzf /tmp/firecracker.tgz -C /tmp \
 && release="/tmp/release-${FIRECRACKER_VERSION}-${fc_arch}" \
 && if [ -f "${release}/firecracker-${FIRECRACKER_VERSION}-${fc_arch}" ]; then \
        mv "${release}/firecracker-${FIRECRACKER_VERSION}-${fc_arch}" /usr/local/bin/firecracker; \
    else \
        mv "${release}/firecracker" /usr/local/bin/firecracker; \
    fi \
 && rm -rf /tmp/firecracker.tgz "$release" \
 && chmod +x /usr/local/bin/firecracker
RUN useradd -m -u 1000 -s /bin/bash kletka
COPY --from=build /build/docker/guest-default/ /usr/share/kletka/guest/default/
COPY --from=build /usr/local/bin/kletka-vm-agent /usr/local/bin/kletka-vm-agent
ENV HOME=/var/lib/kletka
WORKDIR /var/lib/kletka
LABEL org.opencontainers.image.source="https://github.com/kletka-dev/kletka" \
      org.opencontainers.image.description="kletka vm-agent" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/kletka-vm-agent"]

FROM debian:trixie-slim AS image-builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      podman fakeroot e2fsprogs bash curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN printf '[storage]\ndriver = "overlay"\ngraphroot = "/var/lib/kletka/podman-store"\nrunroot = "/run/containers/storage"\n' \
      > /etc/containers/storage.conf
COPY --from=build /usr/local/bin/kletka-image-builder /usr/local/bin/kletka-image-builder
ENV KLETKA_CONTAINER_ENGINE=podman \
    HOME=/var/lib/kletka
WORKDIR /var/lib/kletka
LABEL org.opencontainers.image.source="https://github.com/kletka-dev/kletka" \
      org.opencontainers.image.description="kletka guest-image builder: builds/patches guest images in the deployment environment" \
      org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["/usr/local/bin/kletka-image-builder"]
