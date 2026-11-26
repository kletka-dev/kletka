ARG FEDORA_VERSION=44
FROM registry.fedoraproject.org/fedora:${FEDORA_VERSION} AS build

ARG KERNEL_VERSION=7.3.6

ARG KERNEL_CI_CONFIG=6.18
ARG FC_CONFIG_BASE=https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs

RUN dnf install -y --setopt=install_weak_deps=False \
        make gcc bc bison flex perl gawk cpio diffutils \
        elfutils-libelf-devel openssl-devel \
        tar xz curl findutils \
    && dnf clean all

WORKDIR /build

RUN series="${KERNEL_VERSION%%.*}" \
    && curl -fL -o linux.tar.xz \
      "https://cdn.kernel.org/pub/linux/kernel/v${series}.x/linux-${KERNEL_VERSION}.tar.xz" \
    && tar -xJf linux.tar.xz \
    && rm linux.tar.xz

RUN curl -fL -o /tmp/ci.config \
      "${FC_CONFIG_BASE}/microvm-kernel-ci-x86_64-${KERNEL_CI_CONFIG}.config"

COPY microvm-kletka.config /tmp/kletka.config

RUN cd "linux-${KERNEL_VERSION}" \
    && cp /tmp/ci.config .config \
    && scripts/kconfig/merge_config.sh -m .config /tmp/kletka.config \
    && make olddefconfig \
    && cp .config /tmp/kernel.config

RUN cd "linux-${KERNEL_VERSION}" \
    && make -j"$(nproc)" vmlinux

RUN mkdir -p /out \
    && cp "linux-${KERNEL_VERSION}/vmlinux" /out/vmlinux \
    && cp /tmp/kernel.config /out/kernel.config

FROM scratch AS export
COPY --from=build /out /
