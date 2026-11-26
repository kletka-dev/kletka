ARG FEDORA_VERSION=44
FROM registry.fedoraproject.org/fedora:${FEDORA_VERSION}

ARG FEDORA_VERSION=44

ARG KLETKA_UPDATE=0
LABEL org.opencontainers.image.base.name="registry.fedoraproject.org/fedora:${FEDORA_VERSION}"
LABEL kletka.update="${KLETKA_UPDATE}"

RUN dnf install -y --setopt=install_weak_deps=False \
        openssh-server openssh-clients sudo \
        NetworkManager \
        iproute iputils hostname wireguard-tools openresolv nftables \
        procps-ng \
        dbus-broker \
        systemd-pam \
        e2fsprogs util-linux findutils \
    && dnf clean all \
    && rm -rf /var/cache/libdnf5 /var/cache/dnf

RUN if [ "$KLETKA_UPDATE" = "1" ]; then \
        dnf -y upgrade --refresh \
        && dnf clean all \
        && rm -rf /var/cache/libdnf5 /var/cache/dnf; \
    fi

RUN useradd -m -u 1000 -s /bin/bash user \
    && echo 'user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/kletka-user \
    && chmod 0440 /etc/sudoers.d/kletka-user

RUN if [ -f /etc/selinux/config ]; then \
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config; \
    fi

RUN printf 'StreamLocalBindUnlink yes\n' > /etc/ssh/sshd_config.d/kletka.conf

RUN mkdir -p /etc/NetworkManager/conf.d \
    && printf '[main]\nrc-manager=none\n' \
        > /etc/NetworkManager/conf.d/99-kletka-static-dns.conf

RUN rm -f /etc/ssh/ssh_host_* /var/lib/dbus/machine-id /etc/machine-id

RUN rm -f /usr/local/sbin && mkdir -p /usr/local/sbin
COPY rootfs/ /
RUN mkdir -p /etc/systemd/system/multi-user.target.wants \
    && ln -sf /usr/lib/systemd/system/sshd.service \
              /etc/systemd/system/multi-user.target.wants/sshd.service \
    && ln -sf /usr/lib/systemd/system/NetworkManager.service \
              /etc/systemd/system/multi-user.target.wants/NetworkManager.service \
    && ln -sf /usr/lib/systemd/system/kletka-seed.service \
              /etc/systemd/system/multi-user.target.wants/kletka-seed.service \
    && ln -sf /usr/lib/systemd/system/kletka-wireguard.service \
              /etc/systemd/system/multi-user.target.wants/kletka-wireguard.service \
    && ln -sf /usr/lib/systemd/system/kletka-volumes.service \
              /etc/systemd/system/multi-user.target.wants/kletka-volumes.service \
    && ln -sf /usr/lib/systemd/system/kletka-checkpoints.service \
              /etc/systemd/system/multi-user.target.wants/kletka-checkpoints.service \
    && printf 'enable kletka-seed.service\nenable kletka-wireguard.service\nenable kletka-volumes.service\nenable kletka-checkpoints.service\n' \
              > /usr/lib/systemd/system-preset/50-kletka.preset

RUN ln -sf /dev/null /etc/systemd/system/systemd-firstboot.service

RUN mkdir -p /rw /rw/home /rw/usrlocal /.kletka/checkpoints \
    && chmod 0755 /usr/local/sbin/kletka-seed /usr/local/sbin/kletka-wireguard \
                  /usr/local/sbin/kletka-volumes \
                  /usr/local/sbin/kletka-checkpoints /usr/local/sbin/kletka-overlay-init

ENV container=docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
