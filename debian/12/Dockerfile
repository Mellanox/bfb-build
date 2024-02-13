FROM debian:12
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
ARG DISTRO
ARG DISTRO_VERSION
ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
WORKDIR /root/workspace
ADD install.sh .
ADD install.env ./install.env
ADD create_bfb .
ADD mlxbf-bootimages.deb .
ADD BF2BMC ./BF2BMC
ADD BF3BMC ./BF3BMC
ADD doca-repo.deb .
ADD debian.sources /etc/apt/sources.list.d/debian.sources
ADD docker.list /etc/apt/sources.list.d/docker.list
ADD kubernetes.list /etc/apt/sources.list.d/kubernetes.list

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

# Install Docker
RUN apt-get update -y -q; \
        apt-get install -y -q \
        apt-transport-https \
        ca-certificates \
        curl \
        sudo \
        gnupg-agent \
        software-properties-common \
        apt-utils; \
        install -m 0755 -d /etc/apt/keyrings; \
        curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc; \
        chmod a+r /etc/apt/keyrings/docker.asc; \
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          sudo tee /etc/apt/sources.list.d/docker.list > /dev/null; \
        curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.25/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg; \
        echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.25/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list; \
        apt update -y -q; \
        apt install -y docker-ce docker-ce-cli containerd.io kubelet cri-tools kubernetes-cni

RUN apt install -y grub-efi

RUN dpkg -i /root/workspace/doca-repo.deb

RUN apt-get update -y -q

RUN apt-get install --no-install-recommends -y -q \
                          linux-image-6.1.0-11-arm64 \
                          watchdog \
                          binutils \
                          sbsigntool \
                          rasdaemon \
                          net-tools \
                          iproute2 \
                          ethtool \
                          nfs-common \
                          lsb-release \
                          logrotate \
                          bsdmainutils \
                          liblz4-tool \
                          libiscsi7 \
                          efivar \
                          vim \
                          python3.11 \
                          python3-twisted \
                          python3-netifaces \
                          systemd \
                          rsyslog \
                          wget \
                          irqbalance \
                          ifupdown \
                          locales \
                          libjs-jquery \
                          libjs-underscore \
                          libvirt-clients \
                          libvirt-daemon \
                          hwdata \
                          less \
                          nvi \
                          dhcpcd \
                          iptables-persistent \
                          zstd \
                          efibootmgr \
                          bsdextrautils \
                          parted \
                          fdisk \
                          pkexec \
                          policykit-1 \
                          grep \
                          gawk \
                          sed \
                          openssh-server \
                          sshpass \
                          findutils \
                          util-linux-extra \
                          usbutils \
                          dosfstools \
                          file \
                          rsync \
                          tcpdump \
                          nvme-cli \
                          iputils-arping \
                          iputils-ping \
                          iputils-tracepath \
                          bridge-utils \
                          iperf3 \
                          bc \
                          initramfs-tools \
                          lm-sensors \
                          ifenslave \
                          acpid \
                          network-manager \
                          kexec-tools \
                          i2c-tools \
                          dc \
                          lldpad \
                          unzip \
                          ipmitool \
                          sysstat \
                          mmc-utils \
                          libhugetlbfs-bin \
                          uuid \
                          uuid-runtime \
                          ntp \
                          libgdbm-dev \
                          jq \
                          libev4 \
                          python3-pip \
                          build-essential

RUN apt-get install --no-install-recommends -y -q \
                          mstflint \
                          $MLXBF_BOOTIMAGES \
                          $MLNX_FW_UPDATER \
                          openvswitch-common=2.17.8-1 \
                          libopenvswitch=2.17.8-1 \
                          openvswitch-ipsec=2.17.8-1 \
                          openvswitch-switch=2.17.8-1 \
                          python3-openvswitch=2.17.8-1 \
                          strongswan-swanctl=5.9.10-1.bf \
                          doca-runtime \
                          doca-tools \
                          doca-sdk \
                          mlx-openipmi \
                          mlnx-snap \
                          '*mlx*-modules' \
                          'dpa*' \
                          flexio \
                          bluefield-edac-modules \
                          bf-release && \
                        apt-mark hold mstflint openvswitch-common libopenvswitch openvswitch-ipsec openvswitch-switch python3-openvswitch strongswan-swanctl && \
                        apt-get remove --purge -y 'doca-dpu-repo*' && \
                        apt-get clean -y -q && \
                        dpkg-reconfigure bf-release && \
                        rm -rf /var/lib/apt/lists/* && \
                        systemctl disable mlx-regex openvswitch-ipsec srp_daemon ibacm opensmd apt-daily-upgrade docker.service docker.socket kubelet.service containerd.service && \
                        systemctl enable NetworkManager NetworkManager-wait-online networking mlnx_snap acpid mlx-openipmi mlx_ipmid set_emu_param && \
                        truncate -s0 /etc/machine-id && \
                        sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "6.1.0-11-arm64"]
