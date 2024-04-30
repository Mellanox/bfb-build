FROM debian:12
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
ARG DISTRO
ARG DISTRO_VERSION
ARG DISTRO_KERNEL
ARG MLXBF_BOOTIMAGES=mlxbf-bootimages
ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
WORKDIR /root/workspace
ADD install.sh .
ADD install.env ./install.env
ADD create_bfb .
ADD mlxbf-bootimages.deb .
ADD BF2BMC ./BF2BMC
ADD BF3BMC ./BF3BMC
ADD debian.sources /etc/apt/sources.list.d/debian.sources

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

# Install Docker
RUN apt-get update -y -q
RUN apt-get install -y -q \
    apt-transport-https \
    ca-certificates \
    curl \
    sudo \
    gnupg-agent \
    software-properties-common \
    apt-utils
RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
RUN chmod a+r /etc/apt/keyrings/docker.asc
RUN echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
RUN echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
RUN curl -fsSL https://linux.mellanox.com/public/repo/doca/GPG-KEY-Mellanox.pub | gpg --dearmor > /etc/apt/trusted.gpg.d/GPG-KEY-Mellanox.pub
RUN apt update -y -q
RUN apt install -y docker-ce docker-ce-cli containerd.io kubelet=1.29.3-1.1 kubernetes-cni=1.3.0-1.1 cri-tools=1.29.0-1.1 kubeadm=1.29.3-1.1
RUN rm -f /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf

RUN apt install -y grub-efi

RUN echo "deb [trusted=yes] ${BASE_URL}/doca/${DOCA_VERSION}/${DISTRO}${DISTRO_VERSION}${DISTRO_KERNEL}/arm64-dpu/ /" | sudo tee /etc/apt/sources.list.d/doca.base.list

RUN apt-get update -y -q

RUN apt-get install --no-install-recommends -y -q \
						  libgrpc-dev=1.39.0-2 \
						  python3-protobuf=3.17.3 \
						  python3-grpcio=1.50.0

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
                          isc-dhcp-client \
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
                          xxd \
                          libev4 \
                          python3-pip \
                          build-essential

RUN apt-get install --no-install-recommends -y -q \
                          mstflint \
                          $MLXBF_BOOTIMAGES \
                          $MLNX_FW_UPDATER \
                          doca-openvswitch-common \
                          doca-libopenvswitch \
                          doca-openvswitch-ipsec \
                          doca-openvswitch-switch \
                          python3-doca-openvswitch \
                          strongswan-swanctl=5.9.10-1.bf \
                          doca-runtime \
                          doca-devel \
                          mlx-openipmi \
                          mlnx-snap \
                          '*mlx*-modules' \
                          'dpa*' \
                          flexio \
                          bluefield-edac-modules \
                          bf-release && \
                        apt-mark hold mstflint strongswan-swanctl kubelet cri-tools kubernetes-cni kubeadm && \
                        apt-get clean -y -q && \
                        dpkg-reconfigure bf-release && \
                        rm -rf /var/lib/apt/lists/* && \
                        systemctl disable mlx-regex openvswitch-ipsec srp_daemon ibacm opensmd apt-daily-upgrade docker.service docker.socket kubelet.service containerd.service && \
                        systemctl enable NetworkManager NetworkManager-wait-online networking mlnx_snap acpid mlx-openipmi mlx_ipmid set_emu_param && \
                        truncate -s0 /etc/machine-id && \
                        sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link

RUN /usr/sbin/update-pciids || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "6.1.0-11-arm64"]
