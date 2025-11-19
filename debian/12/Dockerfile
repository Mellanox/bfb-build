FROM --platform=linux/arm64 debian:12
ADD qemu-aarch64-static /usr/bin/

ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
ARG BMC_FW_PACKAGES="bf2-bmc-fw-signed bf3-bmc-fw-signed bf3-bmc-gi-signed bf3-bmc-nic-fw*"
ARG CEC_FW_PACKAGES="bf2-cec-fw-signed bf3-cec-fw-signed"
WORKDIR /root/workspace
ADD install.sh .
ADD install.env ./install.env
ADD create_bfb .
ADD mlxbf-bootimages.deb .
ADD 10-mlx-console-messages.conf /etc/sysctl.d/

ENV DEBIAN_FRONTEND="noninteractive" FLASH_KERNEL_SKIP="yes" RUN_FW_UPDATER="no"

ADD repos/ /etc/apt/sources.list.d/
ADD apt-preferences /etc/apt/preferences.d/99doca
ADD --chown=0:0 --chmod=644 https://download.docker.com/linux/debian/gpg /etc/apt/keyrings/docker.asc
ADD --chown=0:0 --chmod=644 https://prod-cdn.packages.k8s.io/repositories/isv:/kubernetes:/core:/stable:/v1.34/deb/Release.key /etc/apt/keyrings/kubernetes.asc

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN dpkg -i /root/workspace/mlxbf-bootimages.deb

RUN apt-get clean -y && \
    apt-get update -o "Acquire::https::Verify-Peer=false" -y && \
    apt-get install -o "Acquire::https::Verify-Peer=false" -y ca-certificates locales && \
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    apt-get clean -y && \
    apt-get update -y && \
    apt-get autoremove --purge -y \
        snapd \
        plymouth \
    && \
    apt-get upgrade -y && \
    apt-get install -y \
        acpid \
        bash-completion \
        bc \
        bridge-utils \
        bsdextrautils \
        build-essential \
        conntrack \
        containerd.io \
        cri-tools \
        curl \
        dc \
        dmidecode \
        dnsmasq \
        docker-ce \
        docker-ce-cli \
        dosfstools \
        dracut \
        dracut-network \
        ebtables \
        edac-utils \
        ethtool \
        fdisk \
        file \
        gawk \
        grub-efi \
        i2c-tools \
        ifenslave \
        iperf3 \
        ipmitool \
        iptables-persistent \
        iputils-arping \
        iputils-ping \
        iputils-tracepath \
        irqbalance \
        isc-dhcp-client \
        jq \
        kexec-tools \
        kubeadm \
        kubelet \
        kubernetes-cni \
        less \
        libev4 \
        libgdbm-dev \
        libhugetlbfs-bin \
        lldpd \
        lm-sensors \
        mmc-utils \
        mstflint \
        net-tools \
        network-manager \
        nfs-common \
        nftables \
        ntpsec \
        nvme-cli \
        parted \
        pciutils \
        pkexec \
        python3-netifaces \
        python3-pip \
        python3-twisted \
        python3.11 \
        rasdaemon \
        rsync \
        rsyslog \
        software-properties-common \
        mlnx-libsnap \
        spdk \
        spdk-rpc \
        spdk-dev \
        ssh \
        sshpass \
        sudo \
        sysstat \
        tcpdump \
        unzip \
        usbutils \
        uuid \
        uuid-runtime \
        vim \
        vim-common \
        watchdog \
        wget \
        xxd \
        zip \
        zstd \
        libyara9 \
        libteec1 \
#DOCA Packages
        doca-runtime \
        doca-devel \
        libxlio \
        libxlio-dev \
        libxlio-utils \
        strongswan \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
        ${CEC_FW_PACKAGES} \
    && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/* /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf && \
    truncate -s0 /etc/machine-id && \
    sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link && \
    update-pciids && \
    wget -qO - https://linux.mellanox.com/public/repo/doca/GPG-KEY-Mellanox.pub | apt-key add -

# Manage system services
RUN systemctl enable NetworkManager.service || true
RUN systemctl enable NetworkManager-wait-online.service || true
RUN systemctl enable networking.service || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl enable acpid.service || true
RUN systemctl enable mlx-openipmi.service || true
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl disable openvswitch-ipsec || true
RUN systemctl disable srp_daemon.service || true
RUN systemctl disable ibacm.service || true
RUN systemctl disable opensmd.service || true
RUN systemctl disable unattended-upgrades.service || true
RUN systemctl disable apt-daily-upgrade.timer || true
RUN systemctl disable docker.service || true
RUN systemctl disable docker.socket || true
RUN systemctl disable kubelet.service || true
RUN systemctl disable containerd.service || true
RUN systemctl disable ModemManager.service || true

RUN sed -i -E "s/(_unsigned|_prod|_dev)/_@IMAGE_TYPE@@CUSTOM_VERSION@/;" /etc/mlnx-release
