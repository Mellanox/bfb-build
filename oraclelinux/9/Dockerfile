FROM --platform=linux/arm64 oraclelinux:9

ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG BSP_VERSION
ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
ARG BMC_FW_PACKAGES="bf2-bmc-fw-signed bf3-bmc-fw-signed bf3-bmc-gi-signed bf3-bmc-nic-fw*"
ARG CEC_FW_PACKAGES="bf2-cec-fw-signed bf3-cec-fw-signed"

ADD bootimages bootimages/
ADD 10-mlx-console-messages.conf /etc/sysctl.d/
ADD install.env /root/workspace/install.env/
ADD install.sh create_bfb /root/workspace/

ENV RUN_FW_UPDATER="no"

ADD repos/ /etc/yum.repos.d/

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN echo 'excludepkgs=OpenIPMI' >> /etc/dnf/dnf.conf && \
    dnf -y --exclude='mlxbf-bootimages*' install \
        acpid \
        annobin \
        audit \
        bc \
        binutils \
        chkconfig \
        chrony \
        containerd.io \
        coreutils \
        cri-tools \
        crypto-policies \
        cryptsetup \
        curl \
        dbus-tools \
        dhcp-client \
        device-mapper-persistent-data \
        dmidecode \
        docker-ce-cli \
        dosfstools \
        dracut \
        dracut-network \
        dracut-tools \
        e2fsprogs \
        efibootmgr \
        gawk \
        grub2 \
        grub2-tools grubby grub2-tools-minimal grub2-efi-aa64 \
        grub2-efi-aa64-modules grub2-common grub2-tools-extra shim-aa64 \
        i2c-tools \
        ibacm \
        infiniband-diags \
        initscripts \
        ipcalc \
        iperf3 \
        ipmitool \
        iproute-tc \
        iputils \
        iwpmd \
        jq \
        kexec-tools \
        kernel-rpm-macros \
        kmod \
        kubeadm \
        kubelet \
        kubernetes-cni \
        libbsd \
        libibverbs \
        libibverbs-utils \
        libibumad \
        librdmacm \
        librdmacm-utils \
        libmnl \
        libnghttp2 \
        libnl3 \
        libreswan \
        libunwind \
        lm_sensors \
        lsof \
        ltrace \
        lvm2 \
        mstflint \
        nano \
        net-tools \
        lsb-release \
        NetworkManager \
        NetworkManager-initscripts-updown \
        nfs-utils \
        nvme-cli \
        openssl \
        openssh-server \
        parted \
        passwd \
        pciutils \
        pciutils-devel \
        perf \
        perl \
        plymouth \
        popt-devel \
        python3-pip \
        python3-pyverbs  \
        python3-six \
        rasdaemon \
        rdma-core \
        rdma-core-devel \
        rng-tools \
        rsync \
        sg3_utils \
        shadow-utils \
        shim \
        spdk \
        srp_daemon \
        sshpass \
        sudo \
        systemd-udev \
        systemd-timesyncd \
        tar \
        tcpdump \
        unzip \
        usbutils \
        util-linux \
        vim \
        vim-common \
        watchdog \
        wget \
        which \
        xfsprogs \
        yum-utils \
        zip \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        mlnx-libsnap \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
        https://linux.mellanox.com/public/repo/doca/2.2.1/extras/addons/dracut-sshd-0.6.5-1.el8.noarch.rpm \
    && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    mkdir -p /etc/ssh/sshd_config.d && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

RUN rm -f /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable kdump || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

RUN systemctl enable openvswitch || true
RUN systemctl enable mlnx_snap || true
RUN systemctl enable watchdog || true

RUN sed -i -E "s/(_unsigned|_prod|_dev)/_@IMAGE_TYPE@@CUSTOM_VERSION@/;" /etc/mlnx-release