from --platform=linux/arm64 openeuler/openeuler:20.03-lts-sp1
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG BSP_VERSION
ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
ADD bootimages bootimages/
ADD 10-mlx-console-messages.conf /etc/sysctl.d/
ADD BF2BMC /root/workspace/BF2BMC/
ADD BF3BMC /root/workspace/BF3BMC/
ADD install.env /root/workspace/install.env/
ADD install.sh create_bfb /root/workspace/

ENV RUN_FW_UPDATER="no"

ADD repos/ /etc/yum.repos.d/

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN dnf install -y kernel-4.19.90-2109.1.0.0108.oe1.aarch64 kernel-devel-4.19.90-2109.1.0.0108.oe1.aarch64

RUN echo 'excludepkgs=OpenIPMI network-scripts-openvswitch' >> /etc/dnf/dnf.conf && \
    dnf -y clean all && \
    dnf --enablerepo='update,kubernetes,doca' --exclude='mlxbf-bootimages*' --exclude='kernel' --exclude='kernel-devel' -y update && \
    dnf --enablerepo='update,kubernetes,doca' --exclude='mlxbf-bootimages*' --exclude='kernel' --exclude='kernel-devel' -y install \
        acpid \
        audit \
        chrony \
        containerd.io \
        cri-tools \
        cryptsetup \
        curl \
        dosfstools \
        dracut \
        dracut-network \
        dracut-tools \
        e2fsprogs \
        edac-utils \
        efibootmgr \
        grub2 \
        grubby \
        glibc-langpack-en \
        i2c-tools \
        iperf3 \
        ipmitool \
        iproute-tc \
        jq \
        kexec-tools \
        kubeadm \
        kubelet \
        kubernetes-cni \
        libguestfs-tools \
        libhugetlbfs-utils \
        libvirt \
        lm_sensors \
        lm_sensors-sensord \
        lsof \
        ltrace \
        lvm2 \
        mstflint \
        net-tools \
        NetworkManager \
        NetworkManager-config-server \
        NetworkManager-ovs \
        network-scripts \
        nfs-utils \
        nvme-cli \
        openeuler-lsb \
        openssh-clients \
        openssh-server \
        parted \
        passwd \
        pciutils \
        perf \
        python3-pip \
        qemu-kvm \
        rasdaemon \
        rsyslog \
        sg3_utils \
        shim \
        sshpass \
        sudo \
        sysstat \
        systemd-timesyncd \
        tcpdump \
        unzip \
        usbutils \
        vim \
        virt-install \
        watchdog \
        wget \
        xfsprogs \
        https://linux.mellanox.com/public/repo/bluefield/latest/extras/addons/sshpass-1.09-1.oe2203.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.1.0-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.1.0-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.12.2-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/l/lcov-1.13-1.el7.noarch.rpm \
        https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/r/re2c-0.14.3-2.el7.aarch64.rpm \
        https://vault.centos.org/centos/8/BaseOS/aarch64/os/Packages/watchdog-5.15-2.el8.aarch64.rpm \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        strongswan-bf \
        ${MLNX_FW_UPDATER} \
    && \
    dnf --exclude='mlxbf-bootimages*' -y reinstall bf-release && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    truncate -s0 /etc/machine-id && \
    update-pciids

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

RUN sed -i "s/_unsigned|_prod|_dev//" /etc/mlnx-release; sed -i "s/$/_@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release
