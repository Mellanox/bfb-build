FROM --platform=linux/arm64 openeuler/openeuler:22.03-lts-sp3
ADD qemu-aarch64-static /usr/bin/

ARG BMC_FW_PACKAGES=bf3-bmc-nic-fw
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

RUN dnf install -y kernel-5.10.0-280.0.0.182.oe2203sp3 kernel-devel-5.10.0-280.0.0.182.oe2203sp3 kernel-headers-5.10.0-280.0.0.182.oe2203sp3

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
        efibootmgr \
        grub2 \
        grubby \
        glibc-all-langpacks \
        glibc-common \
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
        libvirt \
        lm_sensors \
        lm_sensors-sensord \
        lsof \
        ltrace \
        lvm2 \
        https://www.rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/aarch64/mmc-utils-0.1+git.20220208-bp155.1.12.aarch64.rpm \
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
        sg3_utils \
        shim \
        spdk \
        sshpass \
        sudo \
        sysstat \
        systemd-timesyncd \
        tcpdump \
        unzip \
        usbutils \
        vim \
        vim-common \
        virt-install \
        watchdog \
        wget \
        xfsprogs \
        https://linux.mellanox.com/public/repo/bluefield/4.9.1/extras/addons/libmd-1.1.0-1.el8.aarch64.rpm \
        https://linux.mellanox.com/public/repo/bluefield/4.9.1/extras/addons/libmd-devel-1.1.0-1.el8.aarch64.rpm \
        https://linux.mellanox.com/public/repo/bluefield/4.9.1/extras/addons/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
        https://linux.mellanox.com/public/repo/bluefield/4.9.1/extras/addons/libbsd-0.12.2-1.el8.aarch64.rpm \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        mlnx-libsnap \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
        ${CEC_FW_PACKAGES} \
    && \
    systemctl disable kubelet containerd && \
    dnf --exclude='mlxbf-bootimages*' -y reinstall bf-release && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    truncate -s0 /etc/machine-id && \
    update-pciids
#Fix version kernel
RUN dnf install -y dnf-plugin-versionlock
RUN dnf versionlock add kernel-5.10.0-224.0.0.127.oe2203sp3.aarch64
RUN dnf versionlock add kernel-devel-5.10.0-224.0.0.127.oe2203sp3.aarch64
RUN dnf versionlock add kernel-headers-5.10.0-224.0.0.127.oe2203sp3.aarch64

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

RUN sed -i -E "s/(_unsigned|_prod|_dev)/_@IMAGE_TYPE@@CUSTOM_VERSION@/;" /etc/mlnx-release
