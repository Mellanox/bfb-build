FROM --platform=linux/arm64 openanolis/anolisos:8.6
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

RUN dnf install --nogpgcheck -y mmc-utils || dnf install --nogpgcheck -y $BASE_URL/bluefield/$BSP_VERSION/extras/mmc-utils/mmc-utils-0.1+git.20230209-1.1.aarch64.rpm || true

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN echo 'excludepkgs=OpenIPMI' >> /etc/dnf/dnf.conf && \
    dnf -y clean all && \
    dnf install -y epel-release && \
    dnf --exclude='mlxbf-bootimages*,kernel*' -y update && \
    dnf --exclude='mlxbf-bootimages*,kernel*' -y install coreutils-single && \
    dnf --exclude='mlxbf-bootimages*,kernel*' -y install http://mirrors.openanolis.cn/anolis/8.6/BaseOS/aarch64/os/Packages/rasdaemon-0.6.1-12.0.2.an8.aarch64.rpm && \
    dnf -y install python3-dnf-plugin-versionlock && \
    dnf --exclude='mlxbf-bootimages*' -y install kernel-5.10.134-13.1.an8 kernel-devel-5.10.134-13.1.an8 kernel-headers-5.10.134-13.1.an8 && \
    dnf versionlock add kernel-5.10.134-13.1.an8 kernel-devel-5.10.134-13.1.an8 kernel-headers-5.10.134-13.1.an8 rasdaemon-0.6.1-12.0.2.an8 && \
    dnf --exclude='mlxbf-bootimages*' -y install \
        acpid \
        audit \
        chkconfig \
        chrony \
        containerd.io \
        cri-tools \
        cryptsetup \
        curl \
        dhcp-client \
        dosfstools \
        dracut \
        dracut-network \
        dracut-tools \
        e2fsprogs \
        edac-utils \
        efibootmgr \
        epel-release \
        findutils \
        gawk \
        glibc-langpack-en \
        grub2 \
        grubby \
        i2c-tools \
        iperf3 \
        ipmitool \
        iproute-tc \
        iputils \
        jq \
        kexec-tools \
        kmod \
        kubeadm \
        kubelet \
        kubernetes-cni \
        libguestfs-tools \
        libhugetlbfs-utils \
        libvirt \
        libbsd \
        libbsd-devel \
        lm_sensors \
        lm_sensors-sensord \
        lsof \
        ltrace \
        lvm2 \
        mmc-utils \
        mokutil \
        mstflint \
        net-tools \
        NetworkManager \
        NetworkManager-config-server \
        NetworkManager-ovs \
        network-scripts \
        nfs-utils \
        nvme-cli \
        openssh-clients \
        openssh-server \
        openssl \
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
        spdk \
        sshpass \
        sudo \
        sysstat \
        systemd-timesyncd \
        system-lsb \
        tar \
        tcpdump \
        unzip \
        usbutils \
        util-linux \
        vim \
        vim-common \
        virt-install \
        watchdog \
        wget \
        which \
        xfsprogs \
#DOCA Packages
        doca-runtime \
        doca-devel \
        strongswan \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
        ${CEC_FW_PACKAGES} \
    && \
    dnf --disablerepo='*' --enablerepo='doca' --exclude='mlxbf-bootimages*' -y reinstall bf-release && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    truncate -s0 /etc/machine-id && \
    update-pciids

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl enable mlnx_snap.service || true 
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

RUN sed -i -E "s/(_unsigned|_prod|_dev)/_@IMAGE_TYPE@@CUSTOM_VERSION@/;" /etc/mlnx-release
