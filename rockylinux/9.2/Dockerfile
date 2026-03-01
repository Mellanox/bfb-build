FROM --platform=linux/arm64 rockylinux:9.2
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
ENV KERNEL="5.14.0-284.30.1.el9_2.aarch64"

ADD repos/ /etc/yum.repos.d/

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN dnf install --nogpgcheck -y epel-release "dnf-command(config-manager)"

RUN dnf install --nogpgcheck -y yum-utils

#Enable CRB repo
RUN yum-config-manager --enable crb

RUN sed -i '/mirrorlist=.*/d;s/#baseurl/baseurl/g;s/$releasever/9.2/g' /etc/yum.repos.d/rocky*.repo && \
    echo 'vault/rocky' > /etc/dnf/vars/contentdir

RUN dnf install -y \
		kernel-rpm-macros

RUN dnf install -y \
		kernel-core-${KERNEL} \
		kernel-modules-core-${KERNEL} \
		kernel-${KERNEL} \
		kernel-headers-${KERNEL} \
		kernel-devel-${KERNEL}

RUN dnf install -y dnf-plugin-versionlock
RUN dnf versionlock add kernel-${KERNEL}
RUN dnf versionlock add kernel-core-${KERNEL}
RUN dnf versionlock add kernel-devel-${KERNEL}

RUN echo 'excludepkgs=OpenIPMI strongswan*el9' >> /etc/dnf/dnf.conf && \
    dnf -y install systemd && \
    rm -f /etc/machine-id && systemd-machine-id-setup && \
    rm -f /etc/sysconfig/network-scripts/ifcfg-enp1s0 && \
    rm -f /etc/NetworkManager/system-connections/enp1s0.nmconnection && \
    dnf -y clean all && \
    dnf --exclude='mlxbf-bootimages*' --exclude='mlxbf-bootimages*' --exclude='*-firmware' --exclude='kernel-*' --allowerasing -y --nogpgcheck group install Core && \
    dnf --exclude='mlxbf-bootimages*' -y --nogpgcheck update && \
    dnf --enablerepo=baseos --exclude='mlxbf-bootimages*' -y --nogpgcheck install \
        acpid \
        audit \
        bind-utils \
        chrony \
        containerd.io \
        cpp \
        gcc \
        libgcc \
        libgomp \
        cri-tools \
        cryptsetup \
        curl \
        docker-ce-cli \
        dosfstools \
        dracut \
        dracut-network \
        dracut-tools \
        e2fsprogs \
        edac-utils \
        efibootmgr \
        epel-release \
        glibc-langpack-en \
        grub2 \
        grubby \
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
        libbsd \
        libbsd-devel \
        lm_sensors \
        lm_sensors-sensord \
        lsof \
        ltrace \
        lvm2 \
        net-tools \
        lsb-release \
        NetworkManager \
        NetworkManager-config-server \
        NetworkManager-ovs \
        nfs-utils \
        numactl \
        nvme-cli \
        nvmetcli \
        openssh-clients \
        openssh-server \
        parted \
        pciutils \
        perf \
        python3-pip \
        qemu-kvm \
        rasdaemon \
        rrdtool \
        rsync \
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
        vim-common \
        virt-install \
        watchdog \
        wget \
        xfsprogs \
        yum-utils \
        zip \
        https://dl.rockylinux.org/pub/rocky/8/BaseOS/aarch64/os/Packages/l/libhugetlbfs-2.21-17.el8.aarch64.rpm \
        https://dl.rockylinux.org/pub/rocky/8/BaseOS/aarch64/os/Packages/l/libhugetlbfs-utils-2.21-17.el8.aarch64.rpm \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        mlnx-libsnap \
        mft-autocomplete \
        mstflint \
        strongswan \
        kmod-gpio-mlxbf3 \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
        ${CEC_FW_PACKAGES} \
    && \
    dnf --exclude='mlxbf-bootimages*' -y --nogpgcheck reinstall bf-release && \
    dnf -y clean all && \
    rm -rf /var/cache/* /etc/machine-id /etc/yum/vars/infra /etc/BUILDTIME /root/anaconda-post.log /root/*.cfg && \
    truncate -s0 /etc/machine-id && \
    update-pciids && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

RUN sed -i -E "s/(_unsigned|_prod|_dev)/_@IMAGE_TYPE@@CUSTOM_VERSION@/;" /etc/mlnx-release
