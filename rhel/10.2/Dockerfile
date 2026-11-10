FROM --platform=linux/arm64 registry.access.redhat.com/ubi10/ubi:10.2

ENV RUN_FW_UPDATER="no"

ARG BASE_URL
ARG BSP_VERSION

ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
ARG BMC_FW_PACKAGES="bf2-bmc-fw-signed bf3-bmc-fw-signed bf3-bmc-gi-signed bf3-bmc-nic-fw*"
ARG CEC_FW_PACKAGES="bf2-cec-fw-signed bf3-cec-fw-signed"

ADD bootimages bootimages/
ADD 10-mlx-console-messages.conf /etc/sysctl.d/
ADD install.env /root/workspace/install.env/
ADD install.sh create_bfb /root/workspace/
ADD repos/ /etc/yum.repos.d/

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN echo 'excludepkgs=OpenIPMI strongswan*el10' >> /etc/dnf/dnf.conf && \
    rm -f /etc/sysconfig/network-scripts/ifcfg-enp1s0 /etc/NetworkManager/system-connections/enp1s0.nmconnection /etc/yum.repos.d/ubi.repo && \
    dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm && \
    rpm --erase --nodeps systemd && \
    dnf -y install --allowerasing systemd && \
    rm -f /etc/machine-id && systemd-machine-id-setup && \
    dnf -y clean all && \
    dnf --disablerepo='*' --enablerepo='RH-*,epel,kubernetes,doca,docker' --exclude='mlxbf-bootimages*' --exclude='*-firmware' --exclude='kernel-*' --allowerasing -y group install Core && \
    dnf --disablerepo='*' --enablerepo='RH-*,epel,kubernetes,doca,docker' --exclude='mlxbf-bootimages*' -y update && \
    dnf --disablerepo='*' --enablerepo='RH-*,epel,kubernetes,doca,docker' --exclude='mlxbf-bootimages*' -y install \
        acpid \
        audit \
        bind-utils \
        chrony \
        containerd.io \
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
        dhcpcd \
        efibootmgr \
        epel-release \
        ethtool \
        grub2-efi-aa64 \
        glibc-langpack-en \
        grub2 \
        grub2-efi-aa64-cdboot \
        grub2-efi-aa64-modules \
        grubby \
        i2c-tools \
        ipcalc \
        iperf3 \
        ipmitool \
        iproute-tc \
        iptables-nft \
        iptables-nft-services \
        jq \
        kernel \
        kernel-core \
        kernel-cross-headers \
        kernel-devel \
        kernel-headers \
        kernel-modules \
        kernel-modules-core \
        kernel-modules-extra \
        kernel-tools \
        kernel-tools-libs \
        kernel-tools-libs-devel \
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
        net-tools \
        lsb-release \
        mtools \
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
        xorriso \
        yum-utils \
        zip \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mft-autocomplete \
        mstflint \
        strongswan \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
    && \
    rpm -e --nodeps bf-release && \
    dnf --disablerepo='*' --enablerepo='RH-*,kubernetes,doca' --exclude='mlxbf-bootimages*' -y install bf-release && \
    KVER="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-core 2>/dev/null)" && \
    test -s "/usr/lib/modules/${KVER}/vmlinuz" && \
    kernel-install add "${KVER}" "/usr/lib/modules/${KVER}/vmlinuz" && \
    test -s "/boot/vmlinuz-${KVER}" && \
    test -s "/boot/initramfs-${KVER}.img" && \
    ls /boot/loader/entries/ | grep -q "${KVER}" && \
    dnf -y clean all && \
    rm -rf /etc/machine-id /root/anaconda-post.log /root/*.cfg && \
    truncate -s0 /etc/machine-id && \
    update-pciids && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

# Create /var/log/journal so journald keeps logs across reboots
RUN mkdir -p /var/log/journal
