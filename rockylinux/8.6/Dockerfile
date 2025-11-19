from --platform=linux/arm64 rockylinux:8.6.20227707
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

RUN dnf install -y epel-release "dnf-command(config-manager)" && \
	dnf config-manager --set-enabled powertools

RUN sed -i '/mirrorlist=.*/d;s/#baseurl/baseurl/g;s/$releasever/8.6/g' /etc/yum.repos.d/Rocky-*.repo && \
    echo 'vault/rocky' > /etc/dnf/vars/contentdir && \
    echo 'excludepkgs=OpenIPMI' >> /etc/dnf/dnf.conf && \
    dnf -y clean all && \
    rm -f /etc/machine-id && systemd-machine-id-setup && \
    rm -f /etc/sysconfig/network-scripts/ifcfg-enp1s0 && \
    rm -f /etc/NetworkManager/system-connections/enp1s0.nmconnection && \
    dnf --exclude='mlxbf-bootimages*' --exclude='mlxbf-bootimages*' --exclude='*-firmware' --exclude='kernel-*' --allowerasing -y group install Core && \
    dnf --exclude='mlxbf-bootimages*' -y update && \
    rpm -e coreutils --nodeps && \
    dnf --exclude='mlxbf-bootimages*' -y install coreutils-single && \
    dnf --enablerepo=baseos --exclude='mlxbf-bootimages*' -y install \
        acpid \
        audit \
        bind-utils \
        chkconfig \
        chrony \
        containerd.io \
        cri-tools \
        cryptsetup \
        curl \
        device-mapper \
        dhcp-client \
        docker-ce-cli \
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
        lvm2-libs \
        mmc-utils \
        mokutil \
        mstflint \
        net-tools \
        network-scripts \
        NetworkManager \
        NetworkManager-config-server \
        NetworkManager-ovs \
        nfs-utils \
        numactl \
        nvme-cli \
        nvmetcli \
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
        redhat-lsb-core \
        rrdtool \
        rsync \
        sg3_utils \
        shim \
        sshpass \
        sudo \
        sysstat \
        systemd-timesyncd \
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
        yum-utils \
        zip \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        mlnx-libsnap \
        mft-autocomplete \
        mstflint \
        strongswan \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
        ${CEC_FW_PACKAGES} \
    && \
    dnf --exclude='mlxbf-bootimages*' -y reinstall bf-release && \
    dnf -y clean all && \
    rm -rf /var/cache/* /etc/machine-id /etc/yum/vars/infra /etc/BUILDTIME /root/anaconda-post.log /root/*.cfg && \
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
