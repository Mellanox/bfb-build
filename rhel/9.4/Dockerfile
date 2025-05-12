FROM registry.redhat.io/ubi9/ubi:9.4

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

RUN echo 'excludepkgs=OpenIPMI strongswan*el9' >> /etc/dnf/dnf.conf && \
    rm -f /etc/sysconfig/network-scripts/ifcfg-enp1s0 /etc/NetworkManager/system-connections/enp1s0.nmconnection /etc/yum.repos.d/ubi.repo && \
    dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && \
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
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        mft-autocomplete \
        mstflint \
        strongswan \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
    && \
    dnf --disablerepo='*' --enablerepo='RH-*,kubernetes,doca' --exclude='mlxbf-bootimages*' -y reinstall bf-release && \
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
RUN systemctl enable mlnx_snap.service || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true
