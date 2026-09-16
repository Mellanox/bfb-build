FROM rockylinux/rockylinux:10.1

ADD qemu-aarch64-static /usr/bin/

ADD repos/ /etc/yum.repos.d/

RUN echo "install_weak_deps=False" >> /etc/dnf/dnf.conf && \
    sed -i '/tsflags=nodocs/d' /etc/dnf/dnf.conf && \
    dnf -y install dnf-plugins-core epel-release && \
    dnf config-manager --set-enabled 'crb'

# rocky 10.1: limit packages up to 10.1
RUN sed -i '/mirrorlist=.*/d;s/#baseurl/baseurl/g;s/$releasever/10.1/g' /etc/yum.repos.d/rocky*.repo && \
    echo 'vault/rocky' > /etc/dnf/vars/contentdir

RUN dnf -y install systemd && \
    dnf  --allowerasing -y group install Core && \
    rm -f /etc/machine-id && systemd-machine-id-setup && \
    rm -f /etc/sysconfig/network-scripts/ifcfg-enp1s0 && \
    rm -f /etc/NetworkManager/system-connections/enp1s0.nmconnection && \
    dnf -y clean all && \
    dnf -y install \
        kernel \
        acpid \
        audit \
        bind-utils \
        chrony \
        containerd.io \
        cri-tools \
        cryptsetup \
        curl \
        dbus-broker \
        docker-ce-cli \
        dosfstools \
        dracut \
        dracut-network \
        dracut-tools \
        e2fsprogs \
        edac-utils \
        efibootmgr \
        glibc-langpack-en \
        grub2 \
        grub2-common \
        grub2-efi-aa64 \
        grub2-efi-aa64-cdboot \
        grub2-efi-aa64-modules \
        grub2-tools \
        grub2-tools-extra \
        grub2-tools-minimal \
        grubby \
        i2c-tools \
        ipcalc \
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
        mtools \
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
        mft-autocomplete \
        mstflint \
        strongswan \
    && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    mkdir -p /etc/ssh/sshd_config.d && \
    echo 'PermitRootLogin yes' > /etc/ssh/sshd_config.d/00-nvidia-bf.conf && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config.d/00-nvidia-bf.conf

# Manage services
RUN systemctl enable openvswitch.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true
RUN systemctl disable mlx_ipmid.service || true
RUN systemctl disable bfvcheck || true

ADD 10-mlx-console-messages.conf /etc/sysctl.d/
ADD install.env /root/workspace/install.env/
ADD install.sh create_bfb /root/workspace/

