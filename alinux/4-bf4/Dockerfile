ARG DOCKER_IMAGE_URL
FROM --platform=linux/arm64 ${DOCKER_IMAGE_URL}

ADD qemu-aarch64-static /usr/bin/

ADD 10-mlx-console-messages.conf /etc/sysctl.d/
ADD install.env /root/workspace/install.env/
ADD install.sh create_bfb /root/workspace/

ADD repos/ /etc/yum.repos.d/

RUN echo "install_weak_deps=False" >> /etc/dnf/dnf.conf && \
    echo 'excludepkgs=OpenIPMI' >> /etc/dnf/dnf.conf && \
    # alinux mirrors are throttled; relax dnf download limits so slow transfers don't abort.
    printf 'minrate=100\ntimeout=600\nretries=20\n' >> /etc/dnf/dnf.conf && \
    dnf config-manager --set-enabled alinux4-devel

RUN dnf -y install systemd && \
    dnf  --allowerasing -y group install Core && \
    dnf  -y install \
        kernel \
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
        efibootmgr \
        glibc-langpack-en \
        grub2 \
        grub2-efi-aa64 \
        grub2-efi-aa64-cdboot \
        grub2-efi-aa64-modules \
        grubby \
        iperf3 \
        ipmitool \
        iproute-tc \
        jq \
        kexec-tools \
        kubeadm \
        kubelet \
        kubernetes-cni \
        libvirt \
        libbsd \
        lm_sensors \
        lm_sensors-sensord \
        lsof \
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
        shim-aa64 \
        sshpass \
        sudo \
        sysstat \
        tcpdump \
        unzip \
        usbutils \
        vim \
        vim-common \
        virt-install \
        wget \
        xfsprogs \
        xorriso \
        yum-utils \
        zip \
#DOCA Packages
        doca-runtime \
        doca-runtime-kernel \
        mlnx-ofa_kernel-modules \
        doca-devel \
        mlnx-libsnap \
        mft-autocomplete \
        mstflint \
        https://archives.fedoraproject.org/pub/archive/epel/9.6/Everything/aarch64/Packages/s/strongswan-5.9.11-1.el9.aarch64.rpm \
    && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Manage services
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true
RUN systemctl disable mlx_ipmid.service || true
# ecs_mq is the Alibaba Cloud ECS message-queue agent baked into the alinux base
# image; it has no role on a DPU and fails to start every boot. Mask it (alinux-only).
RUN systemctl mask ecs_mq.service || true
RUN systemctl disable bfvcheck || true

# Add the built-in "None" source, so cloud-init resolves cleanly (no-op) instead of failing.
RUN  printf 'datasource_list: [ NoCloud, None ]\n' > /etc/cloud/cloud.cfg.d/99-nvidia-bf-datasource.cfg

RUN rm -f /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf
