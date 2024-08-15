from --platform=linux/arm64 ctyunos3/ctyunos3:23.01
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
ARG DISTRO
ARG DISTRO_VERSION
ARG DISTRO_KERNEL
ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
WORKDIR /root/workspace
ADD install.sh .
ADD install.env ./install.env
ADD create_bfb .
ADD bootimages bootimages/
ADD BF2BMC ./BF2BMC
ADD BF3BMC ./BF3BMC
ADD build_ctyunos_bfb .
ADD 10-mlx-console-messages.conf /etc/sysctl.d/

ENV RUN_FW_UPDATER="no"

ADD repos/ /etc/yum.repos.d/

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN echo 'excludepkgs=OpenIPMI libreswan' >> /etc/dnf/dnf.conf && \
    dnf -y clean all && \
    dnf --setopt='tsflags=noscripts' -y autoremove 'kernel*' && rm -rf /lib/modules/* && \
    dnf --exclude='mlxbf-bootimages*' -y update && \
    mv /etc/yum.repos.d/ctyunos.repo.rpmnew /etc/yum.repos.d/ctyunos.repo && \
    dnf -y clean all && \
    dnf --exclude='mlxbf-bootimages*' -y install \
        acpid \
        audit \
        chrony \
        containerd.io \
        cri-tools \
        cryptsetup \
        ctyunos-lsb \
        curl \
        dosfstools \
        dracut \
        dracut-network \
        dracut-tools \
        e2fsprogs \
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
        openssh-clients \
        openssh-server \
        parted \
        pciutils \
        perf \
        python3-pip \
        qemu-kvm \
        rasdaemon \
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
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.1.0-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.1.0-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.12.2-1.el8.aarch64.rpm \
        https://repo.openeuler.org/openEuler-20.03-LTS/OS/aarch64/Packages/edac-utils-0.16-20.oe1.aarch64.rpm \
        https://dl.fedoraproject.org/pub/epel/9/Everything/aarch64/Packages/p/python3-twisted-22.10.0-3.el9.noarch.rpm \
        https://dl.fedoraproject.org/pub/epel/9/Everything/aarch64/Packages/p/python3-Automat-22.10.0-2.el9.noarch.rpm \
        https://dl.fedoraproject.org/pub/epel/9/Everything/aarch64/Packages/p/python3-zope-interface-5.4.0-5.el9.1.aarch64.rpm \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        strongswan-bf \
        ${MLNX_FW_UPDATER} \
    && \
    dnf --exclude='mlxbf-bootimages*' -y reinstall bf-release grub2 grub2-common && \
    dnf -y clean all && \
    rm -rf /var/cache/* && \
    truncate -s0 /etc/machine-id && \
    update-pciids

# Reinstall broken RPMs
RUN for ff in `rpm -qa`; do if ! (rpm --verify $ff > /dev/null 2>&1); then dnf reinstall --nogpgcheck -y $ff; fi; done

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

RUN sed -i "s/_unsigned|_prod|_dev//" /etc/mlnx-release; sed -i "s/$/_@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/build_ctyunos_bfb"]
