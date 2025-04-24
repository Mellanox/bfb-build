
FROM ctyunos:23.01
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

RUN command -v dnf || command -v yum || echo "No dnf or yum found"

RUN dnf install -y bash
RUN pwd
RUN ls -l

RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN echo 'excludepkgs=OpenIPMI libreswan' >> /etc/dnf/dnf.conf && \
    dnf -y clean all && \
    rpm --install /root/workspace/doca-repo.rpm && \
    rpm --install /usr/share/doca-dpu-repo*/repo/${MLXBF_BOOTIMAGES}-[0-9]*.rpm && \
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
        vim-common \
        virt-install \
        watchdog \
        wget \
        xfsprogs \
        https://rpmfind.net/linux/epel/8/Everything/aarch64/Packages/e/edac-utils-0.18-27.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.1.0-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.1.0-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.12.2-1.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
        https://rpmfind.net/linux/epel/8/Everything/aarch64/Packages/p/python3-twisted-19.10.0-4.el8.aarch64.rpm \
        https://rpmfind.net/linux/epel/8/Everything/aarch64/Packages/p/python3-zope-interface-4.6.0-1.el8.aarch64.rpm \
#DOCA Packages
        doca-runtime \
        doca-devel \
        libxlio \
        libxlio-devel \
        libxlio-utils \
        mlnx-snap \
        strongswan \
        ${MLNX_FW_UPDATER} \
        ${BMC_FW_PACKAGES} \
    && \
    dnf --exclude='mlxbf-bootimages*' -y reinstall bf-release grub2 grub2-common && \
    dnf -y remove 'doca-dpu-repo*' && \
    dnf -y clean all && \
    rm -rf /var/cache/* /etc/yum.repos.d/urm.repo /root/workspace/doca-repo.rpm && \
    truncate -s0 /etc/machine-id && \
    update-pciids

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl disable kubelet || true
RUN systemctl disable containerd || true

# Reinstall broken RPMs
RUN for ff in `rpm -qa`; do if ! (rpm --verify $ff > /dev/null 2>&1); then dnf reinstall --nogpgcheck -y $ff; fi; done

RUN dnf install -y kernel-5.10.0-136.12.0.88.4.ctl3.aarch64.rpm kernel-devel-5.10.0-136.12.0.88.4.ctl3.aarch64.rpm

CMD ["/root/workspace/build_ctyunos_bfb"]