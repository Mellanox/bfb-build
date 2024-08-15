FROM scratch

ENV DEBIAN_FRONTEND="noninteractive" FLASH_KERNEL_SKIP="yes" RUN_FW_UPDATER="no"

ADD jammy-server-cloudimg-arm64-root.tar.xz /
ADD qemu-aarch64-static /usr/bin/
RUN mkdir -p /opt/mellanox/doca/services/
ADD telemetry-agent /opt/mellanox/doca/services/telemetry
ADD blueman /opt/mellanox/doca/services/blueman
ADD infrastructure /opt/mellanox/doca/services/infrastructure

ARG MLNX_FW_UPDATER=mlnx-fw-updater-signed
WORKDIR /root/workspace
ADD install.sh .
ADD install.env ./install.env
ADD create_bfb .
ADD build_ubuntu_bfb .
ADD mlxbf-bootimages.deb .
ADD BF2BMC ./BF2BMC
ADD BF3BMC ./BF3BMC
ADD 10-mlx-console-messages.conf /etc/sysctl.d/
ADD repos/ /etc/apt/sources.list.d/
ADD apt-preferences /etc/apt/preferences.d/99doca
ADD --chown=0:0 --chmod=644 https://prod-cdn.packages.k8s.io/repositories/isv:/kubernetes:/core:/stable:/v1.29/deb/Release.key /etc/apt/keyrings/kubernetes.asc

RUN apt update
RUN dpkg -i /root/workspace/mlxbf-bootimages*.deb
RUN apt remove -y --purge $(dpkg --list "*openipmi*" | grep openipmi | awk '{print $2}') || true
RUN apt install -y -f \
	linux-bluefield-cloud-tools-common=5.15.0-1050.52 \
	linux-bluefield-headers-5.15.0-1050=5.15.0-1050.52 \
	linux-bluefield-modules-5.15.0-1050-bluefield=5.15.0-1050.52+1 \
	linux-bluefield-modules-bluefield=5.15.0-1050.52+1 \
	linux-bluefield-modules-headers=5.15.0-1050.52+1 \
	linux-bluefield-modules-source=5.15.0-1050.52+1 \
	linux-bluefield-modules=5.15.0-1050.52+1 \
	linux-bluefield-tools-5.15.0-1050=5.15.0-1050.52 \
	linux-bluefield=5.15.0.1050.52 \
	linux-buildinfo-5.15.0-1050-bluefield=5.15.0-1050.52 \
	linux-headers-5.15.0-1050-bluefield=5.15.0-1050.52 \
	linux-headers-bluefield=5.15.0.1050.52 \
	linux-image-5.15.0-1050-bluefield=5.15.0-1050.52 \
	linux-image-bluefield=5.15.0.1050.52 \
	linux-modules-5.15.0-1050-bluefield=5.15.0-1050.52 \
	linux-modules-extra-5.15.0-1050-bluefield=5.15.0-1050.52 \
	linux-tools-5.15.0-1050-bluefield=5.15.0-1050.52 \
	linux-tools-bluefield=5.15.0.1050.52

RUN apt-get clean -y && \
    apt-get update -o "Acquire::https::Verify-Peer=false" -y && \
    apt-get install -o "Acquire::https::Verify-Peer=false" -y ca-certificates locales gzip && \
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    apt-get clean -y && \
    apt-get update -y && \
    apt-get autoremove --purge -y \
        snapd \
        plymouth \
    && \
    apt-get upgrade -y && \
    apt-get install -y \
        acpid \
        bash-completion \
        bc \
        bridge-utils \
        bsdextrautils \
        build-essential \
        conntrack \
        containerd \
        cri-tools \
        curl \
        dc \
        dmidecode \
        dnsmasq \
        docker.io \
        dosfstools \
        dracut \
        dracut-network \
        ebtables \
        edac-utils \
        ethtool \
        fdisk \
        file \
        gawk \
        grub-efi \
        i2c-tools \
        ifenslave \
        iperf3 \
        ipmitool \
        iptables-persistent \
        iputils-arping \
        iputils-ping \
        iputils-tracepath \
        irqbalance \
        isc-dhcp-client \
        jq \
        kexec-tools \
        kubeadm \
        kubelet \
        kubernetes-cni \
        less \
        libev4 \
        libgdbm-dev \
        libhugetlbfs-bin \
        libpam-pwquality \
        lldpad \
        lm-sensors \
        mmc-utils \
        mstflint \
        net-tools \
        network-manager \
        nfs-common \
        nftables \
        ntpsec \
        nvme-cli \
        parted \
        pciutils \
        pkexec \
        python3-pip \
		python3.10 \
		python3-pyinotify \
        rasdaemon \
        rsync \
        rsyslog \
        shim-signed \
        software-properties-common \
        ssh \
        sshpass \
        sudo \
        sysstat \
        tcpdump \
        unzip \
        usbutils \
        uuid \
        uuid-runtime \
        vim \
        watchdog \
        zstd \
#DOCA Packages
        doca-runtime \
        doca-devel \
        mlnx-snap \
        strongswan \
        ${MLNX_FW_UPDATER} \
    && \
    rm -rf /var/lib/apt/lists/* /root/workspace/doca-repo.deb /etc/default/grub.d/50-cloudimg-settings.cfg /etc/ssh/sshd_config.d/60-cloudimg-settings.conf /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf && \
    truncate -s0 /etc/machine-id && \
    printf 'set superusers="admin"' >> /etc/grub.d/40_custom && \
    printf 'password_pbkdf2 admin grub.pbkdf2.sha512.10000.5EB1FF92FDD89BDAF3395174282C77430656A6DBEC1F9289D5F5DAD17811AD0E2196D0E49B49EF31C21972669D180713E265BB2D1D4452B2EA9C7413C3471C53.F533423479EE7465785CC2C79B637BDF77004B5CC16C1DDE806BCEA50BF411DE04DFCCE42279E2E1F605459F1ABA3A0928CE9271F2C84E7FE7BF575DC22935B1' >> /etc/grub.d/40_custom && \
    sed -i -r -e "s/# minlen =.*/minlen = 12/" /etc/security/pwquality.conf && \
    sed -i -r -e "s/# silent/silent/;s/# deny.*/deny = 10/;s/# unlock_time.*/unlock_time = 600/" /etc/security/faillock.conf && \
    sed -i -e '/use_authtok/ipassword\trequired\t\t\tpam_pwhistory.so remember=3' /etc/pam.d/common-password && \
    sed -i -e "s@'gnulinux-simple-\$boot_device_id'@'gnulinux-simple-\$boot_device_id' --unrestricted@" -e "s@'gnulinux-\$version-\$type-\$boot_device_id'@'gnulinux-\$version-\$type-\$boot_device_id' --users ''@" /etc/grub.d/10_linux && \
    sed -i -e "s/FORCE_MODE=.*/FORCE_MODE=yes/" /etc/infiniband/openib.conf && \
    sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link && \
    update-pciids && \
    wget -qO - https://linux.mellanox.com/public/repo/doca/latest/ubuntu22.04/aarch64/GPG-KEY-Mellanox.pub | apt-key add -

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1

# Manage system services
RUN systemctl enable NetworkManager.service || true
RUN systemctl enable NetworkManager-wait-online.service || true
RUN systemctl enable networking.service || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl enable acpid.service || true
RUN systemctl enable mlx-openipmi.service || true
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
RUN systemctl enable mst || true
RUN systemctl disable mlx-regex.service || true
RUN systemctl disable openvswitch-ipsec || true
RUN systemctl disable srp_daemon.service || true
RUN systemctl disable ibacm.service || true
RUN systemctl disable opensmd.service || true
RUN systemctl disable unattended-upgrades.service || true
RUN systemctl disable apt-daily-upgrade.timer || true
RUN systemctl disable docker.service || true
RUN systemctl disable docker.socket || true
RUN systemctl disable kubelet.service || true
RUN systemctl disable containerd.service || true
RUN systemctl disable ModemManager.service || true


# openibd to support MLNX_OFED drivers coming with Canonical's deb
RUN sed -i -e "s/FORCE_MODE=.*/FORCE_MODE=yes/" /etc/infiniband/openib.conf

# Copy boot bits from rootfs to EFI partition
RUN mkdir -p /boot/efi/EFI/ubuntu/; \
	cp /usr/lib/grub/arm64-efi-signed/grubaa64.efi.signed \
	/boot/efi/EFI/ubuntu/grubaa64.efi; \
	cp /usr/lib/grub/arm64-efi-signed/grubnetaa64.efi.signed \
	/boot/efi/EFI/ubuntu/grubnetaa64.efi; \
	cp /usr/lib/shim/shimaa64.efi.signed \
	/boot/efi/EFI/ubuntu/shimaa64.efi; \
	cp /usr/lib/shim/mmaa64.efi \
	   /usr/lib/shim/BOOTAA64.CSV \
	/boot/efi/EFI/ubuntu/; \
	mkdir -p /boot/efi/EFI/BOOT; \
	cp /usr/lib/shim/shimaa64.efi.signed \
	/boot/efi/EFI/BOOT/BOOTAA64.EFI; \
	cp /usr/lib/shim/mmaa64.efi \
	   /usr/lib/shim/fbaa64.efi \
	/boot/efi/EFI/BOOT/

RUN sed -i "s/_unsigned|_prod|_dev//" /etc/mlnx-release; sed -i "s/$/_@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release
