FROM mellanox/bluefield:bfb_builder_debian10
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD update.cap .
ADD mlxbf-bootimages_3.8.5-12027_arm64.deb .

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

RUN dpkg -i mlxbf-bootimages_3.8.5-12027_arm64.deb
RUN apt update
RUN apt remove --purge -y snapd plymouth
RUN apt autoremove -y
RUN apt install -y grub-efi-arm64-signed grub-efi-arm64-bin openssh-server shim-signed watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad initramfs-tools dosfstools sudo bsdmainutils
RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y python2.7 python3.7

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.7 1
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10

# Install Docker
RUN apt purge -y docker.io; \
        apt-get install -y \
            apt-transport-https \
            ca-certificates \
            curl \
            gnupg-agent \
            software-properties-common; \
        curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add - ; \
        apt-key fingerprint 0EBFCD88; \
        add-apt-repository "deb [arch=arm64] https://download.docker.com/linux/debian \
           $(lsb_release -cs) stable"; \
        apt update; \
        apt install -y docker-ce docker-ce-cli containerd.io; \
        update-alternatives --set iptables /usr/sbin/iptables-legacy; \
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy;

RUN wget -qO - https://linux.mellanox.com/public/repo/doca/1.2.1/debian10/aarch64/GPG-KEY-Mellanox.pub | apt-key add -
RUN echo "deb [trusted=yes] https://linux.mellanox.com/public/repo/doca/1.2.1/debian10/\$(ARCH) ./" | tee /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN apt install -y -f libpka1 mlnx-dpdk mlx-regex strongswan libvma mlnx-snap mlnx-libsnap liburing1 spdk spdk-rpc virtio-net-controller mlx-openipmi rdma-core ibverbs-providers python3-pyverbs ibverbs-utils libibverbs1 librdmacm1 libibnetdisc5 ibacm mlnx-ofed-kernel-modules mlnx-ofed-kernel-utils mlnx-tools ofed-scripts libopensm ucx iser-modules isert-modules knem knem-modules kernel-mft-modules mft mft-oem libibumad3 libibmad5 mstflint libopenvswitch openvswitch-common openvswitch-switch python3-openvswitch openvswitch-ipsec srp-modules srptools mlnx-nvme-modules mlnx-fw-updater mlnx-ethtool mlnx-iproute2 doca-dpi doca-utils doca-flow doca-apsh doca-grpc doca-regex dpcp python3-grpcio python3-protobuf collectx-clxapi linux-image-5.4.0-1023.24.gd30084e-bluefield || true
RUN apt install -y -f mlxbf-scripts mlxbf-bootctl mlxbf-bootimages libvma-utils ibverbs-utils rdmacm-utils infiniband-diags perftest opensm ibutils2 rxp-compiler hyperscan rxpbench doca-dpi-tools || true
RUN apt install -y -f doca-sdk || true

RUN apt --fix-broken install -y || true
RUN apt install -y bf-release || true
RUN /bin/rm -f /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true
RUN /usr/sbin/dpkg-reconfigure bf-release || true
RUN mkdir -p /etc/kubelet.d
RUN mkdir -p /workspace

# Manage system services
RUN systemctl enable mlx-regex.service || true
RUN systemctl enable NetworkManager.service || true
RUN systemctl enable NetworkManager-wait-online.service || true
RUN systemctl enable networking.service || true
RUN systemctl enable mlnx_snap.service || true
RUN systemctl enable acpid.service || true
RUN systemctl enable mlx-openipmi.service || true
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true
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
RUN systemctl disable mosquitto.service || true

# Copy boot bits from rootfs to EFI partition
RUN mkdir -p /boot/efi/EFI/debian/; \
	cp /usr/lib/grub/arm64-efi-signed/grubaa64.efi.signed \
	/boot/efi/EFI/debian/grubaa64.efi; \
	cp /usr/lib/grub/arm64-efi-signed/grubnetaa64.efi.signed \
	/boot/efi/EFI/debian/grubnetaa64.efi; \
	cp /usr/lib/shim/shimaa64.efi.signed \
	/boot/efi/EFI/debian/shimaa64.efi; \
	cp /usr/lib/shim/mmaa64.efi \
	   /usr/lib/shim/BOOTAA64.CSV \
	/boot/efi/EFI/debian/; \
	mkdir -p /boot/efi/EFI/BOOT; \
	cp /usr/lib/shim/shimaa64.efi.signed \
	/boot/efi/EFI/BOOT/BOOTAA64.EFI; \
	cp /usr/lib/shim/mmaa64.efi \
	   /usr/lib/shim/fbaa64.efi \
	/boot/efi/EFI/BOOT/

CMD ["/root/workspace/create_bfb", "-k", "5.4.0-1023.24.gd30084e-bluefield"]
