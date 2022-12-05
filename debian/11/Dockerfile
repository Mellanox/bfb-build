FROM mellanox/bluefield:bfb_builder_debian11
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD mlxbf-bootimages_3.9.3-12383_arm64.deb .
ADD doca-repo.deb .

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN apt update
RUN apt remove --purge -y snapd plymouth
RUN apt autoremove -y
RUN apt install -y vim parted cpio logrotate initramfs-tools dosfstools e2fsprogs ifupdown uuid-runtime efivar openssh-server shim-signed shim-unsigned watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad initramfs-tools dosfstools sudo bsdmainutils wget fdisk usbutils
RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y python2.7 python3.9

RUN apt install -y \
 	grub-common \
 	grub2-common \
 	grub-efi-arm64-signed \
 	grub-efi-arm64-bin \
 	grub-efi-arm64

RUN apt upgrade -y

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.9 1
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

RUN wget -qO - https://linux.mellanox.com/public/repo/doca/1.5.1/debian11/aarch64/GPG-KEY-Mellanox.pub | apt-key add -
RUN echo "deb [trusted=yes] https://linux.mellanox.com/public/repo/doca/1.5.1/debian11/\$(ARCH) ./" | tee /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true

RUN dpkg -i /root/workspace/doca-repo.deb
RUN apt update || true

RUN apt install -y -f --allow-downgrades \
		linux-image-5.10.156-bf.76.g6d46ef5=5.10.156-bf.76.g6d46ef5-1 \
		linux-headers-5.10.156-bf.76.g6d46ef5=5.10.156-bf.76.g6d46ef5-1 \
		linux-libc-dev=5.10.156-bf.76.g6d46ef5-1
RUN apt install -y -f doca-runtime-user || true
RUN apt install -y -f doca-runtime-kernel || true
RUN apt install -y -f doca-sdk-user || true
RUN apt install -y -f doca-sdk-kernel || true
RUN apt install -y -f doca-tools || true
RUN cd /var/doca-dpu-repo-debian11-local; for dr in *modules*deb; do dpkg -i $dr || true;done
RUN apt --fix-broken install -y || true
# RUN apt install -y bf-release mlxbf-scripts mstflint || true
RUN apt install -y libvma libvma-dev libvma-utils || true
RUN apt install -y mlnx-libsnap mlnx-snap || true
RUN apt remove --purge -y doca-dpu-repo-debian11-local || true
RUN /bin/rm -f /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true
RUN /usr/sbin/dpkg-reconfigure bf-release || true
RUN mkdir -p /etc/kubelet.d
RUN mkdir -p /workspace
RUN dpkg -i /root/workspace/mlxbf-bootimages_*_arm64.deb

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

RUN /usr/sbin/update-pciids || true

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

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "5.10.156-bf.76.g6d46ef5"]
