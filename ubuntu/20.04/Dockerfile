#  docker build -t bfb_runtime_ubuntu20.04 -f Dockerfile .
FROM scratch
ADD ubuntu-20.04-server-cloudimg-arm64-root.tar.xz /
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD update.cap .
ADD vmlinuz .

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

RUN apt update
RUN apt remove --purge -y snapd plymouth
RUN apt autoremove -y
RUN apt install -y grub-efi-arm64-signed grub-efi-arm64-bin shim-signed watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad
RUN apt install -y docker.io; systemctl disable docker.service || true; systemctl disable docker.socket || true
RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y libpam-pwquality; echo "minlen = 8" >> /etc/security/pwquality.conf; echo "minclass = 3" >> /etc/security/pwquality.conf
RUN apt install -y python2.7 python3.8

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10

RUN curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
RUN apt update
RUN apt install -y kubelet runc containerd
RUN apt upgrade -y
RUN wget -qO - https://linux.mellanox.com/public/repo/doca/1.2.1/ubuntu20.04/aarch64/GPG-KEY-Mellanox.pub | sudo apt-key add -
RUN echo "deb [trusted=yes] https://linux.mellanox.com/public/repo/doca/1.2.1/ubuntu20.04/\$(ARCH) ./" | tee /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container
RUN apt install -y -f \
	linux-bluefield=5.4.0.1023.24 \
	linux-bluefield-headers-5.4.0-1023=5.4.0-1023.26 \
	linux-bluefield-tools-5.4.0-1023=5.4.0-1023.26 \
	linux-headers-5.4.0-1023-bluefield=5.4.0-1023.26 \
	linux-headers-bluefield=5.4.0.1023.24 \
	linux-image-5.4.0-1023-bluefield=5.4.0-1023.26 \
	linux-image-bluefield=5.4.0.1023.24 \
	linux-modules-5.4.0-1023-bluefield=5.4.0-1023.26 \
	linux-tools-5.4.0-1023-bluefield=5.4.0-1023.26 \
	linux-tools-bluefield=5.4.0.1023.24

RUN apt install -y -f doca-runtime doca-tools doca-sdk || true
RUN apt-mark hold linux-tools-bluefield linux-image-bluefield linux-bluefield linux-headers-bluefield linux-image-bluefield linux-libc-dev linux-tools-common
RUN apt --fix-broken install -y || true
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
RUN systemctl disable ztp.service || true
RUN systemctl disable nvsm-api-gateway.service || true
RUN systemctl disable nvsm-core.service || true
RUN systemctl disable nvsm-mqtt.service || true
RUN systemctl disable nvsm-notifier.service || true
RUN systemctl disable nvsm.service || true
RUN sed -i -e  '/configure/a exit 0' /usr/share/nvsm/pkgscripts/postinst
RUN /bin/rm -f /etc/nvsm/nvsm-ca.crt \
				/etc/nvsm/nvsm-ca.key \
				/etc/nvsm/nvsm-ca.srl \
				/etc/nvsm/nvsm-server.crt \
				/etc/nvsm/nvsm-server.csr \
				/etc/nvsm/nvsm-server.key


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


CMD ["/root/workspace/create_bfb", "-k", "5.4.0-1023-bluefield"]
