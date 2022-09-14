#  docker build -t bfb_runtime_ubuntu20.04 -f Dockerfile .
FROM scratch
Add jammy-server-cloudimg-arm64-root.tar.xz /
Add doca-repo.deb /tmp/
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD mlxbf-bootimages.deb .

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN apt update
RUN apt upgrade -y
RUN apt remove --purge -y snapd plymouth
RUN apt autoremove -y
RUN apt install -y grub-efi-arm64-signed grub-efi-arm64-bin shim-signed watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad unzip ipmitool
RUN apt install -y docker.io; systemctl disable docker.service || true; systemctl disable docker.socket || true
RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y libpam-pwquality; echo "minlen = 8" >> /etc/security/pwquality.conf; echo "minclass = 3" >> /etc/security/pwquality.conf
RUN apt install -y python2.7 python3.10

# Grub password
RUN echo 'set superusers="admin"' >> /etc/grub.d/40_custom; \
	echo 'password_pbkdf2 admin grub.pbkdf2.sha512.10000.5EB1FF92FDD89BDAF3395174282C77430656A6DBEC1F9289D5F5DAD17811AD0E2196D0E49B49EF31C21972669D180713E265BB2D1D4452B2EA9C7413C3471C53.F533423479EE7465785CC2C79B637BDF77004B5CC16C1DDE806BCEA50BF411DE04DFCCE42279E2E1F605459F1ABA3A0928CE9271F2C84E7FE7BF575DC22935B1' >> /etc/grub.d/40_custom; \
	sed -i -e "s@'gnulinux-simple-\$boot_device_id'@'gnulinux-simple-\$boot_device_id' --unrestricted@" \
	       -e "s@'gnulinux-\$version-\$type-\$boot_device_id'@'gnulinux-\$version-\$type-\$boot_device_id' --users ''@" /etc/grub.d/10_linux

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10

RUN curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
RUN apt update
RUN apt install -y kubelet runc containerd cri-tools
RUN dpkg -i /tmp/doca-repo.deb
RUN apt update
RUN apt upgrade -y
# RUN wget -qO - https://linux.mellanox.com/public/repo/doca/1.3.0/ubuntu20.04/aarch64/GPG-KEY-Mellanox.pub | sudo apt-key add -
# RUN echo "deb [trusted=yes] https://linux.mellanox.com/public/repo/doca/1.4.0-alpha/ubuntu22.04/\$(ARCH) ./" | tee /etc/apt/sources.list.d/doca.tmp.list
# RUN apt update || true
RUN apt install -y -f doca-runtime doca-tools doca-sdk || true
RUN apt remove -y --purge openipmi libopenipmi0 || true
RUN apt install -y libgdbm-dev; dpkg -i /var/doca-repo-aarch64-ubuntu2204-local/mlx-*openipmi*.deb || true
RUN cd /var/doca-repo-aarch64-ubuntu2204-local; for dr in *modules*deb; do dpkg -i $dr || true;done
RUN apt --fix-broken install -y || true
RUN dpkg -i /var/doca-repo-aarch64-ubuntu2204-local/bf-release_*arm64.deb || true
RUN apt remove --purge -y doca-repo-aarch64-ubuntu2204-local || true
RUN apt update || true
RUN /usr/sbin/dpkg-reconfigure bf-release || true
RUN mkdir -p /etc/kubelet.d
RUN mkdir -p /workspace
RUN dpkg -i /root/workspace/mlxbf-bootimages*.deb

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
RUN systemctl disable ModemManager.service || true

RUN /usr/sbin/update-pciids || true

RUN /bin/rm -f /var/lib/dbus/machine-id /etc/machine-id; touch /var/lib/dbus/machine-id /etc/machine-id

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

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "5.15.0-1003.28.ga8d758d-bluefield"]