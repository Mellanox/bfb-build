#  docker build -t bfb_runtime_ubuntu20.04 -f Dockerfile .
FROM scratch
ADD ubuntu-20.04-server-cloudimg-arm64-root.tar.xz /
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN apt update
RUN apt upgrade -y
RUN apt remove --purge -y snapd plymouth
RUN apt autoremove -y
RUN apt install -y watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad unzip sysstat mmc-utils uuid ntp jq libev4 conntrack wget
# Install ipmitool and ignore default OpenIPMI due to possible conflicts with mlx-openipmi (notice the - in openipmi-)
# Ref: https://serverfault.com/questions/250224/how-do-i-get-apt-get-to-ignore-some-dependencies
RUN apt install -y ipmitool openipmi-
RUN apt install -y docker.io; systemctl disable docker.service || true; systemctl disable docker.socket || true
RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y libpam-pwquality; echo "minlen = 8" >> /etc/security/pwquality.conf; echo "minclass = 3" >> /etc/security/pwquality.conf
RUN apt install -y python2.7 python3.8 python3-pyinotify

RUN apt update
RUN apt install -y grub-efi-arm64-signed grub-efi-arm64-bin shim-signed
RUN perl -ni -e 'print unless /focal-proposed/' /etc/apt/sources.list
RUN apt update

# Grub password
RUN echo 'set superusers="admin"' >> /etc/grub.d/40_custom; \
	echo 'password_pbkdf2 admin grub.pbkdf2.sha512.10000.5EB1FF92FDD89BDAF3395174282C77430656A6DBEC1F9289D5F5DAD17811AD0E2196D0E49B49EF31C21972669D180713E265BB2D1D4452B2EA9C7413C3471C53.F533423479EE7465785CC2C79B637BDF77004B5CC16C1DDE806BCEA50BF411DE04DFCCE42279E2E1F605459F1ABA3A0928CE9271F2C84E7FE7BF575DC22935B1' >> /etc/grub.d/40_custom; \
	sed -i -e "s@'gnulinux-simple-\$boot_device_id'@'gnulinux-simple-\$boot_device_id' --unrestricted@" \
	       -e "s@'gnulinux-\$version-\$type-\$boot_device_id'@'gnulinux-\$version-\$type-\$boot_device_id' --users ''@" /etc/grub.d/10_linux

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10

RUN mkdir -p -m 755 /etc/apt/keyrings/
RUN echo "deb [signed-by=/etc/apt/keyrings/kubernetes.asc] https://pkgs.k8s.io/core:/stable:/v1.25/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
RUN mkdir -p /etc/apt/keyrings/
ADD --chown=0:0 --chmod=644 https://prod-cdn.packages.k8s.io/repositories/isv:/kubernetes:/core:/stable:/v1.30/deb/Release.key /etc/apt/keyrings/kubernetes.asc
RUN apt update
# Install Libvirt+QEMU+KVM
RUN apt install -y bridge-utils cpu-checker libvirt-clients libvirt-daemon qemu qemu-kvm
RUN apt install -y kubelet=1.25.16-1.1 runc containerd cri-tools=1.26.0-1.1 kubernetes-cni=1.2.0-2.1
RUN apt-mark hold kubelet cri-tools kubernetes-cni
RUN wget -qO - $BASE_URL/doca/$DOCA_VERSION/ubuntu20.04/arm64-dpu/GPG-KEY-Mellanox.pub | sudo apt-key add -
RUN echo "deb [trusted=yes] ${BASE_URL}/doca/${DOCA_VERSION}/ubuntu20.04/arm64-dpu/ ./" | sudo tee /etc/apt/sources.list.d/doca.base.list
RUN apt update || true

RUN dpkg -i bootimages/mlxbf-bootimages.deb

RUN apt install -y -f \
    linux-bluefield=5.4.0.1105.101 \
    linux-bluefield-headers-5.4.0-1105=5.4.0-1105.112 \
    linux-bluefield-tools-5.4.0-1105=5.4.0-1105.112 \
    linux-headers-5.4.0-1105-bluefield=5.4.0-1105.112 \
    linux-headers-bluefield=5.4.0.1105.101 \
    linux-image-5.4.0-1105-bluefield=5.4.0-1105.112 \
    linux-image-bluefield=5.4.0.1105.101 \
    linux-libc-dev:arm64 \
    linux-modules-5.4.0-1105-bluefield=5.4.0-1105.112 \
    linux-tools-5.4.0-1105-bluefield=5.4.0-1105.112 \
    linux-tools-bluefield=5.4.0.1105.101 \
    linux-tools-common

RUN apt install -y -f doca-runtime doca-tools doca-sdk || true
RUN apt --fix-broken install -y || true
RUN apt-mark hold linux-tools-bluefield linux-image-bluefield linux-bluefield linux-headers-bluefield linux-image-bluefield linux-libc-dev linux-tools-common
RUN apt update || true
RUN /usr/sbin/dpkg-reconfigure bf-release || true
RUN mkdir -p /etc/kubelet.d
RUN mkdir -p /workspace
RUN /bin/rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf || true
RUN /bin/rm -f /etc/default/grub.d/50-cloudimg-settings.cfg || true

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

RUN /usr/sbin/update-pciids || true

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

CMD ["/root/workspace/create_bfb", "-k", "5.4.0-1105-bluefield"]
