#  docker build -t bfb_runtime_ubuntu22.04 -f Dockerfile .
FROM scratch
Add jammy-server-cloudimg-arm64-root.tar.xz /
Add doca-repo.deb /tmp/
ADD qemu-aarch64-static /usr/bin/
RUN mkdir -p /opt/mellanox/doca/services/
Add telemetry-agent /opt/mellanox/doca/services/telemetry
add blueman /opt/mellanox/doca/services/blueman
Add infrastructure /opt/mellanox/doca/services/infrastructure

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
ARG DISTRO
ARG DISTRO_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD build_ubuntu_bfb .
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
RUN apt install -y grub-efi-arm64-signed grub-efi-arm64-bin shim-signed watchdog binutils sbsigntool rasdaemon net-tools nfs-common iptables-persistent rsync tcpdump nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 bc lm-sensors ifenslave acpid network-manager kexec-tools i2c-tools dc lldpad unzip ipmitool sysstat mmc-utils libhugetlbfs-bin uuid ntp libgdbm-dev jq libev4
RUN apt install -y docker.io; systemctl disable docker.service || true; systemctl disable docker.socket || true
RUN apt install -y qemu-user-static qemu-utils qemu-user
RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y libpam-pwquality; echo "minlen = 8" >> /etc/security/pwquality.conf; echo "minclass = 3" >> /etc/security/pwquality.conf
RUN apt install -y python2.7 python3.10 python3-pyinotify

# Grub password
RUN echo 'set superusers="admin"' >> /etc/grub.d/40_custom; \
	echo 'password_pbkdf2 admin grub.pbkdf2.sha512.10000.5EB1FF92FDD89BDAF3395174282C77430656A6DBEC1F9289D5F5DAD17811AD0E2196D0E49B49EF31C21972669D180713E265BB2D1D4452B2EA9C7413C3471C53.F533423479EE7465785CC2C79B637BDF77004B5CC16C1DDE806BCEA50BF411DE04DFCCE42279E2E1F605459F1ABA3A0928CE9271F2C84E7FE7BF575DC22935B1' >> /etc/grub.d/40_custom; \
	sed -i -e "s@'gnulinux-simple-\$boot_device_id'@'gnulinux-simple-\$boot_device_id' --unrestricted@" \
	       -e "s@'gnulinux-\$version-\$type-\$boot_device_id'@'gnulinux-\$version-\$type-\$boot_device_id' --users ''@" /etc/grub.d/10_linux

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.10 1
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10

RUN wget -qO - $BASE_URL/doca/$DOCA_VERSION/ubuntu22.04/aarch64/GPG-KEY-Mellanox.pub | sudo apt-key add -
RUN wget -qO - https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/kubernetes-archive-keyring.gpg add -
RUN echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list
RUN apt update
# Install Libvirt+QEMU+KVM
RUN apt install -y bridge-utils cpu-checker libvirt-clients libvirt-daemon qemu qemu-kvm
RUN dpkg -i /tmp/doca-repo.deb
RUN apt update
RUN apt upgrade -y
RUN apt install -y containerd=1.7.2-0ubuntu1~22.04.1 runc
RUN apt install -y kubelet=1.25.3-00 cri-tools=1.25.0-00 kubernetes-cni=1.1.1-00
RUN apt-mark hold kubelet cri-tools kubernetes-cni
RUN dpkg -i /var/doca-dpu-repo-ubuntu2204-local/*mstflint*.deb || true
RUN apt-mark hold mstflint
RUN apt remove -y --purge $(dpkg --list "*openipmi*" | grep openipmi | awk '{print $2}') || true
RUN apt install -y -f doca-runtime doca-tools doca-sdk || true
RUN dpkg -i /var/doca-dpu-repo-ubuntu2204-local/mlxbf-gige-modules*.deb || true
RUN dpkg -i /var/doca-dpu-repo-ubuntu2204-local/mlx-*openipmi*.deb || true
RUN apt --fix-broken install -y || true
RUN dpkg -i /var/doca-dpu-repo-ubuntu2204-local/mlnx-snap_*arm64.deb || true
RUN dpkg -i /var/doca-dpu-repo-ubuntu2204-local/bf-release_*arm64.deb || true
RUN apt remove --purge -y doca-dpu-repo-ubuntu2204-local || true
RUN apt update || true
RUN /usr/sbin/dpkg-reconfigure bf-release || true
RUN apt clean
RUN rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/kubelet.d
RUN mkdir -p /workspace
RUN sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link
RUN dpkg -i --force-overwrite /root/workspace/mlxbf-bootimages*.deb

# Manage system services
RUN systemctl disable mlx-regex.service || true
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

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["bash", "-x", "/root/workspace/build_ubuntu_bfb"]
