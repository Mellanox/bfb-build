FROM debian:12
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
ARG DISTRO
ARG DISTRO_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD mlxbf-bootimages.deb .
ADD doca-repo.deb .
ADD debian.sources /etc/apt/sources.list.d/debian.sources
ADD docker.list /etc/apt/sources.list.d/docker.list
ADD kubernetes.list /etc/apt/sources.list.d/kubernetes.list

ENV DEBIAN_FRONTEND=noninteractive
ENV FLASH_KERNEL_SKIP=yes
ENV RUN_FW_UPDATER=no

# Avoid running flash-kernel post install
RUN mkdir -p /run/systemd; echo docker > /run/systemd/container

RUN apt update
RUN apt install -y logrotate e2fsprogs shim-signed shim-unsigned binutils nfs-common iptables-persistent i2c-tools lldpad sudo bsdmainutils

RUN apt install -y liblz4-tool rpm2cpio rpm libiscsi7 grub2-common vim-tiny vim openssh-server rsync systemd tcpdump wget parted irqbalance \
                 nvme-cli iputils-arping iputils-ping iputils-tracepath bridge-utils iperf3 locales software-properties-common dc \
                 net-tools libjs-jquery libjs-underscore acpid libpopt-dev bc flex bison dh-python debhelper pkg-config doxygen graphviz inkscape libpcap-dev \
                 libnuma-dev python3-sphinx python3-sphinx-rtd-theme python3-pip texlive-fonts-recommended texlive-latex-extra libcap-dev lm-sensors \
                 ninja-build meson re2c cryptsetup ifenslave equivs rasdaemon sbsigntool watchdog kexec-tools jq dwarves fdisk unzip libpci-dev libiberty-dev \
                 libdwarf-dev libperl-dev lzma-dev liblzma-dev libzstd-dev libdw-dev libunwind-dev libssl-dev binutils-dev asciidoc dkms default-jdk systemtap-sdt-dev \
                 sysstat mmc-utils bridge-utils cpu-checker libvirt-clients libvirt-daemon perl-modules hwdata libunbound8 libunwind8 usb.ids usbutils \
                 rsyslog runc containerd qemu-system-arm libssl-dev libudev-dev libnuma-dev python3-dev pkexec \
                 libselinux1-dev libmnl-dev pkg-config gcc cmake libnl-route-3-200 valgrind libdb-dev chrpath graphviz libelf-dev make pandoc libnl-route-3-dev \
                 libtool libglib2.0-dev libltdl-dev python3-docutils debhelper swig cython3 libsystemd-dev libnl-3-dev quilt libhugetlbfs-bin libaio1 efibootmgr gfortran \
                 python3-pyelftools cpio initramfs-tools dosfstools e2fsprogs ifupdown uuid-runtime network-manager efivar grub-efi-arm64 grub-efi-arm64-bin grub-efi-arm64-signed

RUN apt install -y python3-pip
RUN apt install -y build-essential
RUN apt install -y python3.11

RUN apt upgrade -y

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

RUN wget -qO - $BASE_URL/doca/$DOCA_VERSION/debian12/aarch64/GPG-KEY-Mellanox.pub | apt-key add -
RUN echo "deb [trusted=yes] $BASE_URL/doca/$DOCA_VERSION/debian12/\$(ARCH) ./" | tee /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true

RUN dpkg -i /root/workspace/doca-repo.deb
RUN apt update || true

RUN apt install -y -f --allow-downgrades \
        linux-image-6.1.0-11-arm64=6.1.38-4 \
        linux-headers-6.1.0-11-arm64=6.1.38-4
RUN apt install -y -f doca-runtime-user || true
RUN apt install -y -f doca-runtime-kernel || true
RUN apt install -y -f doca-sdk-user || true
RUN apt install -y -f doca-sdk-kernel || true
RUN apt install -y -f doca-tools || true
RUN cd /var/doca-dpu-repo-debian12-local; for dr in *modules*deb; do dpkg -i $dr || true;done
RUN apt --fix-broken install -y || true
RUN apt install -y mstflint || true
RUN apt install -y libvma libvma-dev libvma-utils || true
RUN apt install -y mlnx-libsnap mlnx-snap || true
RUN apt remove --purge -y doca-dpu-repo-debian12-local || true
RUN /bin/rm -f /etc/apt/sources.list.d/doca.tmp.list
RUN apt update || true
RUN /usr/sbin/dpkg-reconfigure bf-release || true
RUN apt clean
RUN rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/kubelet.d
RUN mkdir -p /workspace
RUN dpkg -i --force-overwrite /root/workspace/mlxbf-bootimages*.deb

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

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "6.1.0-11-arm64"]
