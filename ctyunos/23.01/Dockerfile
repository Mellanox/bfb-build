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

ENV RUN_FW_UPDATER=no

RUN dnf update -y

RUN dnf install -y --disableexcludes=kubernetes \
	rpm-build rpm-sign automake meson cmake gcc gcc-c++  make autoconf m4 \
	bc bison flex pesign rsync patchutils git annobin intltool \
	groff kernel-rpm-macros libtool desktop-file-utils jq wget \
	systemd lm_sensors-sensord openssh-server acpid irqbalance unbound rasdaemon \
	cryptsetup lvm2 device-mapper-persistent-data ltrace lsof unzip sysstat nvme-cli \
	usbutils kexec-tools nfs-utils dracut-tools iproute-tc sudo parted passwd \
	network-scripts tcpdump NetworkManager NetworkManager-ovs NetworkManager-config-server glib2-devel\
	libarchive libreswan adobe-mappings-cmap-lang ImageMagick \
	perl perl-Fedora-VSP perl-generators sg3_utils \
	python3-Cython python3-sphinx python3-pyelftools python3-pip \
	python3 python3-devel elfutils-devel binutils binutils-devel pciutils pciutils-devel openssl-devel \
	libnl3 libnl3-devel selinux-policy-devel numactl-libs numactl-devel unbound-devel libpcap-devel tcl-devel \
	valgrind-devel iptables-devel libdb-devel libmnl libmnl-devel libcap-ng-devel systemd-devel \
	grub2-tools grub2 grubby grub2-tools-minimal grub2-efi-aa64 grub2-efi-aa64-modules grub2-common grub2-tools-extra shim \
	python-netifaces libreswan sg3_utils \
	device-mapper-persistent-data lvm2 acpid perf popt-devel bc edac-utils lm_sensors lm_sensors-sensord re2c ninja-build \
	cryptsetup rasdaemon watchdog kexec-tools jq libnghttp2 wget sudo uriparser \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.0.4-2.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.0.4-2.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.12.2-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/l/lcov-1.13-1.el7.noarch.rpm \
	https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/r/re2c-0.14.3-2.el7.aarch64.rpm \
	https://vault.centos.org/centos/8/BaseOS/aarch64/os/Packages/watchdog-5.15-2.el8.aarch64.rpm \
	https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/u/uriparser-0.9.7-1.el8.aarch64.rpm \
	https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/u/uriparser-devel-0.9.7-1.el8.aarch64.rpm

RUN dnf install -y dnf-plugins-core-4.0.17-1.ctl2.noarch

# Reinstall broken RPMs
RUN for ff in `rpm -qa`; do if ! (rpm --verify $ff > /dev/null 2>&1); then dnf reinstall --nogpgcheck -y $ff; fi; done

RUN dnf install -y kernel-5.10.0-136.12.0.88.ctl3.aarch64 kernel-devel-5.10.0-136.12.0.88.ctl3.aarch64

CMD ["/root/workspace/build_ctyunos_bfb"]
