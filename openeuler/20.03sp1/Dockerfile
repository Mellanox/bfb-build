from --platform=linux/arm64 openeuler/openeuler:20.03-lts-sp1
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

ENV RUN_FW_UPDATER=no

RUN dnf update -y --allowerasing --nobest

RUN dnf install -y --allowerasing --nobest --disableexcludes=kubernetes \
	rpm-build rpm-sign automake meson cmake gcc-c++ \
	bc bison flex pesign rsync patchutils git annobin intltool \
	groff kernel-rpm-macros libtool desktop-file-utils jq wget \
	systemd lm_sensors-sensord openssh-server acpid irqbalance unbound rasdaemon \
	cryptsetup lvm2 device-mapper-persistent-data ltrace lsof unzip sysstat nvme-cli \
	usbutils kexec-tools nfs-utils dracut-tools iproute-tc sudo parted passwd \
	network-scripts NetworkManager NetworkManager-ovs NetworkManager-config-server tcpdump \
	libarchive libreswan \
	perl-Fedora-VSP perl-generators \
	python3-Cython python3-sphinx python3-twisted python3-pyelftools \
	glib2-devel python3-devel elfutils-devel binutils-devel pciutils-devel openssl-devel \
	libnl3-devel selinux-policy-devel numactl-devel unbound-devel libpcap-devel tcl-devel \
	valgrind-devel iptables-devel libdb-devel libmnl-devel libcap-ng-devel systemd-devel \
	grubby grub2-efi-aa64 efibootmgr shim \
	https://linux.mellanox.com/public/repo/bluefield/4.7.0-13127/extras/addons/sshpass-1.09-1.oe2203.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.1.0-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.1.0-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.12.2-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/l/lcov-1.13-1.el7.noarch.rpm \
	https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/r/re2c-0.14.3-2.el7.aarch64.rpm \
	https://vault.centos.org/centos/8/BaseOS/aarch64/os/Packages/watchdog-5.15-2.el8.aarch64.rpm

RUN dnf install -y rpm-build rpm-sign automake meson cmake gcc-c++

RUN echo -e "[doca] \n\
name=Nvidia DOCA repository \n\
baseurl=$BASE_URL/doca/$DOCA_VERSION/${DISTRO}${DISTRO_VERSION}${DISTRO_KERNEL}/arm64-dpu/ \n\
gpgcheck=0 \n\
enabled=1" > /etc/yum.repos.d/doca.repo

RUN dnf install -y kernel-4.19.90-2109.1.0.0108.oe1.aarch64 kernel-devel-4.19.90-2109.1.0.0108.oe1.aarch64

RUN dnf install --nogpgcheck -y --exclude network-scripts-openvswitch doca-runtime doca-devel
RUN dnf install --nogpgcheck -y mstflint
RUN dnf install --nogpgcheck -y $MLNX_FW_UPDATER
RUN dnf install --nogpgcheck -y dpacc dpacc-extract dpa-compiler

RUN dnf install --nogpgcheck -y mmc-utils || dnf install --nogpgcheck -y $BASE_URL/bluefield/$BSP_VERSION/extras/mmc-utils/mmc-utils-0.1+git.20230209-1.1.aarch64.rpm || true

RUN /usr/sbin/update-pciids || true
RUN rpm -e --nodeps $(rpm -qa mlxbf-bootimages*)
RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/;s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "4.19.90-2109.1.0.0108.oe1.aarch64"]
