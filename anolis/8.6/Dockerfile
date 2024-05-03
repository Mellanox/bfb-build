from --platform=linux/arm64 openanolis/anolisos:8.6
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
ENV KVER=5.10.134-13.1.an8.aarch64

# Set releasever to 8.6
RUN echo 8.6 > /etc/dnf/vars/dockerreleasever
RUN sed -i -e "s/releasever/dockerreleasever/g" /etc/yum.repos.d/*repo

RUN dnf update -y
RUN dnf install -y epel-release

RUN echo -e "[Experimental] \n\
name=AnolisOS-8.6 - Experimental \n\
baseurl=http://mirrors.openanolis.cn/anolis/\$dockerreleasever/Experimental/\$basearch/os \n\
enabled=1 \n\
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-ANOLIS \n\
gpgcheck=1" > /etc/yum.repos.d/AnolisOS-Experimental.repo

RUN echo -e "[kubernetes-1.29] \n\
name=Kubernetes \n\
baseurl=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/ \n\
enabled=1 \n\
gpgcheck=1 \n\
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/repodata/repomd.xml.key" > /etc/yum.repos.d/kubernetes.repo

RUN dnf install -y --disableexcludes=kubernetes \
	rpm-build rpm-sign automake meson cmake gcc-c++ \
	bc bison flex pesign rsync patchutils git annobin intltool \
	groff kernel-rpm-macros libtool desktop-file-utils jq wget \
	systemd lm_sensors-sensord openssh-server acpid irqbalance unbound rasdaemon \
	cryptsetup lvm2 device-mapper-persistent-data ltrace lsof unzip sysstat nvme-cli \
	usbutils kexec-tools nfs-utils dracut-tools dracut-network dracut-squash iproute-tc sudo parted passwd \
	network-scripts NetworkManager NetworkManager-ovs NetworkManager-config-server tcpdump \
	libarchive libreswan rsyslog system-lsb-core time vim numactl libiscsi \
	perl-Fedora-VSP perl-generators edac-util dmidecode ipmitool \
	glib2-devel python3-devel elfutils-devel binutils-devel pciutils-devel openssl-devel \
	libnl3-devel selinux-policy-devel numactl-devel unbound-devel libpcap-devel tcl-devel \
	valgrind-devel iptables-devel libdb-devel libmnl-devel libcap-ng-devel systemd-devel \
	grubby grub2-efi-aa64 shim-aa64 efibootmgr re2c watchdog libmd libmd-devel libbsd libbsd-devel

RUN dnf install -y --disableexcludes=kubernetes \
    kubelet-1.29.3 kubernetes-cni-1.3.0 cri-tools
RUN dnf install -y rpm-build rpm-sign automake meson cmake gcc-c++

RUN echo -e "[doca] \n\
name=Nvidia DOCA repository \n\
baseurl=$BASE_URL/doca/$DOCA_VERSION/${DISTRO}${DISTRO_VERSION}${DISTRO_KERNEL}/arm64-dpu/ \n\
gpgcheck=0 \n\
enabled=1" > /etc/yum.repos.d/doca.repo

RUN dnf install -y kernel-$KVER kernel-modules-$KVER kernel-devel-$KVER kernel-core-$KVER kernel-modules-extra-$KVER
RUN dnf install -y openssl-1.1.1q openssl-devel-1.1.1q openssl-libs-1.1.1q openssl-perl-1.1.1q openssl-static-1.1.1q

RUN dnf install --nogpgcheck -y mstflint
RUN dnf install --nogpgcheck -y $MLNX_FW_UPDATER
RUN bash -c "rpm -e $(rpm -qa | grep openvswitch)" || true
RUN dnf install --nogpgcheck -y doca-runtime doca-devel
RUN dnf install --nogpgcheck -y dpacc dpacc-extract dpa-compiler

RUN dnf install --nogpgcheck -y mmc-utils || dnf install --nogpgcheck -y $BASE_URL/bluefield/$BSP_VERSION/extras/mmc-utils/mmc-utils-0.1+git.20230209-1.1.aarch64.rpm || true

RUN /usr/sbin/update-pciids || true
RUN rpm -e --nodeps $(rpm -qa mlxbf-bootimages*)
RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

# Manage services
RUN systemctl enable mlx_ipmid.service || true
RUN systemctl enable set_emu_param.service || true

CMD ["/root/workspace/create_bfb", "-k", "5.10.134-13.1.an8.aarch64"]
