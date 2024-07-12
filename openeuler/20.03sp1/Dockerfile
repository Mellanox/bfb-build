from --platform=linux/arm64 openeuler/openeuler:20.03-lts-sp1
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/

ENV RUN_FW_UPDATER=no

RUN dnf update -y --nobest

RUN dnf install -y --nobest --disableexcludes=kubernetes \
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
	grubby grub2-efi-aa64 efibootmgr \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.1.0-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.1.0-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.12.2-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.12.2-1.el8.aarch64.rpm \
	https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/l/lcov-1.13-1.el7.noarch.rpm \
	https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/r/re2c-0.14.3-2.el7.aarch64.rpm \
	https://vault.centos.org/centos/8/BaseOS/aarch64/os/Packages/watchdog-5.15-2.el8.aarch64.rpm

RUN dnf install -y --nobest rpm-build rpm-sign automake meson cmake gcc-c++

RUN echo -e "[kubernetes] \n\
name=Kubernetes  \n\
baseurl=https://pkgs.k8s.io/core:/stable:/v1.25/rpm/ \n\
enabled=1 \n\
gpgcheck=1 \n\
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.25/rpm/repodata/repomd.xml.key \n\
exclude=kubelet kubeadm kubectl" > /etc/yum.repos.d/kubernetes.repo

RUN echo -e "[docker-ce-stable] \n\
name=Docker CE Stable - \$basearch \n\
baseurl=https://download.docker.com/linux/centos/8/\$basearch/stable \n\
enabled=1 \n\
gpgcheck=1 \n\
gpgkey=https://download.docker.com/linux/centos/gpg" > /etc/yum.repos.d/docker-ce.repo

RUN dnf install -y --disableexcludes=kubernetes containerd.io kubelet-1.25.16-150500.1.1.aarch64 cri-tools-1.26.0-150500.1.1.aarch64 kubernetes-cni-1.2.0-150500.2.1.aarch64

RUN echo -e "[doca] \n\
name=Nvidia DOCA repository \n\
baseurl=$BASE_URL/doca/$DOCA_VERSION/openeuler20.03sp1/aarch64/ \n\
gpgcheck=0 \n\
enabled=1" > /etc/yum.repos.d/doca.repo

RUN dnf install -y --nobest kernel-4.19.90-2109.1.0.0108.oe1.aarch64 kernel-devel-4.19.90-2109.1.0.0108.oe1.aarch64

RUN dnf install --nogpgcheck --nobest --exclude network-scripts-openvswitch -y doca-runtime doca-tools doca-sdk
RUN dnf install --nogpgcheck --nobest -y mstflint

RUN /usr/sbin/update-pciids || true
RUN rpm -e --nodeps $(rpm -qa mlxbf-bootimages*)
RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "4.19.90-2109.1.0.0108.oe1.aarch64"]
