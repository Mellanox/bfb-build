from --platform=linux/arm64 registry.openanolis.cn/openanolis/anolisos:8.6
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD mlxbf-bootimages-@VERSION@.aarch64.rpm .


ENV RUN_FW_UPDATER=no

RUN dnf install -y anolis-experimental-release epel-release "dnf-command(config-manager)" && \
	dnf config-manager --set-enabled PowerTools && \
	dnf config-manager --set-enabled Experimental && \
	sed -i 's#$releasever#8.6#' /etc/yum.repos.d/Anolis* && \
	dnf module enable -y ruby:3.0 && dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && \
	dnf install --enablerepo=BaseOS -y passwd dracut-network dracut-tools dracut-squash bc bison flex \
				pesign rsync re2c patchutils git annobin intltool dwarves groff \
				kernel-rpm-macros libtool rpm-build rpm-sign automake meson cmake \
				gcc-c++ cryptsetup ltrace lsof jq unzip sysstat nvme-cli uuid \
				lm_sensors lm_sensors-sensord systemd watchdog usbutils grub2-efi-aa64 \
				openssh-server acpid lvm2 efivar device-mapper-persistent-data linux-firmware \
				irqbalance libarchive libreswan kexec-tools nfs-utils dracut-tools rasdaemon \
				unbound iproute-tc network-scripts NetworkManager NetworkManager-ovs NetworkManager-config-server \
				tcpdump wget parted sudo efibootmgr grubby systemd-udev perl-Fedora-VSP perl-generators \
				python3-Cython python3-sphinx python3-twisted glib2-devel python36-devel elfutils-devel \
				binutils-devel pciutils-devel openssl-devel libnl3-devel selinux-policy-devel numactl-devel \
				unbound-devel libpcap-devel tcl-devel valgrind-devel iptables-devel libdb-devel libmnl-devel \
				dmidecode edac-utils ipmitool libiscsi libsysfs llvm-libs mstflint \
                                system-lsb-submod-security system-lsb-core \
				docker-ce docker-ce-cli container-selinux containerd.io

RUN dnf update -y

RUN dnf install -y kernel-5.10.134-13.an8 \
	kernel-core-5.10.134-13.an8 \
	kernel-devel-5.10.134-13.an8 \
	kernel-headers-5.10.134-13.an8 \
	kernel-modules-5.10.134-13.an8 \
	kernel-modules-extra-5.10.134-13.an8

RUN wget https://www.mellanox.com/downloads/ofed/MLNX_OFED-@MLNX_OFED_VERSION@/MLNX_OFED_SRC-@MLNX_OFED_VERSION@.tgz && \
    tar xzf MLNX_OFED_SRC-@MLNX_OFED_VERSION@.tgz && \
    cd MLNX_OFED_SRC-@MLNX_OFED_VERSION@ && \
    ./install.pl -k 5.10.134-13.an8.aarch64 --kernel-sources /lib/modules/5.10.134-13.an8.aarch64/build \
	--kernel-extra-args '--with-sf-cfg-drv --without-xdp --without-odp' \
	--kernel-only --build-only && cd ..  && \
find MLNX_OFED_SRC-@MLNX_OFED_VERSION@/RPMS -name '*rpm' -a ! -name '*debuginfo*rpm' -exec rpm -ihv '{}' \;

RUN cd /tmp && wget -r -np -nH --cut-dirs=3 -R "index.html*" https://linux.mellanox.com/public/repo/bluefield/@VERSION@/extras/SRPMS/
RUN mkdir -p /tmp/@VERSION@/extras/{SPECS,RPMS,SOURCES,BUILD} && \
    for p in /tmp/@VERSION@/extras/SRPMS/*.src.rpm; do rpmbuild --rebuild -D "debug_package %{nil}" -D "KVERSION 5.10.134-13.an8.aarch64" --define "_topdir /tmp/@VERSION@/extras" $p;done && \
     rpm -ivh --force /tmp/@VERSION@/extras/RPMS/aarch64/*.rpm

RUN dnf config-manager --add-repo https://linux.mellanox.com/public/repo/doca/2.0.2/rockylinux8.6/aarch64/ && \
	dnf install --nogpgcheck -y doca-runtime-user doca-tools doca-sdk-user mft kmod-kernel-mft-mlnx

RUN /usr/sbin/update-pciids || true
RUN rpm -ihv --force ${WORKDIR}/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/RockyLinux/@IMAGE_TYPE@_@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "5.10.134-13.an8.aarch64"]
