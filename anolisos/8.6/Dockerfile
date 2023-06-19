from --platform=linux/arm64 rockylinux:8.6.20227707
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD mlxbf-bootimages-3.9.3-12383.aarch64.rpm .

ENV RUN_FW_UPDATER=no

RUN dnf install -y epel-release "dnf-command(config-manager)" && \
	dnf config-manager --set-enabled powertools && \
	dnf module enable -y ruby:3.0 && dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo && \
	dnf install --enablerepo=baseos -y passwd dracut-network dracut-tools dracut-squash bc bison flex \
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
				dmidecode edac-utils ipmitool libiscsi libsysfs llvm-libs redhat-lsb-core redhat-lsb-submod-security \
				docker-ce docker-ce-cli container-selinux containerd.io

RUN dnf update -y

RUN dnf config-manager --nogpgcheck --add-repo https://linux.mellanox.com/public/repo/doca/1.5.1/rockylinux8.6/aarch64/

RUN dnf install -y kernel-4.18.0-372.26.1.el8_6 \
	kernel-core-4.18.0-372.26.1.el8_6 \
	kernel-cross-headers-4.18.0-372.26.1.el8_6 \
	kernel-devel-4.18.0-372.26.1.el8_6 \
	kernel-headers-4.18.0-372.26.1.el8_6 \
	kernel-modules-4.18.0-372.26.1.el8_6 \
	kernel-modules-extra-4.18.0-372.26.1.el8_6

RUN dnf install --nogpgcheck -y doca-runtime doca-tools doca-sdk

RUN /usr/sbin/update-pciids || true
RUN rpm -ihv --force mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "4.18.0-372.26.1.el8_6.aarch64"]
