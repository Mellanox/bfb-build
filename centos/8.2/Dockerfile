from mellanox/bluefield:bfb_builder_centos8.2
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/

ENV RUN_FW_UPDATER=no

RUN yum install -y \
		grub2-tools grub2 grubby grub2-tools-minimal grub2-efi-aa64 grub2-efi-aa64-modules grub2-common grub2-tools-extra \
		efibootmgr tcpdump nvme-cli rsync binutils sg3_utils libnl3 bison flex libmnl perl lsof \
		libreswan yum-utils \
		device-mapper-persistent-data lvm2 acpid perf popt-devel bc lm_sensors lm_sensors-sensord \
		cryptsetup rasdaemon pciutils-devel watchdog kexec-tools jq python3-pip libnghttp2 wget \
		annobin kernel-rpm-macros iproute-tc network-scripts usbutils nfs-utils python3-six chkconfig

RUN yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo; \
    yum install -y --enablerepo=extras --nogpgcheck docker-ce docker-ce-cli container-selinux containerd.io; \
    systemctl enable docker

RUN yum-config-manager --nogpgcheck --add-repo https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/; \
     yum install -y epel-release; \
     yum install -y --nogpgcheck uriparser
RUN yum install -y --enablerepo=PowerTools meson libnghttp2-devel

RUN yum-config-manager --nogpgcheck --add-repo @NV_BASE_URL@/doca/@DOCA_VERSION@/centos8.2/aarch64/

RUN yum install --nogpgcheck -y doca-runtime doca-tools doca-sdk
RUN yum install --nogpgcheck -y mstflint

RUN /usr/sbin/update-pciids || true
RUN rpm -ihv --force /root/workspace/bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" -e "s/prod/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "4.18.0-193.el8.aarch64"]
