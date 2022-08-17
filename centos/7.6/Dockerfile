from mellanox/bluefield:bfb_builder_centos7.6
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD mlxbf-bootimages-3.9.2-12271.aarch64.rpm .
ADD parted-3.2-39.el7.aarch64.rpm .

ENV RUN_FW_UPDATER=no

RUN rpm -Uhv parted-3.2-39.el7.aarch64.rpm
RUN rpm -ihv mlxbf-bootimages-3.9.2-12271.aarch64.rpm

RUN yum install -y \
		--enablerepo=updates \
		NetworkManager \
		grub2-tools grub2 grubby grub2-tools-minimal grub2-efi-aa64 grub2-efi-aa64-modules grub2-common grub2-tools-extra \
		efibootmgr tcpdump nvme-cli rsync binutils sg3_utils libnl3 bison flex meson libmnl libnuma perl lsof \
		python-netifaces libreswan python36 python36-devel python36-idle python36-libs python36-test python36-tkinter python36-Cython \
		device-mapper-persistent-data lvm2 acpid perf popt-devel bc edac-utils lm_sensors lm_sensors-sensord re2c ninja-build \
		cryptsetup rasdaemon pciutils-devel watchdog python3-sphinx python36-six kexec-tools jq python3-pip libnghttp2 wget sudo

# Set python2.7 as a default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.8 1
RUN update-alternatives --install /usr/bin/python python /usr/bin/python2.7 10

RUN yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo; \
    yum install -y --enablerepo=extras --nogpgcheck docker-ce docker-ce-cli container-selinux containerd.io; \
    systemctl enable docker

RUN yum-config-manager --nogpgcheck --add-repo https://download-ib01.fedoraproject.org/pub/epel/7/aarch64/; \
     yum install -y epel-release; \
     yum install -y --nogpgcheck uriparser

RUN yum-config-manager --nogpgcheck --add-repo https://linux.mellanox.com/public/repo/doca/1.4.0/centos7.6/aarch64/

RUN yum install --nogpgcheck -y doca-runtime doca-tools doca-sdk

CMD ["/root/workspace/create_bfb", "-k", "5.4.0-1042.48.g040f5c3-bluefield"]
