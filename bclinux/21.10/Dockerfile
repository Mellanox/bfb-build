from --platform=linux/arm64 bc-oe:21.10
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/
ADD build_bclinux_bfb .

ENV RUN_FW_UPDATER=no

RUN dnf update -y
RUN dnf install dnf-plugins-core -y

RUN yum-config-manager --nogpgcheck --add-repo https://mirrors.cmecloud.cn/bclinux/oe21.10U3/everything/aarch64
RUN yum-config-manager --nogpgcheck --add-repo https://mirrors.cmecloud.cn/bclinux/oe21.10/kernel-oe/aarch64

RUN dnf reinstall crypto-policies -y

RUN dnf install -y \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-1.0.4-2.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libmd-devel-1.0.4-2.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-devel-0.11.7-2.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/l/libbsd-0.11.7-2.el8.aarch64.rpm \
        https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/l/lcov-1.13-1.el7.noarch.rpm \
        https://download.fedoraproject.org/pub/epel/7/aarch64/Packages/r/re2c-0.14.3-2.el7.aarch64.rpm \
        https://vault.centos.org/centos/8/BaseOS/aarch64/os/Packages/watchdog-5.15-2.el8.aarch64.rpm \
        https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/u/uriparser-0.9.7-1.el8.aarch64.rpm \
        https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/u/uriparser-devel-0.9.7-1.el8.aarch64.rpm \
        https://mirrors.cmecloud.cn/bclinux/oe21.10U3/everything/aarch64/Packages/libreswan-4.1-2.oe1.aarch64.rpm  \
        https://mirrors.cmecloud.cn/bclinux/oe21.10U3/everything/aarch64/Packages/openssl-devel-1.1.1f-13.oe1.aarch64.rpm \
        https://mirrors.cmecloud.cn/bclinux/oe21.10U3/everything/aarch64/Packages/openssl-1.1.1f-13.oe1.aarch64.rpm \
        https://mirrors.cmecloud.cn/bclinux/oe21.10U3/everything/aarch64/Packages/efi-filesystem-4-4.oe1.bclinux.noarch.rpm \
        https://mirrors.cmecloud.cn/bclinux/oe21.10U3/everything/aarch64/Packages/ninja-build-1.8.2-8.oe1.aarch64.rpm

RUN dnf install -y --disableexcludes=kubernetes \
        rpm-build rpm-sign automake cmake gcc-c++ \
        bc bison flex pesign rsync patchutils git annobin intltool \
        groff kernel-rpm-macros libtool desktop-file-utils jq wget \
        systemd lm_sensors-sensord openssh-server acpid irqbalance unbound rasdaemon \
        cryptsetup lvm2 device-mapper-persistent-data ltrace lsof unzip sysstat nvme-cli \
        usbutils kexec-tools nfs-utils dracut-tools iproute-tc sudo parted passwd \
        network-scripts tcpdump NetworkManager NetworkManager-ovs NetworkManager-config-server glib2-devel\
        libarchive adobe-mappings-cmap-lang ImageMagick \
        perl-Fedora-VSP perl-generators \
        python3-Cython python3-sphinx python3-pyelftools \
        python3 python3-devel elfutils-devel binutils-devel pciutils-devel \
        libnl3-devel selinux-policy-devel numactl-devel unbound-devel libpcap-devel tcl-devel \
        valgrind-devel iptables-devel libdb-devel libmnl-devel libcap-ng-devel systemd-devel \
        binutils sg3_utils libnl3 libmnl perl \
        python-netifaces numactl perf popt-devel  edac-utils lm_sensors  \
        grub2-tools grubby grub2-tools-minimal grub2-common \
        rsync bison flex grub2-tools-extra \
        device-mapper-persistent-data lvm2 acpid bc lm_sensors-sensord \
        cryptsetup rasdaemon pciutils-devel kexec-tools jq \
        python3-pip libnghttp2 wget tar rpm-build python2 python2-devel \
        shim grub2 grub2-efi-aa64 grub2-efi-aa64-modules efibootmgr \
        autoconf ethtool gdb-headless make pciutils python3-devel gcc patch 

# RUN dnf install -y kernel-4.19.90-2211.6.0.0179.oe1.aarch64 kernel-devel-4.19.90-2211.6.0.0179.oe1.aarch64
RUN dnf install -y kernel-4.19.90-2304.4.0.0198.oe1.aarch64 kernel-devel-4.19.90-2304.4.0.0198.oe1.aarch64

# Reinstall broken RPMs
RUN for ff in `rpm -qa`; do if ! (rpm --verify $ff > /dev/null 2>&1); then dnf reinstall --nogpgcheck -y $ff; fi; done

CMD ["/root/workspace/build_bclinux_bfb"]
