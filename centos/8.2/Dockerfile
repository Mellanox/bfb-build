from mellanox/bluefield:bfb_builder_centos8.2
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/

ENV RUN_FW_UPDATER=no

RUN sed -i 's|baseurl=http://vault.centos.org/|baseurl=https://mirror.nsc.liu.se/centos-store/|g' /etc/yum.repos.d/CentOS-*

RUN yum install -y \
		grub2-tools grub2 grubby grub2-tools-minimal grub2-efi-aa64 grub2-efi-aa64-modules grub2-common grub2-tools-extra \
		efibootmgr tcpdump nvme-cli rsync binutils sg3_utils libnl3 bison flex libmnl perl lsof \
		libreswan yum-utils python3-sphinx python3-pyelftools re2c dracut-tools unzip sysstat \
		device-mapper-persistent-data lvm2 acpid perf popt-devel bc lm_sensors lm_sensors-sensord \
		cryptsetup rasdaemon pciutils-devel watchdog kexec-tools jq python3-pip libnghttp2 wget \
		annobin kernel-rpm-macros iproute-tc network-scripts usbutils nfs-utils python3-six chkconfig

RUN echo -e "[kubernetes] \n\
name=Kubernetes \n\
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-aarch64 \n\
enabled=1 \n\
gpgcheck=1 \n\
gpgkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg \n\
exclude=kubelet kubeadm kubectl kubernetes-cni" > /etc/yum.repos.d/kubernetes.repo

RUN yum install -y --disableexcludes=kubernetes containerd.io kubelet-1.25.3-0.aarch64 cri-tools-1.25.0-0.aarch64 kubernetes-cni-1.1.1-0.aarch64

RUN yum-config-manager --nogpgcheck --add-repo https://download.fedoraproject.org/pub/epel/8/Everything/aarch64/; \
     yum install -y epel-release; \
     yum install -y --nogpgcheck uriparser
RUN yum install -y --enablerepo=PowerTools meson libnghttp2-devel

RUN yum-config-manager --nogpgcheck --add-repo $BASE_URL/doca/$DOCA_VERSION/centos8.2/aarch64/

RUN yum install --nogpgcheck -y doca-runtime doca-tools doca-sdk
RUN yum install --nogpgcheck -y mstflint
RUN /usr/sbin/update-pciids || true
RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "4.18.0-193.el8.aarch64"]
