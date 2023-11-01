from mellanox/bluefield:bfb_builder_centos7.6
ADD qemu-aarch64-static /usr/bin/

ARG BASE_URL
ARG DOCA_VERSION
ARG BSP_VERSION
WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/
ADD parted-3.2-39.el7.aarch64.rpm .

ENV RUN_FW_UPDATER=no

RUN rpm -Uhv parted-3.2-39.el7.aarch64.rpm

RUN sed -i 's|baseurl=http://mirror.centos.org/altarch|baseurl=https://mirror1.hs-esslingen.de/pub/Mirrors/centos-altarch|g' /etc/yum.repos.d/CentOS-*
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

RUN echo -e "[kubernetes] \n\
name=Kubernetes \n\
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-aarch64 \n\
enabled=1 \n\
gpgcheck=1 \n\
gpgkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg \n\
exclude=kubelet kubeadm kubectl kubernetes-cni" > /etc/yum.repos.d/kubernetes.repo

RUN echo -e "[docker-ce-stable] \n\
name=Docker CE Stable - $basearch \n\
baseurl=https://download.docker.com/linux/centos/7/aarch64/stable \n\
enabled=1 \n\
gpgcheck=1 \n\
gpgkey=https://download.docker.com/linux/centos/gpg" > /etc/yum.repos.d/docker-ce.repo


RUN yum install -y --disableexcludes=kubernetes --enablerepo=extras containerd.io kubelet-1.25.3-0.aarch64 cri-tools-1.25.0-0.aarch64 kubernetes-cni-1.1.1-0.aarch64

RUN yum-config-manager --nogpgcheck --add-repo https://download.fedoraproject.org/pub/epel/7/aarch64/; \
     yum install -y epel-release; \
     yum install -y --nogpgcheck uriparser

RUN yum-config-manager --nogpgcheck --add-repo $BASE_URL/doca/$DOCA_VERSION/centos7.6/aarch64/

RUN yum install --nogpgcheck -y doca-runtime doca-tools doca-sdk
RUN /usr/sbin/update-pciids || true
RUN rpm -ihv --force bootimages/mlxbf-bootimages-*.aarch64.rpm || true

RUN sed -i -e "s/signed/@IMAGE_TYPE@@CUSTOM_VERSION@/" /etc/mlnx-release

CMD ["/root/workspace/create_bfb", "-k", "5.4.0-1074.2.g0c050d4-bluefield"]
