from mellanox/bluefield:bfb_builder_bclinux7.6
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD install.bfb .
ADD mlxbf-bootimages-3.9.0-12175.aarch64.rpm .
ADD parted-3.2-39.el7.aarch64.rpm .
ADD license /etc/bclinux/license
ADD build_bclinux_bfb .

ENV RUN_FW_UPDATER=no

RUN rm -f /var/run/yum.pid
RUN rpm -Uhv parted-3.2-39.el7.aarch64.rpm
RUN rpm -ihv mlxbf-bootimages-3.9.0-12175.aarch64.rpm

CMD [ "/root/workspace/build_bclinux_bfb" ]
