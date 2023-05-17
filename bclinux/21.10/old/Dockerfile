from --platform=linux/arm64 bc-oe:21.10 
ADD qemu-aarch64-static /usr/bin/

WORKDIR /root/workspace
ADD install.sh .
ADD create_bfb .
ADD bootimages bootimages/ 
ADD build_bclinux_bfb .

ENV RUN_FW_UPDATER=no

