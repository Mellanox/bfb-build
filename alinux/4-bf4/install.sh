#!/bin/bash

###############################################################################
#
# Copyright 2023 NVIDIA Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
###############################################################################

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/mellanox/scripts"

distro="Alinux"
BDIR=$(dirname $0)

#
# Check PXE installation
#
if [ ! -e /tmp/bfpxe.done ]; then touch /tmp/bfpxe.done; bfpxe; fi

ROOTFS=${ROOTFS:-"xfs"}

if [ -e ${BDIR}/install.env/common ]; then
	. ${BDIR}/install.env/common
else
	ilog "WARNING: ${BDIR}/install.env/common is missing"
fi

default_device=/dev/mmcblk0
if [ -b /dev/nvme0n1 ]; then
	default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -V | tail -1)"
fi
device=${device:-"$default_device"}
root_device=${device/\/dev\/}p3
ROOT_PARTITION=${device}p3

update_efi_bootmgr()
{
	ilog "Adding $distro boot entry:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	ilog "$(efibootmgr -c -d $device -p 1 -l '\EFI\alinux\shimaa64.efi' -L $distro 2>&1)"

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_grub()
{
	ilog "Configure grub:"
	configure_default_grub

	find /mnt/boot/loader/entries/ -type f -name "*.conf" -exec sed -i 's/\/boot//g' {} +
	ilog "$(chroot /mnt grub2-mkconfig -o /boot/efi/EFI/alinux/grub.cfg 2>&1)"
	if [[ ! -e /mnt/boot/efi/EFI/alinux/grubenv && -e /mnt/boot/grub2/grubenv ]]; then
		cp /mnt/boot/grub2/grubenv /mnt/boot/efi/EFI/alinux/
	fi

}

set_root_password()
{
	echo alinux | chroot /mnt passwd root --stdin

	echo
	echo "ROOT PASSWORD is \"alinux\""
	echo
}

# Alinux-only override of create_initramfs() from install.env/common.
# The shared version hardcodes SoC drivers (sdhci-of-dwcmshc, mlxbf_tmfifo) that
# the BF4 Alinux (cbp) kernel does not ship. dracut aborts on a missing
# requested module, leaving the installed system with a broken initramfs (no XFS
# root driver -> dracut emergency shell). This override (a) requests only
# drivers that exist for the target kernel and (b) forces the XFS root
# filesystem in. Defined after install.env/common is sourced, so this definition
# wins at call time; no other distro is affected.
create_initramfs()
{
	ilog "Build initramfs (Alinux):"
	kver=$(uname -r)
	if [ -d /mnt/lib/modules/$kver ]; then
	    kdir=/mnt/lib/modules/$kver
	else
	    kdir=$(/bin/ls -1d /mnt/lib/modules/6.* /mnt/lib/modules/5.* 2> /dev/null | head -n 1)
	fi
	if [ -n "$kdir" ]; then
	    kver=${kdir##*/}
	    DRACUT_CMD=$(chroot /mnt /bin/ls -1 /sbin/dracut /usr/bin/dracut 2> /dev/null | head -n 1 | tr -d '\n')
	    ilog "$(chroot /mnt grub2-set-default 0)"
	    initrd_drivers=""
	    for m in sdhci-of-dwcmshc dw_mmc-bluefield dw_mmc dw_mmc-pltfm mmc_block mlxbf_tmfifo gpio-mlxbf3 virtio_console nvme; do
	        if chroot /mnt modinfo -k "${kver}" "$m" > /dev/null 2>&1; then
	            initrd_drivers="${initrd_drivers} $m"
	        else
	            ilog "create_initramfs: skipping absent driver '$m' for kernel ${kver}"
	        fi
	    done
	    ilog "$(chroot /mnt env SYSTEMCTL=systemctl $DRACUT_CMD --kver ${kver} --force --filesystems xfs --add-drivers "${initrd_drivers}" /boot/initramfs-${kver}.img 2>&1)"
	else
	    kver=$(/bin/ls -1 /mnt/lib/modules/ | head -1)
	fi
}

global_installation_flow

save_log
sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
