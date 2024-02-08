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

distro="RockyLinux"
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

if [ -e ${BDIR}/install.env/atf-uefi ]; then
	. ${BDIR}/install.env/atf-uefi
else
	ilog "WARNING: ATF/UEFI update environment is missing"
fi

if [ -e ${BDIR}/install.env/nic-fw ]; then
	. ${BDIR}/install.env/nic-fw
else
	ilog "WARNING: NIC FW update environment is missing"
fi

if [ -e ${BDIR}/install.env/bmc ]; then
	. ${BDIR}/install.env/bmc
else
	ilog "WARNING: BMC installation environment is missing"
fi

default_device=/dev/mmcblk0
if [ -b /dev/nvme0n1 ]; then
	default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -n | tail -1)"
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

	ilog "$(efibootmgr -c -d $device -p 1 -l '\EFI\rocky\grubaa64.efi' -L $distro 2>&1)"

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_grub()
{
	ilog "Configure grub:"
	configure_default_grub

	ilog "$(chroot /mnt grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg 2>&1)"
}

set_root_password()
{
	echo rocky | chroot /mnt passwd root --stdin

	echo
	echo "ROOT PASSWORD is \"rocky\""
	echo
}

global_installation_flow

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	reset_nic_firmware
fi

save_log
sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
