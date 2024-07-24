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


distro="CentOS"
BDIR=$(dirname $0)

#
# Check PXE installation
#
if [ ! -e /tmp/bfpxe.done ]; then touch /tmp/bfpxe.done; bfpxe; fi

PART_SCHEME="SCHEME_A"

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
    default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -V | tail -1)"
fi
device=${device:-"$default_device"}
root_device=${device/\/dev\/}p3
ROOT_PARTITION=${device}p3

prepare_target_partitions()
{
	ilog "Installation target: $device"
	ilog "Preparing target partitions"
	SUPPORTED_SCHEMES="SCHEME_A SCHEME_B"
	if ! (echo "$SUPPORTED_SCHEMES" | grep -wq "$PART_SCHEME"); then
		echo "ERROR: Unsupported partition scheme: $PART_SCHEME"
		echo "Switching to SCHEME_A"
		PART_SCHEME="SCHEME_A"
	fi

	dd if=/dev/zero of=$device bs=512 count=1

	if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
		parted --script $device -- \
			mklabel gpt \
			mkpart primary 1MiB 201MiB set 1 esp on \
			mkpart primary 201MiB 1225MiB \
			mkpart primary 1225MiB 100%
	elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
		parted --script $device -- \
			mklabel gpt \
			mkpart primary 1MiB 201MiB set 1 esp on \
			mkpart primary 201MiB 8000MiB \
			mkpart primary 8000MiB 12489MiB \
			mkpart primary 12489MiB 100%
	fi

	sync

	partprobe "$device" > /dev/null 2>&1

	sleep 1
	blockdev --rereadpt "$device" > /dev/null 2>&1

	# Generate some entropy
	mke2fs  ${device}p2 >> /dev/null
}

mount_target_partition()
{
	ilog "Creating file systems:"
	(
	mkdosfs ${device}p1 -n system-boot
	mkfs.${ROOTFS} -f ${device}p2 -L local-boot
	mkfs.${ROOTFS} -f ${device}p3 -L writable
	) >> $LOG 2>&1
	if [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
		ilog "$(mkfs.${ROOTFS} -f ${device}p4)"
	fi
	sync
	sleep 1

	fsck.vfat -a ${device}p1

	if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
		mount ${device}p3 /mnt
		ROOT_PARTITION=${device}p3
		mkdir -p /mnt/boot
		mount ${device}p2 /mnt/boot
		mkdir -p /mnt/boot/efi
		mount ${device}p1 /mnt/boot/efi
	elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
		root_device=${device/\/dev\/}p2
		ROOT_PARTITION=${device}p2
		mount ${device}p2 /mnt
		mkdir -p /mnt/boot/efi
		mount ${device}p1 /mnt/boot/efi
		mkdir -p /mnt/var
		mount ${device}p4 /mnt/var
	fi
}

configure_target_os()
{
if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
	cat > /mnt/etc/fstab << EOF
${device}p3  /           ${ROOTFS}     defaults                   0 1
${device}p2  /boot       ${ROOTFS}     defaults                   0 2
${device}p1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
${device}p2  /           ${ROOTFS}     defaults                   0 1
${device}p3  /home       ${ROOTFS}     defaults                   0 2
${device}p4  /var        ${ROOTFS}     defaults                   0 2
${device}p1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
fi

	/bin/rm -f /mnt/etc/hostname

	# Enable NetworkManager for ifcfg-enp3s0f0s0 and ifcfg-enp3s0f1s0
	sed -i 's@NM_CONTROLLED="no"@NM_CONTROLLED="yes"@' /mnt/etc/sysconfig/network-scripts/ifcfg-enp3s0f0s0
	sed -i 's@NM_CONTROLLED="no"@NM_CONTROLLED="yes"@' /mnt/etc/sysconfig/network-scripts/ifcfg-enp3s0f1s0

	memtotal=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
	if [ $memtotal -gt 16000000 ]; then
		sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 1000000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
	fi

	cat > /mnt/etc/udev/rules.d/50-dev-root.rules << EOF
# If the system was booted without an initramfs, grubby
# will look for the symbolic link "/dev/root" to figure
# out the root file system block device.
SUBSYSTEM=="block", KERNEL=="$root_device", SYMLINK+="root"
EOF

	configure_snap

	chmod 600 /mnt/etc/ssh/*

	update_default_bfb

	# Disable SELINUX
	sed -i -e "s/^SELINUX=.*/SELINUX=disabled/" /mnt/etc/selinux/config
}

update_efi_bootmgr()
{
	ilog "Adding $distro boot entry:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	ilog "$(efibootmgr -c -d $device -p 1 -l '\EFI\centos\shimaa64.efi' -L $distro 2>&1)"

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_grub()
{
	ilog "Configure grub:"
	configure_default_grub

	/bin/rm -f /mnt/boot/vmlinux-*.bz2
	ilog "$(chroot /mnt grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg 2>&1)"
	ilog "$(chroot /mnt grub2-set-default 0)"
}

set_root_password()
{
	echo centos | chroot /mnt passwd root --stdin

	echo
	echo "ROOT PASSWORD is \"centos\""
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
