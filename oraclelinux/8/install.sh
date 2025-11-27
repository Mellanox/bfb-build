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

distro="OL"
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
	default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -V | tail -1)"
fi
device=${device:-"$default_device"}
root_device=${device/\/dev\/}p2
ROOT_PARTITION=/dev/${root_device}

prepare_target_partitions()
{
	ilog "Installation target: $device"
	ilog "Preparing target partitions"
	dd if=/dev/zero of=$device bs=512 count=1

	parted --script $device -- \
		mklabel gpt \
		mkpart primary 1MiB 201MiB set 1 esp on \
		mkpart primary 201MiB 100%

	sync

	partprobe "$device" > /dev/null 2>&1

	sleep 1
	blockdev --rereadpt "$device" > /dev/null 2>&1

	# Generate some entropy
	mke2fs -O 64bit -O extents -F ${device}p2

	ilog "Creating file systems:"
	(
	mkfs.fat -F32 -n system-boot ${device}p1
	mkfs.${ROOTFS} -f ${device}p2 -L writable
	) >> $LOG 2>&1
	sync
	sleep 1

	fsck.vfat -a ${device}p1

	if [ "${ROOTFS}" == "xfs" ]; then
		ilog "xfs_repair"
		ilog "$(xfs_repair -L ${device}p2 2>&1)"
	fi
}

mount_target_partition()
{
        ilog "Creating file systems:"
        (
        mkdosfs ${device}p1 -n "system-boot"
        mkfs.${ROOTFS} -F ${device}p2 -L "writable"
        ) >> $LOG 2>&1
        sync
        sleep 1

        fsck.vfat -a ${device}p1

        root_device=${device/\/dev\/}p2
        mkdir -p /mnt
        mount -t ${ROOTFS} ${device}p2 /mnt
        mkdir -p /mnt/boot/efi
        mount -t vfat ${device}p1 /mnt/boot/efi
}

get_part_id()
{
	local part_id=$1
	if [ -n "$(lsblk -o UUID ${part_id} 2> /dev/null | tail -1)" ]; then
		echo $(lsblk -o UUID -P ${part_id})
	elif [ -n "$(blkid -o value -s UUID ${part_id} 2> /dev/null)" ]; then
		echo "UUID=$(blkid -o value -s UUID ${part_id})"
	elif [ -n "$(lsblk -o PARTUUID ${part_id} 2> /dev/null | tail -1)" ]; then
		echo "PARTUUID=$(lsblk -o PARTUUID ${part_id} | tail -1)"
	else
		echo "${part_id}"
	fi
}

configure_target_os()
{
cat >> $LOG << EOF

############ configure_target_os BLK DEV INFO ###############
LSBLK:
$(lsblk -o NAME,LABEL,UUID,PARTUUID)

EOF

	if [ "${FSTAB_USE_DEV_NAME}" == "yes" ]; then
		cat > /mnt/etc/fstab << EOF
${device}p2  /           ${ROOTFS}     defaults                   0 1
${device}p1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
	else
		cat > /mnt/etc/fstab << EOF
$(get_part_id ${device}p2)  /           ${ROOTFS}     defaults                   0 1
$(get_part_id ${device}p1)  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
	fi

	/bin/rm -f /mnt/etc/hostname

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

# Disable SELINUX
sed -i -e "s/^SELINUX=.*/SELINUX=disabled/" /mnt/etc/selinux/config

chmod 600 /mnt/etc/ssh/*

# Enable NetworkManager for ifcfg-enp3s0f0s0 and ifcfg-enp3s0f1s0
sed -i 's@NM_CONTROLLED="no"@NM_CONTROLLED="yes"@' /mnt/etc/sysconfig/network-scripts/ifcfg-enp3s0f0s0
sed -i 's@NM_CONTROLLED="no"@NM_CONTROLLED="yes"@' /mnt/etc/sysconfig/network-scripts/ifcfg-enp3s0f1s0

if (lspci -n -d 15b3: | grep -wq 'a2dc'); then
	# BlueField-3 - remove mlnx-snap
	chroot /mnt rpm -e mlnx-snap || true
	packages_to_remove=$(chroot /mnt /bin/bash -c "/usr/bin/rpm -qf /lib/firmware/mellanox/{bmc,cec}/* 2>&1" | grep -viE "bf3-cec-fw|bf3-bmc-fw|bf3-bmc-gi|${dpu_part_number//_/-}" | tr -s '\n' ' ')
elif (lspci -n -d 15b3: | grep -wq 'a2df'); then
	# BlueField-4
	chroot /mnt rpm -e mlnx-snap mlnx-libsnap spdk || true
	packages_to_remove=$(chroot /mnt /bin/bash -c "/usr/bin/rpm -qf /lib/firmware/mellanox/{bmc,cec}/* 2>&1" | grep -E "bf2|bf3" | tr -s '\n' ' ')
fi

if [ -n "$packages_to_remove" ]; then
	ilog "Removing packages: $packages_to_remove"
	ilog "$(chroot /mnt bash -c "/usr/bin/yum remove -y $packages_to_remove" || true)"
fi
}

update_efi_bootmgr()
{
	ilog "Adding $distro boot entry:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	ilog "$(efibootmgr -c -d $device -p 1 -l '\EFI\redhat\shimaa64.efi' -L $distro)"

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_grub()
{
	ilog "Configure grub:"
cat >> $LOG << EOF

############ configure_grub BLK DEV INFO ###############
LSBLK:
$(lsblk -o NAME,LABEL,UUID,PARTUUID)

EOF

	# Then, set boot arguments: Read current 'console' and 'earlycon'
	# parameters, and append the root filesystem parameters.
	bootarg="$(cat /proc/cmdline | sed 's/initrd=initramfs//;s/console=.*//')"
	redfish_osarg="$(bfcfg --dump-osarg 2> /dev/null)"
	if [ -n "$redfish_osarg" ]; then
		bootarg="$bootarg $redfish_osarg"
	fi
	if (lscpu 2>&1 | grep -wq Grace); then
		sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"rw crashkernel=1024M $bootarg keep_bootcon earlycon modprobe.blacklist=mlx5_core,mlx5_ib selinux=0 net.ifnames=0 biosdevname=0 iommu.passthrough=1\"@" /mnt/etc/default/grub
	else
		sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"crashkernel=auto $bootarg console=hvc0 console=ttyAMA0 earlycon=pl011,0x01000000 net.ifnames=0 biosdevname=0 iommu.passthrough=1\"@" /mnt/etc/default/grub
	fi
	if (grep -q MLNXBF33 /sys/firmware/acpi/tables/SSDT*); then
		# BlueField-3
		sed -i -e "s/0x01000000/0x13010000/g" /mnt/etc/default/grub
	fi

	if (lspci -vv | grep -wq SimX); then
		# Remove earlycon from grub parameters on SimX
		sed -i -r -e 's/earlycon=[^ ]* //g' /mnt/etc/default/grub
	fi

	ilog "GRUB /etc/default/grub"
	ilog "$(cat /mnt/etc/default/grub)"

	/bin/rm -f /mnt/boot/vmlinux-*.bz2
	ilog "$(chroot /mnt /usr/sbin/grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg)"
	ilog "$(chroot /mnt grub2-set-default 0)"
	if [[ ! -e /mnt/boot/efi/EFI/redhat/grubenv && -e /mnt/boot/grub2/grubenv ]]; then
		cp /mnt/boot/grub2/grubenv /mnt/boot/efi/EFI/redhat/
	fi
}

create_initramfs()
{
	ilog "Build initramfs:"
	kver=$(uname -r)
	ilog "$(chroot /mnt dracut --kver ${kver} --force --force-drivers 'mlxbf_tmfifo mtd_blkdevs dw_mmc-bluefield dw_mmc dw_mmc-pltfm mmc_block virtio_net virtio_console sdhci dw_mmc-pltfm sdhci-of-dwcmshc xfs vfat nvme' /boot/initramfs-${kver}.img)"
}

set_root_password()
{
	echo oracle | chroot /mnt passwd root --stdin
	echo
	echo "ROOT PASSWORD is \"oracle\""
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
