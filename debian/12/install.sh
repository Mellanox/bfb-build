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
CHROOT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

distro="Debian"
BDIR=$(dirname $0)

#
# Check PXE installation
#
if [ ! -e /tmp/bfpxe.done ]; then touch /tmp/bfpxe.done; bfpxe; fi

ROOTFS=${ROOTFS:-"ext4"}

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
root_device=${device/\/dev\/}p2
ROOT_PARTITION=${device}p2

prepare_target_partitions()
{
	ilog "Installation target: $device"
	ilog "Preparing target partitions"

	# We cannot use wait-for-root as it expects the device to contain a
	# known filesystem, which might not be the case here.
	while [ ! -b $device ]; do
	    log "Waiting for $device to be ready\n"
	    sleep 1
	done

	# Flash image
	bs=512
	reserved=34
	boot_size_megs=50
	mega=$((2**20))
	boot_size_bytes=$(($boot_size_megs * $mega))

	disk_sectors=$(fdisk -l $device | grep "Disk $device:" | awk '{print $7}')
	disk_end=$((disk_sectors - reserved))

	boot_start=2048
	boot_size=$(($boot_size_bytes/$bs))
	root_start=$((2048 + $boot_size))
	root_end=$disk_end
	root_size=$(($root_end - $root_start + 1))

	dd if=/dev/zero of="$device" bs="$bs" count=1

	sfdisk -f "$device" << EOF
label: gpt
label-id: A2DF9E70-6329-4679-9C1F-1DAF38AE25AE
device: ${device}
unit: sectors
first-lba: $reserved
last-lba: $disk_end

${device}p1 : start=$boot_start, size=$boot_size, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=CEAEF8AC-B559-4D83-ACB1-A4F45B26E7F0, name="EFI System", bootable
${device}p2 : start=$root_start ,size=$root_size, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=F093FF4B-CC26-408F-81F5-FF2DD6AE139F, name="writable"
EOF

	sync

	# Refresh partition table
	sleep 1
	blockdev --rereadpt ${device} > /dev/null 2>&1

	# Generate some entropy
	mke2fs  ${device}p2 >> /dev/null
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

configure_target_os()
{
	cat > /mnt/etc/fstab << EOF
$(lsblk -o UUID -P ${device}p2) / ${ROOTFS} defaults 0 1
$(lsblk -o UUID -P ${device}p1) /boot/efi vfat umask=0077 0 2
EOF

	memtotal=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
	if [ $memtotal -gt 16000000 ]; then
		sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 1000000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
	fi

	configure_snap

	update_default_bfb

	# Disable SELINUX
	sed -i -e "s/^SELINUX=.*/SELINUX=disabled/" /mnt/etc/selinux/config

	/bin/rm -f /mnt/etc/hostname

	echo "PasswordAuthentication yes" >> /mnt/etc/ssh/sshd_config
	echo "PermitRootLogin yes" >> /mnt/etc/ssh/sshd_config

	cat > /mnt/etc/resolv.conf << EOF
nameserver 127.0.0.53
nameserver 192.168.100.1
options edns0
EOF
}

update_efi_bootmgr()
{
	ilog "Adding $distro boot entry:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	if efibootmgr | grep buster; then
		efibootmgr -b "$(efibootmgr | grep buster | cut -c 5-8)" -B
	fi
	ilog "$(efibootmgr -c -d $device -p 1 -L buster -l '\EFI\debian\shimaa64.efi')"

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_services()
{
	ilog "Configure Services:"
	chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service
	chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service
	chroot /mnt /bin/systemctl enable serial-getty@hvc0.service

	mkdir -p /mnt/etc/systemd/system/ssh.service.d/

	cat > /mnt/etc/systemd/system/ssh.service.d/regenerate-host-keys.conf <<EOF
[Service]
ExecStartPre=
ExecStartPre=-/usr/bin/ssh-keygen -A
ExecStartPre=/usr/sbin/sshd -t
EOF
}

configure_grub()
{
	ilog "Configure grub:"
	if (hexdump -C /sys/firmware/acpi/tables/SSDT* | grep -q MLNXBF33); then
	    # BlueField-3
	    sed -i -e "s/0x01000000/0x13010000/g" /mnt/etc/default/grub
	fi
	
	if (lspci -vv | grep -wq SimX); then
		# Remove earlycon from grub parameters on SimX
		sed -i -r -e 's/earlycon=[^ ]* //g' /mnt/etc/default/grub
	fi
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-install ${device})"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg)"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-set-default 0)"
	if [ -x /usr/sbin/grub-install ]; then
		mount ${device}p2 /mnt/
		mount ${device}p1 /mnt/boot/efi/
		ilog "$(grub-install ${device}p1 --locale-directory=/mnt/usr/share/locale --efi-directory=/mnt/boot/efi/ --boot-directory=/mnt/boot/)"
		umount /mnt/boot/efi
		umount /mnt
	fi
}

create_initramfs()
{
	ilog "Build initramfs:"
	vmlinuz=$(cd /mnt/boot; /bin/ls -1 vmlinuz-* | tail -1)
	initrd=$(cd /mnt/boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//")
	ln -snf $vmlinuz /mnt/boot/vmlinuz
	ln -snf $initrd /mnt/boot/initrd.img

	cat << EOF > /mnt/etc/initramfs-tools/modules
efivarfs
vfat
fat
msdos
nls_cp850
nls_cp437
nls_ascii
nsl_utf8
mlxbf-tmfifo
virtio_console
sbsa_gwdt
mlxbf-bootctl
sdhci-of-dwcmshc
nvme-rdma
nvme-tcp
nvme
EOF

	kver=$(uname -r)
	if [ ! -d /mnt/lib/modules/$kver ]; then
		kver=$(/bin/ls -1 /mnt/lib/modules/ |grep bf | head -1)
	fi
	ilog "$(chroot /mnt update-initramfs -k ${kver} -u)"
}

set_root_password()
{
	echo "root:debian" | chroot /mnt /usr/sbin/chpasswd

	echo
	echo "ROOT PASSWORD is \"debian\""
	echo
}

global_installation_flow
ilog $(fsck.${ROOTFS} -f -a -C0 ${device}p2 2>&1)

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	reset_nic_firmware
fi

save_log
sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
