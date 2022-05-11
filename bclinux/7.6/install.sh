#!/bin/bash

# Copyright (c) 2018, Mellanox Technologies
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/mellanox/scripts"

fspath=$(readlink -f `dirname $0`)

rshimlog=`which bfrshlog 2> /dev/null`
distro="BCLinux"

log()
{
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	else
		echo "$*"
	fi
}

# This function updates boot options. This cleans up the actual boot
# options and installs a new boot option.
function update_boot()
{

    # Update eMMC boot partitions. Update via either capsule
    # path or default path (i.e., mlxbf-bootctl). This command
    # MUST be executed after 'update_boot' and 'install_grub',
    # otherwise the newly created boot option would be either
    # cleaned up or unset from default option.
    bfrec --bootctl --policy dual 2> /dev/null || true
    if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
        bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap --policy dual
    fi
    sleep 3

    # Clean up actual boot entries.
    bfbootmgr --cleanall

    mount -t efivarfs none /sys/firmware/efi/efivars
    efibootmgr -c -d /dev/mmcblk0 -p 1 -l "\EFI\bclinux\shimaa64-bclinux.efi" -L $distro
    umount /sys/firmware/efi/efivars

	BFCFG=`which bfcfg 2> /dev/null`
	if [ -n "$BFCFG" ]; then
		$BFCFG
	fi
}

log "INFO: $distro installation started"

# Create the BCLinux partitions.
blkdev=/dev/mmcblk0
start_reserved=2048    # sectors required for label before first partition
end_reserved=34        # sectors required after last partition

disk_size=`fdisk -l $blkdev | grep "Disk $blkdev:" | awk '{print $5}'`
disk_sectors=`fdisk -l $blkdev | grep "Disk $blkdev:" | awk '{print $7}'`
disk_size=$((disk_size / 1024 / 1024))
disk_start=$start_reserved

PART_SCHEME="SCHEME_A"
if [ -e /etc/bf.cfg ]; then
	. /etc/bf.cfg
fi

SUPPORTED_SCHEMES="SCHEME_A SCHEME_B"
if ! (echo "$SUPPORTED_SCHEMES" | grep -wq "$PART_SCHEME"); then
	echo "ERROR: Unsupported partition scheme: $PART_SCHEME"
	echo "Switching to SCHEME_A"
	PART_SCHEME="SCHEME_A"
fi

if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
	root_start=2508800
	root_end=$((disk_sectors - end_reserved))
	root_sectors=$((root_end - root_start))
	disk_end=$root_end

cat > /tmp/disk.sfdisk << EOF
label: gpt
label-id: 311E8873-97B3-4DCF-B678-CA3FCF3B59AC
device: $blkdev
unit: sectors
first-lba: 34
last-lba: $disk_end

/dev/mmcblk0p1 : start=2048, size=409600, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=03E5CAD3-CE36-4ACE-A999-710E70651E06, name="EFI System Partition", bootable
/dev/mmcblk0p2 : start=411648, size=2097152, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=2CE0975D-0242-449D-A53C-953EE466DC5E
/dev/mmcblk0p3 : start=$root_start, size=$root_sectors, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=BE5491C2-2101-4006-B217-952DB2763B25
EOF
elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	root_start=411648
	root_sectors=10485760 # 5GB
	root_end=$((root_start + root_sectors - 1))
	home_start=$((root_end + 1))
	home_sectors=14680064 # 7GB
	home_end=$((home_start + home_sectors - 1))
	var_start=$((home_end + 1))
	var_end=$((disk_sectors - end_reserved))
	var_sectors=$((var_end - var_start))
	disk_end=$var_end

cat > /tmp/disk.sfdisk << EOF
label: gpt
label-id: 311E8873-97B3-4DCF-B678-CA3FCF3B59AC
device: $blkdev
unit: sectors
first-lba: 34
last-lba: $disk_end

/dev/mmcblk0p1 : start=2048, size=409600, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=03E5CAD3-CE36-4ACE-A999-710E70651E06, name="EFI System Partition", bootable
/dev/mmcblk0p2 : start=$root_start, size=$root_sectors, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=BE5491C2-2101-4006-B217-952DB2763B25
/dev/mmcblk0p3 : start=$home_start, size=$home_sectors, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=69A71056-7625-45D9-A816-3A038DAD40E1
/dev/mmcblk0p4 : start=$var_start, size=$var_sectors, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, uuid=CCEFAE99-75AB-475A-939F-CFBD9A9E9747
EOF
fi

dd if=/dev/zero of=$blkdev bs=512 count=1

sfdisk -f $blkdev < /tmp/disk.sfdisk

sync

blockdev --rereadpt "$blkdev" > /dev/null 2>&1

# Generate some entropy
mke2fs  /dev/mmcblk0p2 >> /dev/null

# Copy the kernel image.
mkdosfs /dev/mmcblk0p1
mkfs.xfs -f /dev/mmcblk0p2
mkfs.xfs -f /dev/mmcblk0p3
if [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	mkfs.xfs -f /dev/mmcblk0p4
fi

export EXTRACT_UNSAFE_SYMLINKS=1

fsck.vfat -a /dev/mmcblk0p1

root="mmcblk0p3"
if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
	mount /dev/mmcblk0p3 /mnt
	mkdir -p /mnt/boot
	mount /dev/mmcblk0p2 /mnt/boot
	mkdir -p /mnt/boot/efi
	mount /dev/mmcblk0p1 /mnt/boot/efi
elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	root="mmcblk0p2"
	mount /dev/mmcblk0p2 /mnt
	mkdir -p /mnt/boot/efi
	mount /dev/mmcblk0p1 /mnt/boot/efi
	mkdir -p /mnt/var
	mount /dev/mmcblk0p4 /mnt/var
fi

echo "Extracting /..."
tar Jxf $fspath/image.tar.xz --warning=no-timestamp -C /mnt
sync

cd /dev/disk/by-uuid
for uuid in *
do
	case `readlink -f $uuid` in
		*mmcblk0p1)
			UUID1=$uuid
			;;
		*mmcblk0p2)
			UUID2=$uuid
			;;
		*mmcblk0p3)
			UUID3=$uuid
			;;
		*mmcblk0p4)
			UUID4=$uuid
			;;
	esac
done
cd -

if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
	cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
UUID=$UUID3  /           xfs     defaults                   0 1
UUID=$UUID2  /boot       xfs     defaults                   0 2
UUID=$UUID1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
UUID=$UUID2  /           xfs     defaults                   0 1
UUID=$UUID3  /home       xfs     defaults                   0 1
UUID=$UUID4  /var        xfs     defaults                   0 1
UUID=$UUID1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
fi

if (grep -qE "MemTotal:\s+16" /proc/meminfo > /dev/null 2>&1); then
	sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 500000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
fi

cat > /mnt/etc/udev/rules.d/50-dev-root.rules << EOF
# If the system was booted without an initramfs, grubby
# will look for the symbolic link "/dev/root" to figure
# out the root file system block device.
SUBSYSTEM=="block", KERNEL=="$root", SYMLINK+="root"
EOF

if [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	sed -r -i -e "s@(^LOG_DIR=).*@\1/home/snap/log@" /mnt/usr/bin/rotate_nvme_snap_logs.sh
	sed -i -e "s@^\$outchannel@# \$outchannel@" /mnt/etc/rsyslog.d/nvme_snap_logs.conf
	sed -i -e "s@^## \$outchannel@\$outchannel@" /mnt/etc/rsyslog.d/nvme_snap_logs.conf
fi

# Update default.bfb
bfb_location=/lib/firmware/mellanox/default.bfb

if [ -f "$bfb_location" ]; then
	/bin/rm -f /mnt/lib/firmware/mellanox/boot/default.bfb
	cp $bfb_location /mnt/lib/firmware/mellanox/boot/default.bfb
fi

# Disable SELINUX
sed -i -e "s/^SELINUX=.*/SELINUX=disabled/" /mnt/etc/selinux/config

chmod 600 /mnt/etc/ssh/*

# Disable Firewall services
/bin/rm -f /mnt/etc/systemd/system/multi-user.target.wants/firewalld.service
/bin/rm -f /mnt/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service

mount --bind /proc /mnt/proc
mount --bind /dev /mnt/dev
mount --bind /sys /mnt/sys

/bin/rm -f /mnt/boot/vmlinux-*.bz2

# Then, set boot arguments: Read current 'console' and 'earlycon'
# parameters, and append the root filesystem parameters.
bootarg="$(cat /proc/cmdline | sed 's/initrd=initramfs//;s/console=.*//')"
sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"crashkernel=auto $bootarg console=hvc0 console=ttyAMA0 earlycon=pl011,0x01000000 modprobe.blacklist=mlx5_core,mlx5_ib\"@" /mnt/etc/default/grub

chroot /mnt grub2-mkconfig -o /boot/efi/EFI/bclinux/grub.cfg

kdir=$(/bin/ls -1d /mnt/lib/modules/4.18* /mnt/lib/modules/4.19* /mnt/lib/modules/4.20* /mnt/lib/modules/5.4* 2> /dev/null)
kver=""
if [ -n "$kdir" ]; then
	kver=${kdir##*/}
	chroot /mnt grub2-set-default 0
else
	kver=$(/bin/ls -1 /mnt/lib/modules/ | head -1)
fi

chroot /mnt /usr/bin/mkinitrd --force --with=xfs --with=dw_mmc-bluefield --with=dw_mmc-pltfm --with=dw_mmc --with=mtd_blkdevs --with=mmc_block --with=mlxbf_gige --with=mlxbf-tmfifo --with=mlx5_ib /boot/initramfs-${kver}.img $kver

echo bclinux | chroot /mnt passwd root --stdin

if [ `wc -l /mnt/etc/hostname | cut -d ' ' -f 1` -eq 0 ]; then
	echo "localhost" > /mnt/etc/hostname
fi

cat > /mnt/etc/resolv.conf << EOF
nameserver 192.168.100.1
EOF

chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service
chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service
chroot /mnt /bin/systemctl enable serial-getty@hvc0.service
chroot /mnt /bin/systemctl enable openvswitch.service

if [ -x /usr/bin/uuidgen ]; then
	UUIDGEN=/usr/bin/uuidgen
else
	UUIDGEN=/mnt/usr/bin/uuidgen
fi

p0m0_uuid=`$UUIDGEN`
p1m0_uuid=`$UUIDGEN`
p0m0_mac=`echo ${p0m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/'`
p1m0_mac=`echo ${p1m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/'`

pciids=`/usr/sbin/lspci -nD -d 15b3:a2d2 2> /dev/null | awk '{print $1}'`
if [ ! -n "$pciids" ]; then
	pciids=`/usr/sbin/lspci -nD -d 15b3:a2d6 2> /dev/null | awk '{print $1}'`
fi

mkdir -p /mnt/etc/mellanox
echo > /mnt/etc/mellanox/mlnx-sf.conf

i=0
for pciid in $pciids
do
	uuid_iname=p${i}m0_uuid
	mac_iname=p${i}m0_mac
cat >> /mnt/etc/mellanox/mlnx-sf.conf << EOF
/sbin/mlnx-sf --action create --device $pciid --sfnum 0 --hwaddr ${!mac_iname}
EOF
	let i=i+1
done

# Update HW-dependant files
if (/usr/sbin/lspci -n -d 15b3: | grep -wq 'a2d2'); then
	# BlueField-1
	ln -snf snap_rpc_init_bf1.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
	# OOB interface does not exist on BlueField-1
	/bin/rm -f /mnt/etc/sysconfig/network-scripts/ifcfg-oob_net0
elif (/usr/sbin/lspci -n -d 15b3: | grep -wq 'a2d6'); then
	# BlueField-2
	ln -snf snap_rpc_init_bf2.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
fi

# Customisations per PSID
FLINT=""
if [ -x /usr/bin/mstflint ]; then
	FLINT=/usr/bin/mstflint
elif [ -x /usr/bin/flint ]; then
	FLINT=/usr/bin/flint
elif [ -x /mnt/usr/bin/mstflint ]; then
	FLINT=/mnt/usr/bin/mstflint
fi

pciid=`echo $pciids | awk '{print $1}' | head -1`
if [ -e /mnt/usr/sbin/mlnx_snap_check_emulation.sh ]; then
	sed -r -i -e "s@(NVME_SF_ECPF_DEV=).*@\1${pciid}@" /mnt/usr/sbin/mlnx_snap_check_emulation.sh
fi
if [ -n "$FLINT" ]; then
	PSID=`$FLINT -d $pciid q | grep PSID | awk '{print $NF}'`

	case "${PSID}" in
		MT_0000000634)
		sed -r -i -e 's@(EXTRA_ARGS=).*@\1"--mem-size 1200"@' /mnt/etc/default/mlnx_snap
		;;
	esac
fi

# Clean up logs
echo > /mnt/var/log/messages
echo > /mnt/var/log/maillog
echo > /mnt/var/log/secure
echo > /mnt/var/log/firewalld
echo > /mnt/var/log/audit/audit.log
/bin/rm -f /mnt/var/log/yum.log
/bin/rm -rf /mnt/tmp/*

sync

chroot /mnt umount /boot/efi
if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
	chroot /mnt umount /boot
fi
umount /mnt/sys
umount /mnt/dev
umount /mnt/proc
if [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	umount /mnt/var
	umount /mnt/home
fi
umount /mnt

sync

# Update the firmware and boot the current kernel image.
update_boot

echo
echo "ROOT PASSWORD is \"bclinux\""
echo

log "INFO: Installation finished"
log "INFO: Rebooting..."
