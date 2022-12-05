#!/bin/bash

###############################################################################
#
# Copyright 2020 NVIDIA Corporation
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

rshimlog=`which bfrshlog 2> /dev/null`
distro="Debian"
NIC_FW_UPDATE_DONE=0

fspath=$(readlink -f `dirname $0`)

log()
{
	echo "$*"
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	fi
}

fw_update()
{
	FW_UPDATER=/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl
	FW_DIR=/opt/mellanox/mlnx-fw-updater/firmware/

	if [[ -x /mnt/${FW_UPDATER} && -d /mnt/${FW_DIR} ]]; then
		log "INFO: Updating NIC firmware..."
		chroot /mnt ${FW_UPDATER} \
			--force-fw-update \
			--fw-dir ${FW_DIR}
		if [ $? -eq 0 ]; then
			log "INFO: NIC firmware update done"
		else
			log "INFO: NIC firmware update failed"
		fi
	else
		log "WARNING: NIC Firmware files were not found"
	fi
}

fw_reset()
{
	mst start > /dev/null 2>&1 || true
	chroot /mnt /sbin/mlnx_bf_configure > /dev/null 2>&1

	MLXFWRESET_TIMEOUT=${MLXFWRESET_TIMEOUT:-180}
	SECONDS=0
	while ! (chroot /mnt mlxfwreset -d /dev/mst/mt*_pciconf0 q 2>&1 | grep -w "Driver is the owner" | grep -qw "\-Supported")
	do
		if [ $SECONDS -gt $MLXFWRESET_TIMEOUT ]; then
			log "INFO: NIC Firmware reset is not supported. Host power cycle is required"
			return
		fi
		sleep 1
	done

	msg=`chroot /mnt mlxfwreset -d /dev/mst/mt*_pciconf0 -y -l 3 --sync 1 r 2>&1`
	if [ $? -ne 0 ]; then
		log "INFO: NIC Firmware reset failed"
		log "INFO: $msg"
	else
		log "INFO: NIC Firmware reset done"
	fi
}

bind_partitions()
{
	mount --bind /proc /mnt/proc
	mount --bind /dev /mnt/dev
	mount --bind /sys /mnt/sys
}

unmount_partitions()
{
	umount /mnt/sys/fs/fuse/connections > /dev/null 2>&1 || true
	umount /mnt/sys > /dev/null 2>&1
	umount /mnt/dev > /dev/null 2>&1
	umount /mnt/proc > /dev/null 2>&1
	umount /mnt/boot/efi > /dev/null 2>&1
	umount /mnt > /dev/null 2>&1
}

#
# Set the Hardware Clock from the System Clock
#
hwclock -w

#
# Check auto configuration passed from boot-fifo
#
boot_fifo_path="/sys/bus/platform/devices/MLNXBF04:00/bootfifo"
if [ -e "${boot_fifo_path}" ]; then
	cfg_file=$(mktemp)
	# Get 16KB assuming it's big enough to hold the config file.
	dd if=${boot_fifo_path} of=${cfg_file} bs=4096 count=4 > /dev/null 2>&1

	#
	# Check the .xz signature {0xFD, '7', 'z', 'X', 'Z', 0x00} and extract the
	# config file from it. Then start decompression in the background.
	#
	offset=$(strings -a -t d ${cfg_file} | grep -m 1 "7zXZ" | awk '{print $1}')
	if [ -s "${cfg_file}" -a ."${offset}" != ."1" ]; then
		log "INFO: Found bf.cfg"
		cat ${cfg_file} | tr -d '\0' > /etc/bf.cfg
	fi
	rm -f $cfg_file
fi


#
# Check PXE installation
#
if [ ! -e /tmp/bfpxe.done ]; then touch /tmp/bfpxe.done; bfpxe; fi

if [ -e /etc/bf.cfg ]; then
	if ( bash -n /etc/bf.cfg ); then
		. /etc/bf.cfg
	else
		log "INFO: Invalid bf.cfg"
	fi
fi

if [ "X${DEBUG}" == "Xyes" ]; then
	log_output=/dev/kmsg
	if [ -n "$log_output" ]; then
		exec >$log_output 2>&1
		unset log_output
	fi
fi

function_exists()
{
	declare -f -F "$1" > /dev/null
	return $?
}

DHCP_CLASS_ID=${PXE_DHCP_CLASS_ID:-""}
DHCP_CLASS_ID_OOB=${DHCP_CLASS_ID_OOB:-"NVIDIA/BF/OOB"}
DHCP_CLASS_ID_DP=${DHCP_CLASS_ID_DP:-"NVIDIA/BF/DP"}
FACTORY_DEFAULT_DHCP_BEHAVIOR=${FACTORY_DEFAULT_DHCP_BEHAVIOR:-"true"}

if [ "${FACTORY_DEFAULT_DHCP_BEHAVIOR}" == "true" ]; then
	# Set factory defaults
	DHCP_CLASS_ID="NVIDIA/BF/PXE"
	DHCP_CLASS_ID_OOB="NVIDIA/BF/OOB"
	DHCP_CLASS_ID_DP="NVIDIA/BF/DP"
fi

log "INFO: $distro installation started"

device=${device:-/dev/mmcblk0}

# We cannot use wait-for-root as it expects the device to contain a
# known filesystem, which might not be the case here.
while [ ! -b $device ]; do
    log "Waiting for %s to be ready\n" "$device"
    sleep 1
done

# Flash image
bs=512
reserved=34
boot_size_megs=50
mega=$((2**20))
boot_size_bytes=$(($boot_size_megs * $mega))

disk_sectors=`fdisk -l $device | grep "Disk $device:" | awk '{print $7}'`
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
blockdev --rereadpt ${device} > /dev/null 2>&1

if function_exists bfb_pre_install; then
	log "INFO: Running bfb_pre_install from bf.cfg"
	bfb_pre_install
fi

# Generate some entropy
mke2fs  ${device}p2 >> /dev/null

mkdosfs ${device}p1 -n "system-boot"
mkfs.ext4 -F ${device}p2 -L "writable"

fsck.vfat -a ${device}p1

mkdir -p /mnt
mount -t ext4 ${device}p2 /mnt
mkdir -p /mnt/boot/efi
mount -t vfat ${device}p1 /mnt/boot/efi

echo "Extracting /..."
export EXTRACT_UNSAFE_SYMLINKS=1
tar Jxf $fspath/image.tar.xz --warning=no-timestamp -C /mnt
sync

cat > /mnt/etc/fstab << EOF
LABEL=writable / auto defaults 0 1
LABEL=system-boot  /boot/efi       vfat    umask=0077      0       2
EOF

if (grep -qE "MemTotal:\s+16" /proc/meminfo > /dev/null 2>&1); then
	sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 500000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
fi

bind_partitions
if (lspci -n -d 15b3: | grep -wq 'a2dc'); then
    # BlueField-3
    sed -i -e "s/0x01000000/0x13010000/g" /mnt/etc/default/grub
fi
chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-install ${device}
chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg
chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-set-default 0

vmlinuz=`cd /mnt/boot; /bin/ls -1 vmlinuz-* | tail -1`
initrd=`cd /mnt/boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//"`
ln -snf $vmlinuz /mnt/boot/vmlinuz
ln -snf $initrd /mnt/boot/initrd.img

cat > /mnt/etc/resolv.conf << EOF
nameserver 127.0.0.53
nameserver 192.168.100.1
options edns0
EOF

cat > /mnt/etc/hosts << EOF
127.0.0.1       localhost.localdomain   localhost
::1             localhost6.localdomain6 localhost6

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
EOF

cat > /mnt/etc/hostname << EOF
localhost.localdomain
EOF

echo "PasswordAuthentication yes" >> /mnt/etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /mnt/etc/ssh/sshd_config

chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service
chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service
chroot /mnt /bin/systemctl enable serial-getty@hvc0.service

if [ -x /usr/bin/uuidgen ]; then
	UUIDGEN=/usr/bin/uuidgen
else
	UUIDGEN=/mnt/usr/bin/uuidgen
fi

p0m0_uuid=`$UUIDGEN`
p1m0_uuid=`$UUIDGEN`
p0m0_mac=`echo ${p0m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/'`
p1m0_mac=`echo ${p1m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/'`

pciids=`lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}'`

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
if (lspci -n -d 15b3: | grep -wq 'a2d2'); then
	# BlueField-1
	ln -snf snap_rpc_init_bf1.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
	# OOB interface does not exist on BlueField-1
	/bin/rm -f /mnt/etc/network/interfaces.d/*oob_net0
elif (lspci -n -d 15b3: | grep -wq 'a2d6'); then
	# BlueField-2
	ln -snf snap_rpc_init_bf2.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
elif (lspci -n -d 15b3: | grep -wq 'a2dc'); then
	# BlueField-3
	chroot /mnt env PATH=$CHROOT_PATH apt remove -y --purge mlnx-snap || true
fi

	mkdir -p /mnt/etc/dhcp
	cat >> /mnt/etc/dhcp/dhclient.conf << EOF
send vendor-class-identifier "$DHCP_CLASS_ID_DP";
interface "oob_net0" {
  send vendor-class-identifier "$DHCP_CLASS_ID_OOB";
}
EOF

# Customisations per PSID
FLINT=""
if [ -x /usr/bin/flint ]; then
	FLINT=/usr/bin/flint
elif [ -x /usr/bin/mstflint ]; then
	FLINT=/usr/bin/mstflint
fi

if [ -x /usr/bin/mst ]; then
	/usr/bin/mst start > /dev/null 2>&1
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

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	if [ $NIC_FW_UPDATE_DONE -eq 0 ]; then
		fw_update
		NIC_FW_UPDATE_DONE=1
	fi
fi

if function_exists bfb_modify_os; then
	log "INFO: Running bfb_modify_os from bf.cfg"
	bfb_modify_os
fi

sync

unmount_partitions

blockdev --rereadpt ${device} > /dev/null 2>&1

fsck.vfat -a ${device}p1
sync

bfrec --bootctl --policy dual 2> /dev/null || true
if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
	bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap --policy dual
fi

if [ "X$ENROLL_KEYS" = "Xyes" ]; then
	bfrec --capsule /lib/firmware/mellanox/boot/capsule/EnrollKeysCap
fi

bfbootmgr --cleanall > /dev/null 2>&1

# Make it the boot partition
mount -t efivarfs none /sys/firmware/efi/efivars
/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1

if [ -x /usr/sbin/grub-install ]; then
	mount ${device}p2 /mnt/
	mount ${device}p1 /mnt/boot/efi/
	grub-install ${device}p1 --locale-directory=/mnt/usr/share/locale --efi-directory=/mnt/boot/efi/ --boot-directory=/mnt/boot/
	umount /mnt/boot/efi
	umount /mnt
else
	if efibootmgr | grep buster; then
		efibootmgr -b "$(efibootmgr | grep buster | cut -c 5-8)" -B
	fi
	efibootmgr -c -d "$device" -p 1 -L buster -l "\EFI\debian\grubaa64.efi"
fi


BFCFG=`which bfcfg 2> /dev/null`
if [ -n "$BFCFG" ]; then
	# Create PXE boot entries
	if [ -e /etc/bf.cfg ]; then
		mv /etc/bf.cfg /etc/bf.cfg.orig
	fi

	cat > /etc/bf.cfg << EOF
BOOT0=DISK
BOOT1=NET-NIC_P0-IPV4
BOOT2=NET-NIC_P0-IPV6
BOOT3=NET-NIC_P1-IPV4
BOOT4=NET-NIC_P1-IPV6
BOOT5=NET-OOB-IPV4
BOOT6=NET-OOB-IPV6
PXE_DHCP_CLASS_ID=$DHCP_CLASS_ID
EOF

	$BFCFG

	# Restore the original bf.cfg
	/bin/rm -f /etc/bf.cfg
	if [ -e /etc/bf.cfg.orig ]; then
		grep -v PXE_DHCP_CLASS_ID= /etc/bf.cfg.orig > /etc/bf.cfg
	fi
fi

umount /sys/firmware/efi/efivars || true

if [ -n "$BFCFG" ]; then
	$BFCFG
fi

if function_exists bfb_post_install; then
	log "INFO: Running bfb_post_install from bf.cfg"
	bfb_post_install
fi

log "INFO: Installation finished"

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	if [ $NIC_FW_UPDATE_DONE -eq 1 ]; then
		log "INFO: Running NIC Firmware reset"
		if [ "X$mode" == "Xmanufacturing" ]; then
			log "INFO: Rebooting..."
		fi
		# Wait for these messages to be pulled by the rshim service
		# as mlxfwreset will restart the DPU
		sleep 3
		# Reset NIC FW
		mount -t ext4 /dev/mmcblk0p2 /mnt
		bind_partitions
		fw_reset
		unmount_partitions
	fi
fi

echo
echo "ROOT PASSWORD is \"root\""
echo

sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
