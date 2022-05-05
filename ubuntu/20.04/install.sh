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
distro="Ubuntu"

log()
{
	echo "$*"
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	fi
}

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

DUAL_BOOT="no"
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

log "INFO: $distro installation started"

device=/dev/mmcblk0

echo 0 > /proc/sys/kernel/hung_task_timeout_secs

# We cannot use wait-for-root as it expects the device to contain a
# known filesystem, which might not be the case here.
while [ ! -b $device ]; do
    log "Waiting for %s to be ready\n" "$device"
    sleep 1
done

DF=`which df 2> /dev/null`
if [ -n "$DF" ]; then
	current_root=`df --output=source / 2> /dev/null | tail -1`
fi

if [ ! -n "$current_root" ]; then
	current_root="rootfs"
fi

mode="manufacturing"

NEXT_OS_IMAGE=0
if [ "X$current_root" == "X${device}p2" ]; then
    mode="upgrade"
    NEXT_OS_IMAGE=1
    DUAL_BOOT="yes"
elif [ "X$current_root" == "X${device}p4" ]; then
    mode="upgrade"
    NEXT_OS_IMAGE=0
    DUAL_BOOT="yes"
elif [ "X$current_root" == "Xrootfs" ]; then
    mode="manufacturing"
else
    printf "ERROR: unsupported partition scheme\n"
    exit 1
fi

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

# Flash image
bs=512
reserved=34
start_reserved=2048
boot_size_megs=50
mega=$((2**20))
boot_size_bytes=$(($boot_size_megs * $mega))
giga=$((2**30))
MIN_DISK_SIZE4DUAL_BOOT=$((16*$giga)) #16GB
common_size_bytes=$((10*$giga))

disk_sectors=`fdisk -l $device 2> /dev/null | grep "Disk $device:" | awk '{print $7}'`
disk_size=`fdisk -l $device 2> /dev/null | grep "Disk $device:" | awk '{print $5}'`
disk_end=$((disk_sectors - reserved))

pciids=`lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}'`

set -- $pciids
pciid=$1

PSID=""
if [ -n "$FLINT" ]; then
	PSID=`$FLINT -d $pciid q | grep PSID | awk '{print $NF}'`

	case "${PSID}" in
		MT_0000000667|MT_0000000698)
		DUAL_BOOT="yes"
		;;
	esac
fi

if [ "X$mode" == "Xmanufacturing" ]; then

if [ $disk_size -lt $MIN_DISK_SIZE4DUAL_BOOT ]; then
	if [ "X$DUAL_BOOT" == "Xyes" ]; then
		if [ "X$FORCE_DUAL_BOOT" == "Xyes" ]; then
			log "WARN: Dual boot is not supported for EMMC <= 16GB but FORCE_DUAL_BOOT is set"
			DUAL_BOOT="yes"
			common_size_bytes=$((3*$giga/2))
		else
			log "WARN: Dual boot is not supported for EMMC <= 16GB"
			DUAL_BOOT="no"
		fi
	fi
fi

dd if=/dev/zero of="$device" bs="$bs" count=1

boot_size=$(($boot_size_bytes/$bs))
if [ "X$DUAL_BOOT" == "Xyes" ]; then
	common_size=${COMMON_SIZE_SECTORS:-$(($common_size_bytes/$bs))}
	common_start=$(($disk_end - $common_size))
	root_size=$((($common_start - $start_reserved - 2*$boot_size)/2))
	boot1_start=$start_reserved
	root1_start=$(($start_reserved + $boot_size))
	boot2_start=$(($root1_start + $root_size))
	root2_start=$(($boot2_start + $boot_size))

(
sfdisk -f "$device" << EOF
label: gpt
label-id: A2DF9E70-6329-4679-9C1F-1DAF38AE25AE
device: ${device}
unit: sectors
first-lba: $reserved
last-lba: $disk_end

${device}p1 : start=$boot1_start, size=$boot_size, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI System", bootable
${device}p2 : start=$root1_start ,size=$root_size, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="writable"
${device}p3 : start=$boot2_start, size=$boot_size, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI System", bootable
${device}p4 : start=$root2_start ,size=$root_size, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="writable"
${device}p5 : start=$common_start ,size=$common_size, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="writable"
EOF
) > /dev/null 2>&1

else # Single OS configuration
	boot_start=$start_reserved
	boot_size=$(($boot_size_bytes/$bs))
	root_start=$(($boot_start + $boot_size))
	root_end=$disk_end
	root_size=$(($root_end - $root_start + 1))
(
sfdisk -f "$device" << EOF
label: gpt
label-id: A2DF9E70-6329-4679-9C1F-1DAF38AE25AE
device: ${device}
unit: sectors
first-lba: $reserved
last-lba: $disk_end

${device}p1 : start=$boot_start, size=$boot_size, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI System", bootable
${device}p2 : start=$root_start ,size=$root_size, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="writable"
EOF
) > /dev/null 2>&1
fi

sync

# Refresh partition table
blockdev --rereadpt ${device} > /dev/null 2>&1
fi # manufacturing mode

install_os_image()
{
	OS_IMAGE=$1
	if [ "X$DUAL_BOOT" == "Xyes" ]; then
		if [ $OS_IMAGE -eq 0 ]; then
			log "Installing first OS image"
		else
			log "Installing second OS image"
		fi
	else
		log "Installing OS image"
	fi
	BOOT_PARTITION=${device}p$((1 + 2*$OS_IMAGE))
	ROOT_PARTITION=${device}p$((2 + 2*$OS_IMAGE))
	COMMON_PARTITION=${device}p5

	# Generate some entropy
	mke2fs -O 64bit $ROOT_PARTITION > /dev/null 2>&1
	mkfs.fat $BOOT_PARTITION -n "system-boot$OS_IMAGE" > /dev/null 2>&1
	mkfs.ext4 -F $ROOT_PARTITION -L "writable$OS_IMAGE" > /dev/null 2>&1
	sync
	blockdev --rereadpt ${device} > /dev/null 2>&1

	mkdir -p /mnt
	mount -t ext4 $ROOT_PARTITION /mnt
	mkdir -p /mnt/boot/efi
	mount -t vfat $BOOT_PARTITION /mnt/boot/efi

	echo "Extracting /..."
	export EXTRACT_UNSAFE_SYMLINKS=1
	tar Jxf /ubuntu/image.tar.xz --warning=no-timestamp -C /mnt
	sync

	UBUNTU_CODENAME=`grep UBUNTU_CODENAME /mnt/etc/os-release | cut -d '=' -f 2`

	cat > /mnt/etc/fstab << EOF
`lsblk -o UUID -P $ROOT_PARTITION` / auto defaults 0 0
`lsblk -o UUID -P $BOOT_PARTITION` /boot/efi vfat umask=0077 0 1
EOF

	if [ "X$DUAL_BOOT" == "Xyes" ]; then
		cat >> /mnt/etc/fstab << EOF
`lsblk -o UUID -P $COMMON_PARTITION` /common auto defaults 0 0
EOF
		mkdir -p /mnt/common
		mkdir -p /tmp/common
		mount $COMMON_PARTITION /tmp/common
		if [ -e /mnt/etc/bfb_version.json ]; then
			/bin/rm -f /tmp/common/$((2 + 2*$OS_IMAGE)).version.json
			cp /mnt/etc/bfb_version.json /tmp/common/$((2 + 2*$OS_IMAGE)).version.json
			sync
		fi
		umount /tmp/common > /dev/null 2>&1
	fi

	if (grep -qE "MemTotal:\s+16" /proc/meminfo > /dev/null 2>&1); then
		sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 500000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
	fi

	if [ -n "${grub_admin_PASSWORD}" ]; then
		sed -i -r -e "s/(password_pbkdf2 admin).*/\1 ${grub_admin_PASSWORD}/" /mnt/etc/grub.d/40_custom
	fi

	mount --bind /proc /mnt/proc
	mount --bind /dev /mnt/dev
	mount --bind /sys /mnt/sys
	chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-install ${device} > /dev/null 2>&1
	chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg > /dev/null 2>&1
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

	perl -ni -e 'print unless /PasswordAuthentication no/' /mnt/etc/ssh/sshd_config
	echo "PasswordAuthentication yes" >> /mnt/etc/ssh/sshd_config
	echo "PermitRootLogin yes" >> /mnt/etc/ssh/sshd_config

	chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service > /dev/null 2>&1
	chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service > /dev/null 2>&1
	chroot /mnt /bin/systemctl enable serial-getty@hvc0.service > /dev/null 2>&1

	if [ -x /usr/bin/uuidgen ]; then
		UUIDGEN=/usr/bin/uuidgen
	else
		UUIDGEN=/mnt/usr/bin/uuidgen
	fi

	p0m0_uuid=`$UUIDGEN`
	p1m0_uuid=`$UUIDGEN`
	p0m0_mac=`echo ${p0m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/'`
	p1m0_mac=`echo ${p1m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/'`

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
		if [ ! -n "$DHCP_CLASS_ID" ]; then
			DHCP_CLASS_ID="BF1Client"
		fi
		ln -snf snap_rpc_init_bf1.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
		# OOB interface does not exist on BlueField-1
		sed -i -e '/oob_net0/,+1d' /mnt/var/lib/cloud/seed/nocloud-net/network-config
	elif (lspci -n -d 15b3: | grep -wq 'a2d6'); then
		# BlueField-2
		if [ ! -n "$DHCP_CLASS_ID" ]; then
			DHCP_CLASS_ID="BF2Client"
		fi
		ln -snf snap_rpc_init_bf2.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
	elif (lspci -n -d 15b3: | grep -wq 'a2dc'); then
		# BlueField-3
		if [ ! -n "$DHCP_CLASS_ID" ]; then
			DHCP_CLASS_ID="BF3Client"
		fi
		if [ -e /mnt/etc/mlnx_snap/snap_rpc_init_bf3.conf ]; then
			ln -snf snap_rpc_init_bf3.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
		else
			ln -snf snap_rpc_init_bf2.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
		fi
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
			MT_0000000667|MT_0000000698)
			chroot /mnt /bin/systemctl disable lldpad.service
			chroot /mnt /bin/systemctl disable lldpad.socket
			perl -ni -e "print unless /controller_nvme_namespace_attach/" /mnt/etc/mlnx_snap/snap_rpc_init_bf2.conf
			sed -r -i -e "s@(controller_nvme_create.*)@\1 -c /etc/mlnx_snap/mlnx_snap.json.example@" /mnt/etc/mlnx_snap/snap_rpc_init_bf2.conf
			sed -r -i -e 's@(CPU_MASK=).*@\10xff@' \
				      -e 's@.*RDMAV_FORK_SAFE=.*@RDMAV_FORK_SAFE=1@' \
				      -e 's@.*RDMAV_HUGEPAGES_SAFE=.*@RDMAV_HUGEPAGES_SAFE=1@' \
					  -e 's@.*NVME_FW_SUPP=.*@NVME_FW_SUPP=1@' \
					  -e 's@.*NVME_FW_UPDATE_PERSISTENT_LOCATION=.*@NVME_FW_UPDATE_PERSISTENT_LOCATION=/common@' \
					  /mnt/etc/default/mlnx_snap
			perl -ni -e "print unless /rpc_server/" /mnt/etc/mlnx_snap/mlnx_snap.json.example
			sed -i -e '/"ctrl": {/a\'$'\n''        "rpc_server": "/var/tmp/spdk.sock",' /mnt/etc/mlnx_snap/mlnx_snap.json.example
			sed -r -i -e 's@("max_namespaces":).*([a-zA-Z0-9]+)@\1 30@' \
					  -e 's@("quirks":).*([a-zA-Z0-9]+)@\1 0x8@' \
					  /mnt/etc/mlnx_snap/mlnx_snap.json.example
			sed -i -e "s/bdev_nvme_set_options.*/bdev_nvme_set_options --bdev-retry-count 10 --transport-retry-count 7 --transport-ack-timeout 0 --timeout-us 0 --timeout-admin-us 0 --action-on-timeout none --reconnect-delay-sec 10 --ctrlr-loss-timeout-sec -1 --fast-io-fail-timeout-sec 0/" /mnt/etc/mlnx_snap/spdk_rpc_init.conf

	cat >> /mnt/lib/udev/mlnx_bf_udev << EOF

# RoCE configuration
case "\$1" in
        p0|p1)
        mlnx_qos -i \$1 --trust dscp
        echo 106 > /sys/class/infiniband/mlx5_\${1/p/}/tc/1/traffic_class
        cma_roce_tos -d mlx5_\${1/p/} -t 106
        ;;
esac
EOF
			sed -i -e "s/dns=default/dns=none/" /mnt/etc/NetworkManager/conf.d/45-mlnx-dns.conf
			;;
		esac
	fi

	if [ -n "${ubuntu_PASSWORD}" ]; then
		log "INFO: Changing the default password for user ubuntu"
		perl -ni -e "if(/^users:/../^runcmd/) {
						next unless m{^runcmd};
		print q@users:
  - name: ubuntu
    lock_passwd: False
    groups: [adm, audio, cdrom, dialout, dip, floppy, lxd, netdev, plugdev, sudo, video]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    passwd: $ubuntu_PASSWORD
@;
		print } else {print}" /mnt/var/lib/cloud/seed/nocloud-net/user-data
	else
		perl -ni -e "print unless /plain_text_passwd/" /mnt/var/lib/cloud/seed/nocloud-net/user-data
	fi

	mkdir -p /mnt/etc/dhcp
	cat >> /mnt/etc/dhcp/dhclient.conf << EOF
send vendor-class-identifier "$DHCP_CLASS_ID";
EOF

	if function_exists bfb_modify_os; then
		log "INFO: Running bfb_modify_os from bf.cfg"
		bfb_modify_os
	fi

	sync

	umount /mnt/sys/fs/fuse/connections > /dev/null 2>&1 || true
	umount /mnt/sys > /dev/null 2>&1
	umount /mnt/dev > /dev/null 2>&1
	umount /mnt/proc > /dev/null 2>&1
	umount /mnt/boot/efi > /dev/null 2>&1
	umount /mnt > /dev/null 2>&1
}

if function_exists bfb_pre_install; then
	log "INFO: Running bfb_pre_install from bf.cfg"
	bfb_pre_install
fi

if function_exists custom_install_os_image; then
	log "INFO: Running custom_install_os_image from bf.cfg"
	custom_install_os_image
else
	if [ "X$mode" == "Xmanufacturing" ]; then
		if [ "X$DUAL_BOOT" == "Xyes" ]; then
			# Format common partition
			mkfs.ext4 -F ${device}p5 -L "common"
			for OS_IMAGE in 0 1
			do
				install_os_image $OS_IMAGE
			done # OS_IMAGE
		else
			install_os_image 0
		fi
	else
		install_os_image $NEXT_OS_IMAGE
	fi
fi

blockdev --rereadpt ${device} > /dev/null 2>&1

sync

bfrec --bootctl --policy dual 2> /dev/null || true
if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
	bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap --policy dual
fi

bfbootmgr --cleanall > /dev/null 2>&1
/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1

# Make it the boot partition
mounted_efivarfs=0
if [ ! -d /sys/firmware/efi/efivars ]; then
	mount -t efivarfs none /sys/firmware/efi/efivars
	mounted_efivarfs=1
fi

if efibootmgr | grep ${UBUNTU_CODENAME}; then
	efibootmgr -b "$(efibootmgr | grep ${UBUNTU_CODENAME} | cut -c 5-8)" -B > /dev/null 2>&1
fi
efibootmgr -c -d "$device" -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l "\EFI\ubuntu\shimaa64.efi" > /dev/null 2>&1

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
		mv /etc/bf.cfg.orig /etc/bf.cfg
	fi
fi

if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
	log "ERROR: Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry. Retrying..."
	efibootmgr -c -d "$device" -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l "\EFI\ubuntu\shimaa64.efi" > /dev/null 2>&1
	if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
		bfbootmgr --cleanall > /dev/null 2>&1
		efibootmgr -c -d "$device" -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l "\EFI\ubuntu\shimaa64.efi" > /dev/null 2>&1
		if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
			log "ERROR: Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry."
		fi
	fi
fi

if [ $mounted_efivarfs -eq 1 ]; then
	umount /sys/firmware/efi/efivars > /dev/null 2>&1
fi

if [ -n "$BFCFG" ]; then
	$BFCFG
fi

if function_exists bfb_post_install; then
	log "INFO: Running bfb_post_install from bf.cfg"
	bfb_post_install
fi

log "INFO: Installation finished"
if [ "X$mode" == "Xmanufacturing" ]; then
	sleep 3
	log "INFO: Rebooting..."
	# Wait for these messages to be pulled by the rshim service
	sleep 3
fi
