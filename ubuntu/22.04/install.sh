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

rshimlog=$(which bfrshlog 2> /dev/null)
distro="Ubuntu"
NIC_FW_UPDATE_DONE=0
NIC_FW_RESET_REQUIRED=0
RC=0
err_msg=""

logfile=${distro}.installation.log
LOG=/tmp/$logfile

fspath=$(readlink -f "$(dirname $0)")

log()
{
	msg="[$(date +%H:%M:%S)] $*"
	echo "$msg" > /dev/ttyAMA0
	echo "$msg" > /dev/hvc0
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	fi
	echo "$msg" >> $LOG
}

ilog()
{
	msg="[$(date +%H:%M:%S)] $*"
	echo "$msg" >> $LOG
	echo "$msg"
}

save_log()
{
cat >> $LOG << EOF

########################## DMESG ##########################
$(dmesg -x)
EOF
	sync
	if [ ! -d /mnt/root ]; then
		mount -t $ROOTFS $ROOT_PARTITION /mnt
	fi
	cp $LOG /mnt/root
	umount /mnt
}

fw_update()
{
	FW_UPDATER=/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl
	FW_DIR=/opt/mellanox/mlnx-fw-updater/firmware/

	if [[ -x /mnt/${FW_UPDATER} && -d /mnt/${FW_DIR} ]]; then
		log "INFO: Updating NIC firmware..."
		chroot /mnt ${FW_UPDATER} --log /tmp/mlnx_fw_update.log -v \
			--force-fw-update \
			--fw-dir ${FW_DIR}
		rc=$?
		sync
		if [ -e /tmp/mlnx_fw_update.log ]; then
			cat /tmp/mlnx_fw_update.log >> $LOG
		fi
		if [ $rc -eq 0 ]; then
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
	ilog "Running mlnx_bf_configure:"
	ilog "$(chroot /mnt /sbin/mlnx_bf_configure)"

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

	log "INFO: Running NIC Firmware reset"
	save_log
	if [ "X$mode" == "Xmanufacturing" ]; then
		log "INFO: Rebooting..."
	fi
	# Wait for these messages to be pulled by the rshim service
	# as mlxfwreset will restart the DPU
	sleep 3

	msg=$(chroot /mnt mlxfwreset -d /dev/mst/mt*_pciconf0 -y -l 3 --sync 1 r 2>&1)
	if [ $? -ne 0 ]; then
		log "INFO: NIC Firmware reset failed"
		log "INFO: $msg"
	else
		log "INFO: NIC Firmware reset done"
	fi
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
		cat >> $LOG << EOF

############ bf.cfg ###############
$(cat /etc/bf.cfg)
########## END of bf.cfg ##########
EOF
	fi
	rm -f $cfg_file
fi

ilog "Starting mst:"
ilog "$(mst start)"

cat >> $LOG << EOF

############ DEBUG INFO (pre-install) ###############
KERNEL: $(uname -r)

LSMOD:
$(lsmod)

NETWORK:
$(ip addr show)

CMDLINE:
$(cat /proc/cmdline)

PARTED:
$(parted -l -s)

LSPCI:
$(lspci)

NIC FW INFO:
$(flint -d /dev/mst/mt*_pciconf0 q)

MLXCONFIG:
$(mlxconfig -d /dev/mst/mt*_pciconf0 -e q)
########### DEBUG INFO END ############

EOF

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

ROOTFS=${ROOTFS:-"ext4"}
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

default_device=/dev/mmcblk0
if [ -b /dev/nvme0n1 ]; then
	default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -n | tail -1)"
fi
device=${device:-"$default_device"}

ilog "OS installation target: $device"
echo 0 > /proc/sys/kernel/hung_task_timeout_secs

# We cannot use wait-for-root as it expects the device to contain a
# known filesystem, which might not be the case here.
while [ ! -b $device ]; do
    log "Waiting for $device to be ready\n"
    sleep 1
done

DF=$(which df 2> /dev/null)
if [ -n "$DF" ]; then
	current_root=$(df --output=source / 2> /dev/null | tail -1)
fi

if [ -z "$current_root" ]; then
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

disk_sectors=$(fdisk -l $device 2> /dev/null | grep "Disk $device:" | awk '{print $7}')
disk_size=$(fdisk -l $device 2> /dev/null | grep "Disk $device:" | awk '{print $5}')
disk_end=$((disk_sectors - reserved))

pciids=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')

set -- $pciids
pciid=$1

PSID=""
if [ -n "$FLINT" ]; then
	PSID=$($FLINT -d $pciid q | grep PSID | awk '{print $NF}')

	case "${PSID}" in
		MT_0000000667|MT_0000000698)
		DUAL_BOOT="yes"
		;;
	esac
	ilog "PSID: $PSID"
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

ilog "Creating partitions on $device using sfdisk:"

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
) >> $LOG 2>&1

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
) >> $LOG 2>&1
fi

sync

# Refresh partition table
sleep 1
blockdev --rereadpt ${device} > /dev/null 2>&1
fi # manufacturing mode

bind_partitions()
{
	mount --bind /proc /mnt/proc
	mount --bind /dev /mnt/dev
	mount --bind /sys /mnt/sys
	mount -t efivarfs none /mnt/sys/firmware/efi/efivars
}

unmount_partitions()
{
	umount /mnt/sys/fs/fuse/connections > /dev/null 2>&1 || true
	umount /mnt/sys/firmware/efi/efivars 2>&1 || true
	umount /mnt/sys > /dev/null 2>&1
	umount /mnt/dev > /dev/null 2>&1
	umount /mnt/proc > /dev/null 2>&1
	umount /mnt/boot/efi > /dev/null 2>&1
	umount /mnt > /dev/null 2>&1
}

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

	ilog "Creating file systems:"
	(
	mke2fs -O 64bit -O extents -F $ROOT_PARTITION
	mkfs.fat -F32 -n "EFI$OS_IMAGE" $BOOT_PARTITION
	mkfs.${ROOTFS} -F $ROOT_PARTITION -L "OS$OS_IMAGE"
	) >> $LOG 2>&1
	sync
	sleep 1
	blockdev --rereadpt ${device} > /dev/null 2>&1

	mkdir -p /mnt
	mount -t ${ROOTFS} $ROOT_PARTITION /mnt
	mkdir -p /mnt/boot/efi
	mount -t vfat $BOOT_PARTITION /mnt/boot/efi

	ilog "Extracting /..."
	export EXTRACT_UNSAFE_SYMLINKS=1
	tar Jxf $fspath/image.tar.xz --warning=no-timestamp -C /mnt
	sync

	UBUNTU_CODENAME=$(grep ^ID= /mnt/etc/os-release | cut -d '=' -f 2)

	cat > /mnt/etc/fstab << EOF
$(lsblk -o UUID -P $ROOT_PARTITION) / auto defaults 0 1
$(lsblk -o UUID -P $BOOT_PARTITION) /boot/efi vfat umask=0077 0 2
EOF

	if [ "X$DUAL_BOOT" == "Xyes" ]; then
		cat >> /mnt/etc/fstab << EOF
$(lsblk -o UUID -P $COMMON_PARTITION) /common auto defaults 0 2
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

	memtotal=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
	if [ $memtotal -gt 16000000 ]; then
		sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 1000000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
	fi

	bind_partitions

	vmlinuz=$(cd /mnt/boot; /bin/ls -1 vmlinuz-* | tail -1)
	initrd=$(cd /mnt/boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//")
	ln -snf $vmlinuz /mnt/boot/vmlinuz
	ln -snf $initrd /mnt/boot/initrd.img

	kver=$(uname -r)
	if [ ! -d /mnt/lib/modules/$kver ]; then
		kver=$(/bin/ls -1 /mnt/lib/modules/ | tail -1)
	fi
	cat >> /mnt/etc/initramfs-tools/modules << EOF
dw_mmc-bluefield
dw_mmc
dw_mmc-pltfm
sdhci-of-dwcmshc
sdhci_pltfm
sdhci
mlxbf-tmfifo
nvme
EOF

	chroot /mnt update-initramfs -k ${kver} -u

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

	# Remove /etc/hostname to get hostname from DHCP server
	/bin/rm -f /mnt/etc/hostname

	/bin/rm -f /mnt/var/lib/dbus/machine-id /etc/machine-id
	touch /mnt/var/lib/dbus/machine-id /mnt/etc/machine-id

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

	p0m0_uuid=$($UUIDGEN)
	p1m0_uuid=$($UUIDGEN)
	p0m0_mac=$(echo ${p0m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')
	p1m0_mac=$(echo ${p1m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')

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
		sed -i -e '/oob_net0/,+1d' /mnt/var/lib/cloud/seed/nocloud-net/network-config
	elif (lspci -n -d 15b3: | grep -wq 'a2d6'); then
		# BlueField-2
		ln -snf snap_rpc_init_bf2.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
		#chroot /mnt env PATH=$CHROOT_PATH apt remove -y --purge dpa-compiler dpacc dpaeumgmt flexio || true
	elif (lspci -n -d 15b3: | grep -wq 'a2dc'); then
		# BlueField-3
		chroot /mnt env PATH=$CHROOT_PATH apt remove -y --purge mlnx-snap || true
	fi

	pciid=$(echo $pciids | awk '{print $1}' | head -1)
	if [ -e /mnt/usr/sbin/mlnx_snap_check_emulation.sh ]; then
		sed -r -i -e "s@(NVME_SF_ECPF_DEV=).*@\1${pciid}@" /mnt/usr/sbin/mlnx_snap_check_emulation.sh
	fi
	if [ -n "$FLINT" ]; then
		PSID=$($FLINT -d $pciid q | grep PSID | awk '{print $NF}')

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
    groups: adm, audio, cdrom, dialout, dip, floppy, lxd, netdev, plugdev, sudo, video
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
send vendor-class-identifier "$DHCP_CLASS_ID_DP";
interface "oob_net0" {
  send vendor-class-identifier "$DHCP_CLASS_ID_OOB";
}
EOF

	if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
		if [ $NIC_FW_UPDATE_DONE -eq 0 ]; then
			fw_update
			NIC_FW_UPDATE_DONE=1
		fi
	fi

	if [ "X$ENABLE_SFC_HBN" == "Xyes" ]; then
		ARG_PORT0=""
		ARG_PORT1=""
		if ! [ -z "${NUM_VFs_PHYS_PORT0}" ]; then
			ARG_PORT0="--ecpf0 "${NUM_VFs_PHYS_PORT0}
		fi
		if ! [ -z "${NUM_VFs_PHYS_PORT1}" ]; then
			ARG_PORT1="--ecpf1 "${NUM_VFs_PHYS_PORT1}
		fi
		HBN_UPLINKS=${HBN_UPLINKS:-"p0,p1"}
		HBN_REPS=${HBN_REPS:-"pf0hpf,pf1hpf,pf0vf0-pf0vf13"}
		HBN_DPU_SFS=${HBN_DPU_SFS:-"pf0dpu1,pf0dpu3"}
		HUGEPAGE_SIZE=${HUGEPAGE_SIZE:-2048}
		HUGEPAGE_COUNT=${HUGEPAGE_COUNT:-4096}
		CLOUD_OPTION=${CLOUD_OPTION:-""}
		log "INFO: Installing SFC HBN environment"
		chroot /mnt HBN_UPLINKS=${HBN_UPLINKS} HBN_REPS=${HBN_REPS} HBN_DPU_SFS=${HBN_DPU_SFS} HUGEPAGE_SIZE=${HUGEPAGE_SIZE} HUGEPAGE_COUNT=${HUGEPAGE_COUNT} CLOUD_OPTION=${CLOUD_OPTION} /opt/mellanox/sfc-hbn/install.sh ${ARG_PORT0} ${ARG_PORT1}
		NIC_FW_RESET_REQUIRED=1
	fi

	if [ -n "${grub_admin_PASSWORD}" ]; then
		sed -i -r -e "s/(password_pbkdf2 admin).*/\1 ${grub_admin_PASSWORD}/" /mnt/etc/grub.d/40_custom
	fi

	if (hexdump -C /sys/firmware/acpi/tables/SSDT* | grep -q MLNXBF33); then
		# BlueField-3
		sed -i -e "s/0x01000000/0x13010000/g" /mnt/etc/default/grub
	fi

	if (lspci -vv | grep -wq SimX); then
		# Remove earlycon from grub parameters on SimX
		sed -i -r -e 's/earlycon=[^ ]* //g' /mnt/etc/default/grub
	fi

	ilog "Creating GRUB configuration"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-install ${device})"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg)"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-set-default 0)"

	if function_exists bfb_modify_os; then
		log "INFO: Running bfb_modify_os from bf.cfg"
		bfb_modify_os
	fi

	sync

	unmount_partitions
}

if [ ! -d /sys/firmware/efi/efivars ]; then
	mount -t efivarfs none /sys/firmware/efi/efivars
fi

ilog "Remove old boot entries"
ilog "$(bfbootmgr --cleanall)"
/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1
/bin/rm -f /sys/firmware/efi/efivars/dump-* > /dev/null 2>&1

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
			mkfs.${ROOTFS} -F ${device}p5 -L "common"
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

sleep 1
blockdev --rereadpt ${device} > /dev/null 2>&1

sync

ilog "Updating ATF/UEFI:"
ilog "$(bfrec --bootctl || true)"
if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
	ilog "$(bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap)"
fi

if [ -e /lib/firmware/mellanox/boot/capsule/efi_sbkeysync.cap ]; then
	ilog "$(bfrec --capsule /lib/firmware/mellanox/boot/capsule/efi_sbkeysync.cap)"
fi

# Make it the boot partition
if efibootmgr | grep ${UBUNTU_CODENAME}; then
	efibootmgr -b "$(efibootmgr | grep ${UBUNTU_CODENAME} | cut -c 5-8)" -B > /dev/null 2>&1
fi
ilog "$(efibootmgr -c -d $device -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l '\EFI\ubuntu\shimaa64.efi')"

BFCFG=$(which bfcfg 2> /dev/null)
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
	rc=$?
	if [ $rc -ne 0 ]; then
		if (grep -q "boot: failed to get MAC" /tmp/bfcfg.log > /dev/null 2>&1); then
			err_msg="Failed to add PXE boot entries"
		fi
	fi

	RC=$((RC+rc))
	cat >> $LOG << EOF

### Adding PXE boot entries: ###
$(cat /etc/bf.cfg)
### bfcfg LOG: ###
$(cat /tmp/bfcfg.log)
### bfcfg log End ###
EOF
	# Restore the original bf.cfg
	/bin/rm -f /etc/bf.cfg
	if [ -e /etc/bf.cfg.orig ]; then
		grep -v PXE_DHCP_CLASS_ID= /etc/bf.cfg.orig > /etc/bf.cfg
	fi
fi

if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
	log "ERROR: Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry. Retrying..."
	ilog "efibootmgr -c -d $device -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l '\EFI\ubuntu\shimaa64.efi'"
	if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
		bfbootmgr --cleanall > /dev/null 2>&1
		efibootmgr -c -d "$device" -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l "\EFI\ubuntu\shimaa64.efi" > /dev/null 2>&1
		if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
			log "ERROR: Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry."
		fi
	fi
fi

umount /sys/firmware/efi/efivars

if [ -n "$BFCFG" ]; then
	$BFCFG
	rc=$?
	if [ $rc -ne 0 ]; then
		if (grep -q "boot: failed to get MAC" /tmp/bfcfg.log > /dev/null 2>&1); then
			err_msg="Failed to add PXE boot entries"
		fi
	fi

	RC=$((RC+rc))
	cat >> $LOG << EOF

### Applying original bf.cfg: ###
$(cat /etc/bf.cfg)
### bfcfg LOG: ###
$(cat /tmp/bfcfg.log)
### bfcfg log End ###
EOF
fi

if function_exists bfb_post_install; then
	log "INFO: Running bfb_post_install from bf.cfg"
	bfb_post_install
fi

log "INFO: Installation finished"

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	if [ $NIC_FW_UPDATE_DONE -eq 1 ]; then
		NIC_FW_RESET_REQUIRED=1
	fi
fi

if [ $NIC_FW_RESET_REQUIRED -eq 1 ]; then
	# Reset NIC FW
	mount -t ${ROOTFS} ${device}p2 /mnt
	bind_partitions
	fw_reset
	unmount_partitions
fi

save_log
if [ "X$mode" == "Xmanufacturing" ]; then
	sleep 3
	log "INFO: Rebooting..."
	# Wait for these messages to be pulled by the rshim service
	sleep 3
fi
