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
NIC_FW_UPDATE_DONE=0

fspath=$(readlink -f `dirname $0`)

rshimlog=`which bfrshlog 2> /dev/null`
log()
{
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	else
		echo "$*"
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

PART_SCHEME="SCHEME_A"
if [ -e /etc/bf.cfg ]; then
	if ( bash -n /etc/bf.cfg ); then
		. /etc/bf.cfg
	else
		log "INFO: Invalid bf.cfg"
	fi
fi

distro="BCLinux"

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

# Create the CentOS partitions.
device=${device:-/dev/mmcblk0}

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
		mkpart primary 201MiB 6000MiB \
		mkpart primary 6000MiB 12489MiB \
		mkpart primary 12489MiB 100%
fi

sync

partprobe "$device" > /dev/null 2>&1

blockdev --rereadpt "$device" > /dev/null 2>&1

if function_exists bfb_pre_install; then
	log "INFO: Running bfb_pre_install from bf.cfg"
	bfb_pre_install
fi

# Generate some entropy
mke2fs  /dev/mmcblk0p2 >> /dev/null

# Copy the kernel image.
mkdosfs /dev/mmcblk0p1 -n system-boot
mkfs.xfs -f /dev/mmcblk0p2 -L local-boot
mkfs.xfs -f /dev/mmcblk0p3 -L writable
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

if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
	cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
/dev/mmcblk0p3  /           xfs     defaults                   0 1
/dev/mmcblk0p2  /boot       xfs     defaults                   0 2
/dev/mmcblk0p1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF
elif [[ "${PART_SCHEME}" == "SCHEME_B" ]]; then
	cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
/dev/mmcblk0p2  /           xfs     defaults                   0 1
/dev/mmcblk0p3  /home       xfs     defaults                   0 2
/dev/mmcblk0p4  /var        xfs     defaults                   0 2
/dev/mmcblk0p1  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
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

bind_partitions

/bin/rm -f /mnt/boot/vmlinux-*.bz2

# Then, set boot arguments: Read current 'console' and 'earlycon'
# parameters, and append the root filesystem parameters.
bootarg="$(cat /proc/cmdline | sed 's/initrd=initramfs//;s/console=.*//')"
sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"crashkernel=auto $bootarg console=hvc0 console=ttyAMA0 earlycon=pl011,0x01000000 modprobe.blacklist=mlx5_core,mlx5_ib\"@" /mnt/etc/default/grub
if (lspci -n -d 15b3: | grep -wq 'a2dc'); then
    # BlueField-3
    sed -i -e "s/0x01000000/0x13010000/g" /mnt/etc/default/grub
fi

chroot /mnt grub2-mkconfig -o /boot/efi/EFI/bclinux/grub.cfg

kdir=$(/bin/ls -1d /mnt/lib/modules/4.18* /mnt/lib/modules/4.19* /mnt/lib/modules/4.20* /mnt/lib/modules/5.4* 2> /dev/null)
kver=""
if [ -n "$kdir" ]; then
    kver=${kdir##*/}
    DRACUT_CMD=`chroot /mnt /bin/ls -1 /sbin/dracut /usr/bin/dracut 2> /dev/null | head -1`
    chroot /mnt grub2-set-default 0
    chroot /mnt $DRACUT_CMD --kver ${kver} --force --add-drivers "dw_mmc-bluefield dw_mmc dw_mmc-pltfm mmc_block mlxbf_tmfifo virtio_console" /boot/initramfs-${kver}.img
else
    kver=$(/bin/ls -1 /mnt/lib/modules/ | head -1)
fi


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
	/bin/rm -f /mnt/etc/sysconfig/network-scripts/ifcfg-oob_net0
elif (lspci -n -d 15b3: | grep -wq 'a2d6'); then
	# BlueField-2
	ln -snf snap_rpc_init_bf2.conf /mnt/etc/mlnx_snap/snap_rpc_init.conf
elif (lspci -n -d 15b3: | grep -wq 'a2dc'); then
	# BlueField-3
	chroot /mnt rpm -e mlnx-snap || true
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

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	if [ $NIC_FW_UPDATE_DONE -eq 0 ]; then
		fw_update
		NIC_FW_UPDATE_DONE=1
	fi
fi

# Clean up logs
echo > /mnt/var/log/messages
echo > /mnt/var/log/maillog
echo > /mnt/var/log/secure
echo > /mnt/var/log/firewalld
echo > /mnt/var/log/audit/audit.log
/bin/rm -f /mnt/var/log/yum.log
/bin/rm -rf /mnt/tmp/*

if function_exists bfb_modify_os; then
	log "INFO: Running bfb_modify_os from bf.cfg"
	bfb_modify_os
fi

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

bfrec --bootctl --policy dual 2> /dev/null || true
if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
	bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap --policy dual
fi


# Clean up actual boot entries.
bfbootmgr --cleanall > /dev/null 2>&1

mount -t efivarfs none /sys/firmware/efi/efivars
/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1
efibootmgr -c -d /dev/mmcblk0 -p 1 -l "\EFI\bclinux\shimaa64-bclinux.efi" -L $distro
umount /sys/firmware/efi/efivars

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

if [ -n "$BFCFG" ]; then
	$BFCFG
fi

echo
echo "ROOT PASSWORD is \"bclinux\""
echo

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
		if [[ "${PART_SCHEME}" == "SCHEME_A" ]]; then
			mount /dev/mmcblk0p3 /mnt
		else
			mount /dev/mmcblk0p2 /mnt
		fi
		bind_partitions
		fw_reset
		unmount_partitions
	fi
fi

sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
