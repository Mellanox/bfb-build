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
distro="Debian"
NIC_FW_UPDATE_DONE=0
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
		mount -t $ROOTFS /dev/${root_device} /mnt
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

bind_partitions()
{
	mount --bind /proc /mnt/proc
	mount --bind /dev /mnt/dev
	mount --bind /dev/pts /mnt/dev/pts
	mount --bind /sys /mnt/sys
}

unmount_partitions()
{
	umount /mnt/sys/fs/fuse/connections > /dev/null 2>&1 || true
	umount /mnt/sys > /dev/null 2>&1
	umount /mnt/dev/pts > /dev/null 2>&1
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

ilog "Installation target: $device"

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

if function_exists bfb_pre_install; then
	log "INFO: Running bfb_pre_install from bf.cfg"
	bfb_pre_install
fi

# Generate some entropy
mke2fs  ${device}p2 >> /dev/null

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

ilog "Extracting /..."
export EXTRACT_UNSAFE_SYMLINKS=1
tar Jxf $fspath/image.tar.xz --warning=no-timestamp -C /mnt
sync

cat > /mnt/etc/fstab << EOF
$(lsblk -o UUID -P ${device}p2) / auto defaults 0 1
$(lsblk -o UUID -P ${device}p1) /boot/efi vfat umask=0077 0 2
EOF

memtotal=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
if [ $memtotal -gt 16000000 ]; then
	sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 1000000/" /mnt/usr/lib/sysctl.d/90-bluefield.conf
fi

bind_partitions
if (grep -q MLNXBF33 /sys/firmware/acpi/tables/SSDT*); then
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

vmlinuz=$(cd /mnt/boot; /bin/ls -1 vmlinuz-* | tail -1)
initrd=$(cd /mnt/boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//")
ln -snf $vmlinuz /mnt/boot/vmlinuz
ln -snf $initrd /mnt/boot/initrd.img

kver=$(uname -r)
if [ ! -d /mnt/lib/modules/$kver ]; then
	kver=$(/bin/ls -1 /mnt/lib/modules/ | tail -1)
fi

ilog "Updating $distro initramfs"
initrd=$(cd /mnt/boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//")
ilog "$(chroot /mnt dracut --force --force-drivers 'mlxbf-bootctl sdhci-of-dwcmshc mlxbf-tmfifo sbsa_gwdt gpio-mlxbf2 gpio-mlxbf3 mlxbf-gige pinctrl-mlxbf3' --add-drivers 'mlx5_core mlx5_ib mlxfw ib_umad nvme 8021q' --gzip /boot/$initrd ${kver} 2>&1)"
mkdir -p /mnt/etc/systemd/system/ssh.service.d/

cat > /mnt/etc/systemd/system/ssh.service.d/regenerate-host-keys.conf <<EOF
[Service]
ExecStartPre=
ExecStartPre=-/usr/bin/ssh-keygen -A
ExecStartPre=/usr/sbin/sshd -t
EOF

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

/bin/rm -f /mnt/etc/hostname

echo "PasswordAuthentication yes" >> /mnt/etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /mnt/etc/ssh/sshd_config

chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service
chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service
chroot /mnt /bin/systemctl enable serial-getty@hvc0.service

echo "root:debian" | chroot /mnt /usr/sbin/chpasswd
echo
echo "ROOT PASSWORD is \"debian\""
echo

if [ -x /usr/bin/uuidgen ]; then
	UUIDGEN=/usr/bin/uuidgen
else
	UUIDGEN=/mnt/usr/bin/uuidgen
fi

p0m0_uuid=$($UUIDGEN)
p1m0_uuid=$($UUIDGEN)
p0m0_mac=$(echo ${p0m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')
p1m0_mac=$(echo ${p1m0_uuid} | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')

pciids=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')

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
	#chroot /mnt env PATH=$CHROOT_PATH apt remove -y --purge dpa-compiler dpacc dpaeumgmt flexio || true
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

pciid=$(echo $pciids | awk '{print $1}' | head -1)
if [ -e /mnt/usr/sbin/mlnx_snap_check_emulation.sh ]; then
	sed -r -i -e "s@(NVME_SF_ECPF_DEV=).*@\1${pciid}@" /mnt/usr/sbin/mlnx_snap_check_emulation.sh
fi
if [ -n "$FLINT" ]; then
	PSID=$($FLINT -d $pciid q | grep PSID | awk '{print $NF}')
	ilog "PSID: $PSID"
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

sleep 1
blockdev --rereadpt ${device} > /dev/null 2>&1

fsck.vfat -a ${device}p1
sync

UPDATE_BOOT=${UPDATE_BOOT:-1}
if [ $UPDATE_BOOT -eq 1 ]; then
	ilog "Updating ATF/UEFI:"
	ilog "$(bfrec --bootctl || true)"
if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
	ilog "$(bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap)"
fi

if [ -e /lib/firmware/mellanox/boot/capsule/efi_sbkeysync.cap ]; then
	ilog "$(bfrec --capsule /lib/firmware/mellanox/boot/capsule/efi_sbkeysync.cap)"
	fi
fi

if [ ! -d /sys/firmware/efi/efivars ]; then
	mount -t efivarfs none /sys/firmware/efi/efivars
fi

ilog "Remove old boot entries"
ilog "$(bfbootmgr --cleanall)"
/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1
/bin/rm -f /sys/firmware/efi/efivars/dump-* > /dev/null 2>&1

if [ -x /usr/sbin/grub-install ]; then
	mount ${device}p2 /mnt/
	mount ${device}p1 /mnt/boot/efi/
	ilog "$(grub-install ${device}p1 --locale-directory=/mnt/usr/share/locale --efi-directory=/mnt/boot/efi/ --boot-directory=/mnt/boot/)"
	umount /mnt/boot/efi
	umount /mnt
else
	if efibootmgr | grep buster; then
		efibootmgr -b "$(efibootmgr | grep buster | cut -c 5-8)" -B
	fi
	ilog "$(efibootmgr -c -d $device -p 1 -L buster -l '\EFI\debian\grubaa64.efi')"
fi


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
		# Reset NIC FW
		mount -t ${ROOTFS} ${device}p2 /mnt
		bind_partitions
		fw_reset
		unmount_partitions
	fi
fi

save_log
sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
