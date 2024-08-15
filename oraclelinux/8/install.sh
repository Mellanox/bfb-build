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


rshimlog=$(which bfrshlog 2> /dev/null)
distro="OL"
NIC_FW_UPDATE_DONE=0
FORCE_NIC_FW_UPDATE=${FORCE_NIC_FW_UPDATE:-"no"}
NIC_FW_RESET_REQUIRED=0
BFB_NIC_FW_UPDATE=0
NIC_FW_FOUND=0
FW_UPDATER=/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl
FW_DIR=/opt/mellanox/mlnx-fw-updater/firmware/
CHROOT=
RC=0
err_msg=""
export LC_ALL=C

logfile=${distro}.installation.log
LOG=/tmp/$logfile

fspath=$(readlink -f "$(dirname $0)")

cx_pcidev=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}' | head -1)
cx_dev_id=$(lspci -nD -s ${cx_pcidev} 2> /dev/null | awk -F ':' '{print strtonum("0x" $NF)}')
pciids=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')
dpu_part_number=$(flint -d $cx_pcidev q full | grep "Part Number:" | awk '{print $NF}')
PSID=$(mstflint -d $cx_pcidev q | grep PSID | awk '{print $NF}')

rlog()
{
	msg=$(echo "$*" | sed 's/INFO://;s/ERROR:/ERR/;s/WARNING:/WARN/')
	if [ -n "$rshimlog" ]; then
		$rshimlog "$msg"
	fi
}

ilog()
{
	msg="[$(date +%H:%M:%S)] $*"
	echo "$msg" >> $LOG
	echo "$msg" > /dev/ttyAMA0
	echo "$msg" > /dev/hvc0
}

log()
{
	ilog "$*"
	rlog "$*"
}

bind_partitions()
{
	mount --bind /proc /mnt/proc
	mount --bind /dev /mnt/dev
	mount --bind /sys /mnt/sys
}

unmount_partition()
{
	if (grep -wq $1 /proc/mounts); then
		ilog "Unmounting $1"
		ilog "$(umount $1)"
		sync
	fi
}

unmount_partitions()
{
	ilog "Unmount partitions"
	for part in \
		/mnt/boot/efi \
		/mnt/sys/fs/fuse/connections \
		/mnt/sys/firmware/efi/efivars \
		/mnt/sys \
		/mnt/dev \
		/mnt/proc \
		/mnt
	do
		unmount_partition $part
	done

	sync

	UNMOUNT_RETRIES=${UNMOUNT_RETRIES:-"3"}
	unmount_retry=1
	while grep -qw '/mnt' /proc/mounts
	do
		if [ $unmount_retry -gt $UNMOUNT_RETRIES ]; then
			break
		fi
		for mp in $(grep -w '/mnt' /proc/mounts | awk '{print $2}' | sort -r)
		do
			unmount_partition $mp
		done
		unmount_retry=$((unmount_retry+1))
	done
}

save_log()
{
cat >> $LOG << EOF

############ BLK DEV INFO ###############
LSBLK:
$(lsblk -o NAME,LABEL,UUID,PARTUUID)

########################## DMESG ##########################
$(dmesg -x)
EOF
	sync
	for pw in $(grep "PASSWORD=" $LOG | cut -d '=' -f 2- | sed 's/["'\'']//'g)
	do
		sed -i -e "s,$pw,xxxxxx,g" $LOG
	done
	sync

	if [ "$UPDATE_DPU_OS" != "yes" ]; then
		return
	fi

	if [ ! -d /mnt/root ]; then
		mount -t $ROOTFS /dev/${root_device} /mnt
	fi
	cp $LOG /mnt/root
	umount /mnt
}

running_nic_fw()
{
	mstflint -d $cx_pcidev q 2>&1 | grep -w 'FW Version:' | awk '{print $NF}'
}

provided_nic_fw()
{
	$CHROOT ${FW_DIR}/mlxfwmanager_sriov_dis_aarch64_${cx_dev_id} --list 2> /dev/null | grep -w "${PSID}" | awk '{print $4}'
}

fw_update()
{
	if [[ -x ${FW_UPDATER} && -d ${FW_DIR} ]]; then
		BFB_NIC_FW_UPDATE=1
		NIC_FW_FOUND=1
	else
		if [ ! -d /mnt/root ]; then
			mount -t $ROOTFS /dev/${root_device} /mnt
			bind_partitions
		fi

		if [[ -x /mnt/${FW_UPDATER} && -d /mnt/${FW_DIR} ]]; then
			CHROOT="chroot /mnt"
			NIC_FW_FOUND=1
		fi
	fi

	if [ $NIC_FW_FOUND -eq 1 ]; then
		if [ "$(running_nic_fw)" == "$(provided_nic_fw)" ]; then
			if [ "${FORCE_NIC_FW_UPDATE}" == "yes" ]; then
				log "INFO: Installed NIC Firmware is the same as provided. FORCE_NIC_FW_UPDATE is set."
			else
				log "INFO: Installed NIC Firmware is the same as provided. Skipping NIC Firmware update."
				return
			fi
		fi

		log "INFO: Updating NIC firmware..."
		$CHROOT ${FW_UPDATER} --log /tmp/mlnx_fw_update.log -v \
			--force-fw-update \
			--fw-dir ${FW_DIR} > /tmp/mlnx_fw_update.out 2>&1
		rc=$?
		sync
		if [ -e /tmp/mlnx_fw_update.out ]; then
			cat /tmp/mlnx_fw_update.out > /dev/hvc0
			cat /tmp/mlnx_fw_update.out > /dev/ttyAMA0
			cat /tmp/mlnx_fw_update.out >> $LOG
		fi
		if [ -e /tmp/mlnx_fw_update.log ]; then
			cat /tmp/mlnx_fw_update.log > /dev/hvc0
			cat /tmp/mlnx_fw_update.log > /dev/ttyAMA0
			cat /tmp/mlnx_fw_update.log >> $LOG
		fi
		if [ $rc -ne 0 ] || (grep -q '\-E- Failed' /tmp/mlnx_fw_update.log > /dev/null 2>&1); then
			NIC_FW_UPDATE_PASSED=0
			log "INFO: NIC firmware update failed"
		else
			NIC_FW_UPDATE_PASSED=1
			log "INFO: NIC firmware update done: $(provided_nic_fw)"
		fi
		NIC_FW_UPDATE_DONE=1
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
	while ! (chroot /mnt mlxfwreset -d $cx_pcidev q 2>&1 | grep -w "Driver is the owner" | grep -qw "\-Supported")
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

	msg=$(chroot /mnt mlxfwreset -d $cx_pcidev -y -l 3 --sync 1 r 2>&1)
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
	# Get 128KB assuming it's big enough to hold the config file.
	dd if=${boot_fifo_path} of=${cfg_file} bs=4096 count=32 > /dev/null 2>&1

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
$(mstflint -d $cx_pcidev q)

DPU Part Number:
$dpu_part_number

MLXCONFIG:
$(mstconfig -d $cx_pcidev -e q)
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

ROOTFS=${ROOTFS:-"xfs"}
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

BMC_IP=${BMC_IP:-"192.168.240.1"}
BMC_PORT=${BMC_PORT:-"443"}
BMC_USER=${BMC_USER:-"root"}
DEFAULT_BMC_PASSWORD="0penBmc"
TMP_BMC_PASSWORD="Nvidia_12345!"
RESET_BMC_PASSWORD=0
BMC_PASSWORD=${BMC_PASSWORD:-""}
NEW_BMC_PASSWORD=${NEW_BMC_PASSWORD:-""}
UEFI_PASSWORD=${UEFI_PASSWORD:-""}
NEW_UEFI_PASSWORD=${NEW_UEFI_PASSWORD:-""}
OOB_IP=${OOB_IP:-"192.168.240.2"}
OOB_NETPREFIX=${OOB_NETPREFIX:-"29"}
BMC_IP_TIMEOUT=${BMC_IP_TIMEOUT:-600}
BMC_TASK_TIMEOUT=${BMC_TASK_TIMEOUT:-"1800"}
UPDATE_ATF_UEFI=${UPDATE_ATF_UEFI:-"yes"}
UPDATE_DPU_OS=${UPDATE_DPU_OS:-"yes"}
UPDATE_BMC_FW=${UPDATE_BMC_FW:-"yes"}
BMC_REBOOT=${BMC_REBOOT:-"no"}
UPDATE_CEC_FW=${UPDATE_CEC_FW:-"yes"}
CEC_MIN_RESET_VERSION="00.02.0180.0000"
UPDATE_DPU_GOLDEN_IMAGE=${UPDATE_DPU_GOLDEN_IMAGE:-"yes"}
UPDATE_NIC_FW_GOLDEN_IMAGE=${UPDATE_NIC_FW_GOLDEN_IMAGE:-"yes"}
WITH_NIC_FW_UPDATE=${WITH_NIC_FW_UPDATE:-"yes"}
NIC_FW_UPDATE_PASSED=0
NIC_FW_GI_PATH=${NIC_FW_GI_PATH:-"/BF3BMC/golden_images/fw"}
DPU_GI_PATH=${DPU_GI_PATH:-"/BF3BMC/golden_images/dpu"}
BMC_PATH=${BMC_PATH:-"/BF3BMC/bmc"}
CEC_PATH=${CEC_PATH:-"/BF3BMC/cec"}
BMC_CREDENTIALS="'{\"username\":\"$BMC_USER\", \"password\":\"${BMC_PASSWORD}\"}'"
BMC_LINK_UP="no"
export BMC_TOKEN=""
export task_id=""
export task_state=""
export task_status=""

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

default_device=/dev/mmcblk0
if [ -b /dev/nvme0n1 ]; then
	default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -V | tail -1)"
fi
device=${device:-"$default_device"}
root_device=${device/\/dev\/}p2

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

	mount ${device}p2 /mnt
	mkdir -p /mnt/boot/efi
	mount ${device}p1 /mnt/boot/efi
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

	cat > /mnt/etc/fstab << EOF
#
# /etc/fstab
#
#
$(get_part_id ${device}p2)  /           ${ROOTFS}     defaults                   0 1
$(get_part_id ${device}p1)  /boot/efi   vfat    umask=0077,shortname=winnt 0 2
EOF

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

if (lspci -n -d 15b3: | grep -wq 'a2dc'); then
	# BlueField-3 - remove mlnx-snap
	chroot /mnt rpm -e mlnx-snap || true
fi
}

configure_sfs()
{
	: > /mnt/etc/mellanox/mlnx-sf.conf

	for pciid in $(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')
	do
		cat >> /mnt/etc/mellanox/mlnx-sf.conf << EOF
/sbin/mlnx-sf --action create --device $pciid --sfnum 0 --hwaddr $(uuidgen | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')
EOF
	done
}

update_nic_firmware()
{
	if [ $NIC_FW_UPDATE_DONE -eq 0 ]; then
		fw_update
	fi
}

reset_nic_firmware()
{
	if [ $NIC_FW_UPDATE_DONE -eq 1 ]; then
		if [ $NIC_FW_UPDATE_PASSED -eq 1 ]; then
			# Reset NIC FW
			mount ${device}p2 /mnt
			bind_partitions
			fw_reset
			unmount_partitions
		fi
	fi
}

update_atf_uefi()
{
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
		umount /mnt/efi_system_partition
	fi
}

update_efi_bootmgr()
{
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
	fi

	ilog "Remove old boot entries"
	ilog "$(bfbootmgr --cleanall)"
	/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1
	/bin/rm -f /sys/firmware/efi/efivars/dump-* > /dev/null 2>&1
	ilog "$(efibootmgr -c -d $device -p 1 -l '\EFI\redhat\shimaa64.efi' -L $distro)"
	umount /sys/firmware/efi/efivars
}

update_uefi_boot_entries()
{
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
BOOT7=NET-NIC_P0-IPV4-HTTP
BOOT8=NET-NIC_P1-IPV4-HTTP
BOOT9=NET-OOB-IPV4-HTTP
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
}

configure_dhcp()
{
	ilog "Configure dhcp:"
	mkdir -p /mnt/etc/dhcp
	cat >> /mnt/etc/dhcp/dhclient.conf << EOF
send vendor-class-identifier "$DHCP_CLASS_ID_DP";
interface "oob_net0" {
  send vendor-class-identifier "$DHCP_CLASS_ID_OOB";
}
EOF

# Enable NetworkManager for ifcfg-enp3s0f0s0 and ifcfg-enp3s0f1s0
sed -i 's@NM_CONTROLLED="no"@NM_CONTROLLED="yes"@' /mnt/etc/sysconfig/network-scripts/ifcfg-enp3s0f0s0
sed -i 's@NM_CONTROLLED="no"@NM_CONTROLLED="yes"@' /mnt/etc/sysconfig/network-scripts/ifcfg-enp3s0f1s0
}

configure_services()
{
	chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service
	chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service
	chroot /mnt /bin/systemctl enable serial-getty@hvc0.service

	# Disable Firewall services
	/bin/rm -f /mnt/etc/systemd/system/multi-user.target.wants/firewalld.service
	/bin/rm -f /mnt/etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service
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
	sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"crashkernel=auto $bootarg console=hvc0 console=ttyAMA0 earlycon=pl011,0x01000000 net.ifnames=0 biosdevname=0 iommu.passthrough=1\"@" /mnt/etc/default/grub
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

cleanup_target_os()
{
	# Clean up logs
	echo > /mnt/var/log/messages
	echo > /mnt/var/log/maillog
	echo > /mnt/var/log/secure
	echo > /mnt/var/log/firewalld
	/bin/rm -f /mnt/var/log/yum.log
	/bin/rm -rf /mnt/tmp/*
}

install_dpu_os()
{
	log "INFO: $distro installation started"

	prepare_target_partitions

	if function_exists bfb_pre_install; then
		log "INFO: Running bfb_pre_install from bf.cfg"
		bfb_pre_install
	fi

	ilog "Extracting /..."
	export EXTRACT_UNSAFE_SYMLINKS=1
	tar Jxf $fspath/image.tar.xz --warning=no-timestamp -C /mnt
	sync

	configure_target_os

	configure_sfs

	configure_services

	configure_dhcp

	bind_partitions

	create_initramfs

	configure_grub

	cleanup_target_os

	if function_exists bfb_modify_os; then
		log "INFO: Running bfb_modify_os from bf.cfg"
		bfb_modify_os
	fi

	sync

	update_efi_bootmgr

	update_uefi_boot_entries

	set_root_password
}

skip_bmc()
{
	log "WARN Skipping BMC components upgrade."
	RC=$((RC+1))
	UPDATE_BMC_FW="no"
	UPDATE_CEC_FW="no"
	UPDATE_DPU_GOLDEN_IMAGE="no"
	UPDATE_NIC_FW_GOLDEN_IMAGE="no"
}

wait_for_bmc_ip()
{
    SECONDS=0
    while ! (ping -c 3 $BMC_IP > /dev/null 2>&1)
    do
        sleep 10
        if [ $SECONDS -gt $BMC_IP_TIMEOUT ]; then
            if ! (ping -c 3 $BMC_IP > /dev/null 2>&1); then
                rlog "ERR Failed to access BMC"
                ilog "- ERROR: Failed to access $BMC_IP after $SECONDS sec."
                RC=$((RC+1))
            fi
        fi
    done
    sleep 60
}

create_vlan()
{
	ilog "Creating VLAN 4040"
	if [ ! -d "/sys/bus/platform/drivers/mlxbf_gige" ]; then
		ilog "- ERROR: mlxbf_gige driver is not loaded"
		RC=$((RC+1))
		return
	fi
	OOB_IF=$(ls -1 "/sys/bus/platform/drivers/mlxbf_gige/MLNXBF17:00/net")
	ilog "Configuring VLAN id 4040 on ${OOB_IF}. This operation may take up to $BMC_IP_TIMEOUT seconds"
	SECONDS=0
	while ! ip link show vlan4040 | grep -w '<BROADCAST,MULTICAST,UP,LOWER_UP>'; do
		if [ $SECONDS -gt $BMC_IP_TIMEOUT ]; then
			rlog "ERR Failed to create VLAN."
			ilog "- ERROR: Failed to create VLAN interface after $SECONDS sec. All the BMC related operations will be skipped."
			skip_bmc
			return
		fi
		ip link add link ${OOB_IF} name vlan4040 type vlan id 4040
		if ! (dhclient vlan4040); then
			ip addr add ${OOB_IP}/${OOB_NETPREFIX} brd + dev vlan4040
		fi
		ip link set dev ${OOB_IF} up
		ip link set dev vlan4040 up
		sleep 1
	done
	while ! ping -c 3 $BMC_IP; do
		if [ $SECONDS -gt $BMC_IP_TIMEOUT ]; then
			rlog "ERR Failed to access BMC"
			ilog "- ERROR: Failed to access $BMC_IP after $SECONDS sec."
			skip_bmc
			return
		fi
		sleep 1
	done
	ilog "$(ip link show vlan4040)"
	BMC_LINK_UP="yes"
}

get_bmc_token()
{
	cmd=$(echo curl -sSk -H \"Content-Type: application/json\" -X POST https://${BMC_IP}/login -d $BMC_CREDENTIALS)
	BMC_TOKEN=$(eval $cmd | jq -r ' .token')
	if [[ -z "$BMC_TOKEN" || "$BMC_TOKEN" == "null" ]]; then
		rlog "ERR Failed to get BMC token. Check BMC user/password"
		ilog "- ERROR: Failed to get BMC token using command: $cmd. Check BMC user/password."
		RC=$((RC+1))
		return 1
	fi
	return 0
}

change_uefi_password()
{
	UEFI_CREDENTIALS="'{\"Attributes\":{\"CurrentUefiPassword\":\"$UEFI_PASSWORD\",\"UefiPassword\":\"${NEW_UEFI_PASSWORD}\"}}'"
	cmd=$(echo curl -sSk -u $BMC_USER:"$BMC_PASSWORD" -H \"Content-Type: application/json\" -X PATCH https://${BMC_IP}/redfish/v1/Systems/Bluefield/Bios/Settings -d $UEFI_CREDENTIALS)
	output=$(eval $cmd)
	status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
	if [ "$status" != "\"The request completed successfully."\" ]; then
		rlog "ERR Failed to change UEFI password."
		ilog "Failed to change UEFI password. Output: $output"
		return 1
	fi

	ilog "UEFI password is set for the update. The new password will be activated on the second DPU reboot."

	return 0
}

change_bmc_password()
{
	current_password="$1"
	new_password="$2"

	NEW_BMC_CREDENTIALS="'{\"Password\":\"${new_password}\"}'"
	cmd=$(echo curl -sSk -u $BMC_USER:$current_password  -H \"Content-Type: application/json\" -X PATCH https://${BMC_IP}/redfish/v1/AccountService/Accounts/$BMC_USER -d $NEW_BMC_CREDENTIALS)
	output=$(eval $cmd)
	status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
	if [ "$status" != "\"The request completed successfully."\" ]; then
		rlog "ERR Failed to change BMC $BMC_USER password."
		ilog "Failed to change the password. Output: $output"
		return 1
	fi

	ilog "BMC password updated successfully."

	return 0
}

get_bmc_public_key()
{
		get_bmc_token
        SSH_PUBLIC_KEY=$(ssh-keyscan -t ed25519 ${OOB_IP} 2>&1 | tail -1 | cut -d ' ' -f 2-)

        pk_cmd=$(echo curl -sSk -H \"X-Auth-Token: $BMC_TOKEN\" -H \"Content-Type: application/json\" -X POST -d \'{\"RemoteServerIP\":\"${BMC_IP}\", \"RemoteServerKeyString\":\"$SSH_PUBLIC_KEY\"}\' https://$BMC_IP/redfish/v1/UpdateService/Actions/Oem/NvidiaUpdateService.PublicKeyExchange)
        bmc_pk=$(eval $pk_cmd | jq -r ' .Resolution')
		if [ "$bmc_pk" != "null" ]; then
			echo "$bmc_pk" >> /root/.ssh/authorized_keys
		fi
}

bmc_get_task_id()
{
	get_bmc_token
	task_id=$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/TaskService/Tasks | jq -r ' .Members' | grep odata.id | tail -1 | awk '{print $NF}' | tr -d '"')
	ilog "Task id: $task_id"
}

wait_bmc_task_complete()
{
	bmc_get_task_id
	if [ -z "${task_id}" ]; then
		ilog "No active BMC task"
		return
	fi
	output=$(mktemp)
	#Check upgrade progress (%).
	get_bmc_token
	curl -sSk -H "X-Auth-Token: $BMC_TOKEN" https://${BMC_IP}${task_id} > $output
	percent_done=$(cat $output | jq -r ' .PercentComplete')
	SECONDS=0
	while [ "$percent_done" != "100" ]; do
		if [ $SECONDS -gt $BMC_TASK_TIMEOUT ]; then
			ilog "- ERROR: BMC task $task_id timeout"
			RC=$((RC+1))
			break
		fi
		get_bmc_token
		curl -sSk -H "X-Auth-Token: $BMC_TOKEN" https://${BMC_IP}${task_id} > $output
		percent_done=$(cat $output | jq -r ' .PercentComplete')
		sleep 10
	done
	task_state=$(jq '.TaskState' $output | tr -d '"')
	task_status=$(jq '.TaskStatus' $output | tr -d '"')

	if [ "$task_state$task_status" != "CompletedOK" ]; then
		echo "BMC task failed:"  >> $LOG
		cat $output >> $LOG
		RC=$((RC+1))
	fi
	/bin/rm -f $output
}

update_bmc_fw()
{
	wait_bmc_task_complete
	log "Updating BMC firmware"
	#Set upload image from local BFB storage (or tempfs).
	image=$(/bin/ls -1 ${BMC_PATH}/*bmc* 2> /dev/null)
	if [ -z "$image" ]; then
		ilog "- ERROR: Cannot find BMC firmware image"
		RC=$((RC+1))
		return
	fi
	ilog "Found BMC firmware image: $image"

	BMC_IMAGE_VERSION="$(echo $image | grep -o "\([0-9]\+\).\([0-9]\+\)-\([0-9]\+\)" | tr -s '-' '.')"
	if [ -z "$BMC_IMAGE_VERSION" ]; then
		ilog "- ERROR: Cannot detect included BMC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Provided BMC firmware version: $BMC_IMAGE_VERSION"

	get_bmc_token

	BMC_FIRMWARE_URL=$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/UpdateService/FirmwareInventory | grep BMC_Firmware | awk '{print $NF}' | tr -d \")
	ilog "- INFO: BMC_FIRMWARE_URL: $BMC_FIRMWARE_URL"
	BMC_INSTALLED_VERSION="$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}${BMC_FIRMWARE_URL} | jq -r ' .Version' | grep -o "\([0-9]\+\).\([0-9]\+\)-\([0-9]\+\)" | tr -s '-' '.')"
	if [ -z "$BMC_INSTALLED_VERSION" ]; then
		ilog "- ERROR: Cannot detect running BMC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Running BMC firmware version: $BMC_INSTALLED_VERSION"

	if [ "${BMC_IMAGE_VERSION}" == "${BMC_INSTALLED_VERSION}" ]; then
		ilog "Installed BMC version is the same as provided. Skipping BMC firmware update."
		return
	fi

	# Set firmware update URI.
	# get_bmc_token
	# uri=$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" https://${BMC_IP}/redfish/v1/UpdateService | jq -r ' .HttpPushUri')

	#Upload BMC image to BMC. BMC will begin PLDM upgrade automatically.
	ilog "Proceeding with the BMC firmware update."
	uri="/redfish/v1/UpdateService"
	curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -H "Content-Type: application/octet-stream" -X POST -T ${image} https://${BMC_IP}${uri}
	BMC_FIRMWARE_UPDATED="yes"

	wait_bmc_task_complete
	if [ "$BMC_REBOOT" != "yes" ]; then
		log "INFO: BMC firmware was updated to: ${BMC_IMAGE_VERSION}. BMC restart is required."
	fi
}

update_cec_fw()
{
	wait_bmc_task_complete
	log "Updating CEC firmware"
	#Set upload image from local BFB storage (or tempfs).
	image=$(/bin/ls -1 ${CEC_PATH}/cec*)

	if [ -z "$image" ]; then
		ilog "- ERROR: Cannot find CEC firmware image"
		RC=$((RC+1))
		return
	fi
	ilog "Found CEC firmware image: $image"

	CEC_IMAGE_VERSION="$(echo $image | grep -o "\([0-9]\+\).\([0-9]\+\).\([0-9]\+\).\([0-9]\+\)-\([a-z]\+\)\([0-9]\+\)" | tr -s '-' '.')"
	if [ -z "$CEC_IMAGE_VERSION" ]; then
		ilog "- ERROR: Cannot detect included CEC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Provided CEC firmware version: $CEC_IMAGE_VERSION"

	get_bmc_token

	CEC_INSTALLED_VERSION="$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/UpdateService/FirmwareInventory/Bluefield_FW_ERoT | jq -r ' .Version' | sed -e "s/[_|-]/./g")"
	if [ -z "$CEC_INSTALLED_VERSION" ]; then
		ilog "- ERROR: Cannot detect running CEC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Running CEC firmware version: $CEC_INSTALLED_VERSION"

	if [ "${CEC_IMAGE_VERSION}" == "${CEC_INSTALLED_VERSION}" ]; then
		ilog "Installed CEC version is the same as provided. Skipping CEC firmware update."
		return
	fi

	ilog "Proceeding with the CEC firmware update..."

	uri="/redfish/v1/UpdateService"
	curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -H "Content-Type: application/octet-stream" -X POST -T ${image} https://${BMC_IP}${uri}

	wait_bmc_task_complete
	if [[ $(echo -e ${CEC_MIN_RESET_VERSION}\n${CEC_INSTALLED_VERSION} | sort -V | head -n1) == "${CEC_MIN_RESET_VERSION}" ]]; then
		output=$(curl -sSk -u $BMC_USER:"$BMC_PASSWORD" -H "Content-Type: application/json" -X POST -d '{"ResetType": "GracefulRestart"}' https://${BMC_IP}/redfish/v1/Chassis/Bluefield_ERoT/Actions/Chassis.Reset)
		status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
		if [ "$status" != "\"The request completed successfully."\" ]; then
			rlog "ERR Failed to reset CEC"
			ilog "Failed to reset CEC. Output: $output"
			log "INFO: CEC firmware was updated to ${CEC_IMAGE_VERSION}. Host power cycle is required"
		fi
	else
		log "INFO: CEC firmware was updated to ${CEC_IMAGE_VERSION}. Host power cycle is required"
	fi
}

bmc_reboot()
{
	log "Rebooting BMC..."
	get_bmc_token
	curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -H "Content-Type: application/json" -X POST https://${BMC_IP}/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.Reset -d '{"ResetType":"GracefulRestart"}'
	sleep 10
	wait_for_bmc_ip
}

update_dpu_golden_image()
{
	log "Updating DPU Golden Image"
	image=$(/bin/ls -1 ${DPU_GI_PATH}/BlueField*preboot-install.bfb)

	if [ -z "$image" ]; then
		ilog "DPU golden image was not found"
		RC=$((RC+rc))
		return
	fi

	ilog "Found DPU Golden Image: $image"
	DPU_GI_IMAGE_VERSION="$(sha256sum $image | awk '{print $1}')"
	ilog "Provided DPU Golden Image version: $DPU_GI_IMAGE_VERSION"

	DPU_GI_INSTALLED_VERSION="$(sshpass -p $BMC_PASSWORD $SSH ${BMC_USER}@${BMC_IP} dpu_golden_image golden_image_arm -V 2> /dev/null)"
	ilog "Installed DPU Golden Image version: $DPU_GI_INSTALLED_VERSION"

	if [ "$DPU_GI_IMAGE_VERSION" == "$DPU_GI_INSTALLED_VERSION" ]; then
		ilog "Installed DPU Golden Image version is the same as provided. Skipping DPU Golden Image update."
		return
	fi

	sshpass -p $BMC_PASSWORD $SCP $image ${BMC_USER}@${BMC_IP}:/tmp/
	sshpass -p $BMC_PASSWORD $SSH ${BMC_USER}@${BMC_IP} dpu_golden_image golden_image_arm -w /tmp/$(basename $image)
}

update_nic_firmware_golden_image()
{
	log "Updating NIC firmware Golden Image"
	image=$(/bin/ls -1 ${NIC_FW_GI_PATH}/*${dpu_part_number}* 2> /dev/null)

	if [ -z "$image" ]; then
		ilog "NIC firmware Golden Image for $dpu_part_number was not found"
		RC=$((RC+rc))
		return
	fi

	ilog "Found NIC firmware Golden Image: $image"
	NIC_GI_IMAGE_VERSION="$(sha256sum $image | awk '{print $1}')"
	ilog "Provided NIC firmware Golden Image version: $NIC_GI_IMAGE_VERSION"

	NIC_GI_INSTALLED_VERSION="$(sshpass -p $BMC_PASSWORD $SSH ${BMC_USER}@${BMC_IP} dpu_golden_image golden_image_nic -V 2> /dev/null)"
	ilog "Installed NIC firmware Golden Image version: $NIC_GI_INSTALLED_VERSION"

	if [ "$NIC_GI_IMAGE_VERSION" == "$NIC_GI_INSTALLED_VERSION" ]; then
		ilog "Installed NIC firmware Golden Image version is the same as provided. Skipping NIC firmware Golden Image update."
		return
	fi

	sshpass -p $BMC_PASSWORD $SCP $image ${BMC_USER}@${BMC_IP}:/tmp/
	sshpass -p $BMC_PASSWORD $SSH ${BMC_USER}@${BMC_IP} dpu_golden_image golden_image_nic -w /tmp/$(basename $image)
}

bmc_components_update()
{
	if function_exists pre_bmc_components_update; then
		log "INFO: Running pre_bmc_components_update from bf.cfg"
		pre_bmc_components_update
	fi

	if [[ ! -z "$UEFI_PASSWORD" && ! -z "$NEW_UEFI_PASSWORD" ]]; then
		if [[ -z "$BMC_USER" || -z "$BMC_PASSWORD" ]]; then
			ilog "BMC_USER and/or BMC_PASSWORD are not defined. Skipping UEFI password change."
		else
			change_uefi_password
		fi
	fi

	if [[ "$UPDATE_BMC_FW" == "yes" || "$UPDATE_CEC_FW" == "yes" || "$UPDATE_DPU_GOLDEN_IMAGE" == "yes" || "$UPDATE_NIC_FW_GOLDEN_IMAGE" == "yes" || ! -z "$NEW_BMC_PASSWORD" ]]; then
		if [[ -z "$BMC_USER" || -z "$BMC_PASSWORD" ]]; then
			ilog "BMC_USER and/or BMC_PASSWORD are not defined. Skipping BMC components upgrade."
			skip_bmc
			return
		else
			ilog "INFO: Running BMC components update flow"
			create_vlan
			# get_bmc_public_key
			if [ "$BMC_LINK_UP" == "yes" ]; then
				if [ ! -z "$NEW_BMC_PASSWORD" ]; then
					if change_bmc_password "$BMC_PASSWORD" "$NEW_BMC_PASSWORD"; then
						BMC_PASSWORD="$NEW_BMC_PASSWORD"
					else
						skip_bmc
						return
					fi
				elif [ "$BMC_PASSWORD" == "$DEFAULT_BMC_PASSWORD" ]; then
					ilog "BMC password has the default value. Changing to the temporary password."
					if change_bmc_password "$BMC_PASSWORD" "$TMP_BMC_PASSWORD"; then
						BMC_PASSWORD="$TMP_BMC_PASSWORD"
					else
						skip_bmc
						return
					fi
					RESET_BMC_PASSWORD=1
				fi
				BMC_CREDENTIALS="'{\"username\":\"$BMC_USER\", \"password\":\"${BMC_PASSWORD}\"}'"
			else
				skip_bmc
				return
			fi
		fi

		if ! get_bmc_token; then
			skip_bmc
			return
		fi

	else
		return
	fi

	if function_exists bmc_custom_action1; then
		log "INFO: Running bmc_custom_action1 from bf.cfg"
		bmc_custom_action1
	fi

	if [[ "$UPDATE_BMC_FW" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_bmc_fw
	fi

	if function_exists bmc_custom_action2; then
		log "INFO: Running bmc_custom_action2 from bf.cfg"
		bmc_custom_action2
	fi

	if [[ "$UPDATE_CEC_FW" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_cec_fw
	fi

	if function_exists bmc_custom_action3; then
		log "INFO: Running bmc_custom_action3 from bf.cfg"
		bmc_custom_action3
	fi

	if [[ "$UPDATE_BMC_FW" == "yes" && "$BMC_LINK_UP" == "yes" && "$BMC_REBOOT" == "yes" && "$BMC_FIRMWARE_UPDATED" == "yes" ]]; then
		bmc_reboot
	fi

	if function_exists bmc_custom_action4; then
		log "INFO: Running bmc_custom_action4 from bf.cfg"
		bmc_custom_action4
	fi

	if [[ "$UPDATE_DPU_GOLDEN_IMAGE" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_dpu_golden_image
	fi

	if [ $RESET_BMC_PASSWORD -eq 1 ]; then
		ilog "Reset BMC configuration to default"
		output=$(curl -k -u $BMC_USER:"$BMC_PASSWORD" -H "Content-Type: application/json" -X POST https://${BMC_IP}/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.ResetToDefaults -d '{"ResetToDefaultsType": "ResetAll"}')
		status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
		if [ "$status" != "\"The request completed successfully."\" ]; then
			rlog "ERR Failed to reset BMC $BMC_USER password."
			ilog "Failed to reset BMC $BMC_USER password. Output: $output"
		fi
	fi

	if [[ "$UPDATE_NIC_FW_GOLDEN_IMAGE" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_nic_firmware_golden_image
	fi

	if function_exists post_bmc_components_update; then
		log "INFO: Running post_bmc_components_update from bf.cfg"
		post_bmc_components_update
	fi
}

if [ "$UPDATE_DPU_OS" == "yes" ]; then
	install_dpu_os
fi

if function_exists bfb_custom_action1; then
	log "INFO: Running bfb_custom_action1 from bf.cfg"
	bfb_custom_action1
fi

if [ "$UPDATE_ATF_UEFI" == "yes" ]; then
	update_atf_uefi
fi

if function_exists bfb_custom_action2; then
	log "INFO: Running bfb_custom_action2 from bf.cfg"
	bfb_custom_action2
fi

if [[ "$UPDATE_BMC_FW" == "yes" || "$UPDATE_CEC_FW" == "yes" || "$UPDATE_DPU_GOLDEN_IMAGE" == "yes" || "$UPDATE_NIC_FW_GOLDEN_IMAGE" == "yes" ]]; then
	bmc_components_update
fi

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	update_nic_firmware
fi

unmount_partitions

if function_exists bfb_post_install; then
	log "INFO: Running bfb_post_install from bf.cfg"
	bfb_post_install
fi

log "INFO: Installation finished"

if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
	reset_nic_firmware
fi

save_log
sleep 3
log "INFO: Rebooting..."
# Wait for these messages to be pulled by the rshim service
sleep 3
