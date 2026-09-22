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

distro="Ubuntu"
BDIR=$(dirname $0)

load_module()
{
	local mod=$1

	modprobe $mod
}

# Check NIC mode
is_nic_mode=0
cx_pcidev=$(lspci -nD 2> /dev/null | grep 15b3:a2df | awk '{print $1}' | head -1)
str=`mlxconfig -d $cx_pcidev -e q INTERNAL_CPU_OFFLOAD_ENGINE 2>/dev/null | grep INTERNAL_CPU_OFFLOAD_ENGINE | awk '{print $(NF-1)}'`
if [ ."$str" = ."DISABLED(1)" ]; then
    is_nic_mode=1
fi

if [ $is_nic_mode -eq 0 ]; then
    load_module mlx5_core
    load_module mlx5_ib
    load_module mlxfw
    load_module ib_umad
    load_module nvme
fi


#
# Check PXE installation
#
if [ ! -e /tmp/bfpxe.done ]; then touch /tmp/bfpxe.done; bfpxe; fi

DUAL_BOOT="no"
ROOTFS=${ROOTFS:-"ext4"}
SET_EXT4_JOURNAL_DATA=${SET_EXT4_JOURNAL_DATA:-"yes"}

# Enable mlx5_core async probe on BF-4 (default: no)
ENABLE_MLX5_ASYNC_PROBE=${ENABLE_MLX5_ASYNC_PROBE:-"no"}

if [ -e ${BDIR}/install.env/common ]; then
	. ${BDIR}/install.env/common
else
	ilog "WARNING: ${BDIR}/install.env/common is missing"
fi

default_device=/dev/mmcblk0
if [ -b /dev/nvme0n1 ]; then
	default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -V | tail -1)"
fi
device=${device:-"$default_device"}
BOOT_PARTITION=${device}p1
ROOT_PARTITION=${device}p2
echo 0 > /proc/sys/kernel/hung_task_timeout_secs

prepare_target_partitions()
{
	ilog "OS installation target: $device"

	wait_for_device $device

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
}

mount_target_partition()
{
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

	if [[ "X$ROOTFS" == "Xext4" && "X$SET_EXT4_JOURNAL_DATA" == "Xyes" ]]; then
		tune2fs -o journal_data $ROOT_PARTITION
	fi

	mkdir -p /mnt
	mount -t ${ROOTFS} $ROOT_PARTITION /mnt
	mkdir -p /mnt/boot/efi
	mount -t vfat $BOOT_PARTITION /mnt/boot/efi

} # End of prepare_target_partitions

configure_target_os()
{
	if [ "${FSTAB_USE_DEV_NAME}" == "yes" ]; then
		cat > /mnt/etc/fstab << EOF
$ROOT_PARTITION / auto defaults 0 1
$BOOT_PARTITION /boot/efi vfat umask=0077 0 2
EOF
	else
		cat > /mnt/etc/fstab << EOF
$(get_part_id $ROOT_PARTITION) / auto defaults 0 1
$(get_part_id $BOOT_PARTITION) /boot/efi vfat umask=0077 0 2
EOF
	fi

	if [ "X$DUAL_BOOT" == "Xyes" ]; then
		if [ "${FSTAB_USE_DEV_NAME}" == "yes" ]; then
			cat >> /mnt/etc/fstab << EOF
$COMMON_PARTITION /common auto defaults 0 2
EOF
		else
			cat >> /mnt/etc/fstab << EOF
$(get_part_id $COMMON_PARTITION) /common auto defaults 0 2
EOF
		fi
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

	# Update HW-dependant files: BlueField-4
	chroot /mnt env PATH=$CHROOT_PATH apt remove -y --purge mlnx-snap || true
} # End of configure_target_os

update_efi_bootmgr()
{
	ilog "Adding $distro boot entry:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	UBUNTU_CODENAME=$(grep ^ID= /mnt/etc/os-release | cut -d '=' -f 2)

	if efibootmgr | grep ${UBUNTU_CODENAME}; then
		efibootmgr -b "$(efibootmgr | grep ${UBUNTU_CODENAME} | cut -c 5-8)" -B > /dev/null 2>&1
	fi
	ilog "$(efibootmgr -c -d $device -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l '\EFI\ubuntu\shimaa64.efi')"

	if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
		log "ERR Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry. Retrying..."
		ilog "efibootmgr -c -d $device -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l '\EFI\ubuntu\shimaa64.efi'"
		if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
			bfbootmgr --cleanall > /dev/null 2>&1
			efibootmgr -c -d "$device" -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l "\EFI\ubuntu\shimaa64.efi" > /dev/null 2>&1
			if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
				log "ERR Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry."
			fi
		fi
	fi

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_services()
{
	ilog "$(chroot /mnt /bin/systemctl enable serial-getty@ttyAMA0.service > /dev/null 2>&1)"
	ilog "$(chroot /mnt /bin/systemctl enable serial-getty@ttyAMA1.service > /dev/null 2>&1)"
	ilog "$(chroot /mnt /bin/systemctl enable serial-getty@hvc0.service > /dev/null 2>&1)"
}

enable_sfc_hbn()
{
	ilog "Stage deferred SFC-HBN install"
	ARG_PORT0=""
	ARG_PORT1=""
	# initial sfc parameters
	if ! [ -z "${NUM_VFs_PHYS_PORT0}" ]; then
		ARG_PORT0="--ecpf0 "${NUM_VFs_PHYS_PORT0}
	fi
	if ! [ -z "${NUM_VFs_PHYS_PORT1}" ]; then
		ARG_PORT1="--ecpf1 "${NUM_VFs_PHYS_PORT1}
	fi
	# configurable sf/vf mapping
	HBN_UPLINKS=${HBN_UPLINKS:-"p0,p1"}
	HBN_REPS=${HBN_REPS:-"c1pf0,c1pf1"}
	HBN_DPU_SFS=${HBN_DPU_SFS:-"pf0dpu1,pf0dpu3"}
	# generic steering bridge mapping
	if ! [ -z "${BR_HBN_UPLINKS-x}" ]; then
		BR_HBN_UPLINKS=${BR_HBN_UPLINKS:-"$HBN_UPLINKS"}
	fi
	if ! [ -z "${BR_HBN_REPS-x}" ]; then
		BR_HBN_REPS=${BR_HBN_REPS:-"$HBN_REPS"}
	fi
	if ! [ -z "${BR_HBN_SFS-x}" ]; then
		BR_HBN_SFS=${BR_HBN_SFS:-"$HBN_DPU_SFS"}
	fi
	BR_SFC_UPLINKS=${BR_SFC_UPLINKS:-""}
	BR_SFC_REPS=${BR_SFC_REPS:-""}
	BR_SFC_SFS=${BR_SFC_SFS:-""}
	BR_HBN_SFC_PATCH_PORTS=${BR_HBN_SFC_PATCH_PORTS:-""}
	LINK_PROPAGATION=${LINK_PROPAGATION:-""}
	ENABLE_BR_SFC=${ENABLE_BR_SFC:-""}
	ENABLE_BR_SFC_DEFAULT_FLOWS=${ENABLE_BR_SFC_DEFAULT_FLOWS:-""}
	HUGEPAGE_SIZE=${HUGEPAGE_SIZE:-""}
	HUGEPAGE_COUNT=${HUGEPAGE_COUNT:-""}
	HBN_PROFILE=${HBN_PROFILE:-"default"}
	HBN_IFNAME_WAIT_TIMEOUT=${HBN_IFNAME_WAIT_TIMEOUT:-300}
	HBN_IFNAME_WAIT_INTERVAL=${HBN_IFNAME_WAIT_INTERVAL:-10}
	BR_HBN_VF_GROUPS=${BR_HBN_VF_GROUPS:-"c1pf0:0-13"}
	BR_SFC_VF_GROUPS=${BR_SFC_VF_GROUPS:-""}
	CLOUD_OPTION=${CLOUD_OPTION:-""}
	# install.sh needs a fully running system (mlnx_bf_configure must create the
	# uplinks/representors first), which is not the case in this installer chroot.
	# Stage its parameters into the target rootfs (/mnt) so
	# sfc-hbn-deferred-install.service can run it on first boot. The
	# reboot-requiring half still runs here, via provisioning-install.sh below.
	log "INFO: Staging deferred SFC-HBN install"
	mkdir -p /mnt/etc/mellanox
	cat > /mnt/etc/mellanox/sfc-hbn-deferred-install.env <<EOF
BR_HBN_UPLINKS="${BR_HBN_UPLINKS}"
BR_HBN_REPS="${BR_HBN_REPS}"
BR_HBN_SFS="${BR_HBN_SFS}"
BR_SFC_UPLINKS="${BR_SFC_UPLINKS}"
BR_SFC_REPS="${BR_SFC_REPS}"
BR_SFC_SFS="${BR_SFC_SFS}"
BR_HBN_SFC_PATCH_PORTS="${BR_HBN_SFC_PATCH_PORTS}"
LINK_PROPAGATION="${LINK_PROPAGATION}"
ENABLE_BR_SFC="${ENABLE_BR_SFC}"
ENABLE_BR_SFC_DEFAULT_FLOWS="${ENABLE_BR_SFC_DEFAULT_FLOWS}"
HUGEPAGE_SIZE="${HUGEPAGE_SIZE}"
HUGEPAGE_COUNT="${HUGEPAGE_COUNT}"
CLOUD_OPTION="${CLOUD_OPTION}"
HBN_PROFILE="${HBN_PROFILE}"
HBN_IFNAME_WAIT_TIMEOUT="${HBN_IFNAME_WAIT_TIMEOUT}"
HBN_IFNAME_WAIT_INTERVAL="${HBN_IFNAME_WAIT_INTERVAL}"
BR_HBN_VF_GROUPS="${BR_HBN_VF_GROUPS}"
BR_SFC_VF_GROUPS="${BR_SFC_VF_GROUPS}"
HBN_UPLINKS="${HBN_UPLINKS}"
HBN_REPS="${HBN_REPS}"
HBN_DPU_SFS="${HBN_DPU_SFS}"
ARG_PORT0="${ARG_PORT0}"
ARG_PORT1="${ARG_PORT1}"
EOF

	log "INFO: Staged SFC HBN environment for deferred install"
	ilog "BR_HBN_UPLINKS=${BR_HBN_UPLINKS} BR_HBN_REPS=${BR_HBN_REPS} BR_HBN_SFS=${BR_HBN_SFS} BR_SFC_UPLINKS=${BR_SFC_UPLINKS} BR_SFC_REPS=${BR_SFC_REPS} BR_SFC_SFS=${BR_SFC_SFS} BR_HBN_SFC_PATCH_PORTS=${BR_HBN_SFC_PATCH_PORTS} LINK_PROPAGATION=${LINK_PROPAGATION} ENABLE_BR_SFC=${ENABLE_BR_SFC} ENABLE_BR_SFC_DEFAULT_FLOWS=${ENABLE_BR_SFC_DEFAULT_FLOWS} HUGEPAGE_SIZE=${HUGEPAGE_SIZE} HUGEPAGE_COUNT=${HUGEPAGE_COUNT} CLOUD_OPTION=${CLOUD_OPTION} HBN_PROFILE=${HBN_PROFILE} HBN_IFNAME_WAIT_TIMEOUT=${HBN_IFNAME_WAIT_TIMEOUT} HBN_IFNAME_WAIT_INTERVAL=${HBN_IFNAME_WAIT_INTERVAL} BR_HBN_VF_GROUPS=${BR_HBN_VF_GROUPS} BR_SFC_VF_GROUPS=${BR_SFC_VF_GROUPS} ARG_PORT0=${ARG_PORT0} ARG_PORT1=${ARG_PORT1}"


	mkdir -p /mnt/var/lib/sfc-hbn
	touch /mnt/var/lib/sfc-hbn/install-pending

	# Block SSH so users cannot log in to a half-configured system. Best
	# effort: provisioning-install.sh below re-arranges SSH itself
	# (configure_ssh, mgmt VRF) so it can come up early on first boot while
	# install.sh is still wiring.
	chroot /mnt systemctl disable ssh.socket ssh.service >/dev/null 2>&1 || true

	# Arm the deferred one-shot. The unit is already installed at
	# /etc/systemd/system/sfc-hbn-deferred-install.service by the sfc-hbn package.
	chroot /mnt systemctl enable sfc-hbn-deferred-install.service

	# Drop the default sfnum-0 SFs staged by configure_sfs(): without the
	# post-install reboot they would linger next to the SFs that install.sh creates.
	: > /mnt/etc/mellanox/mlnx-sf.conf

	# Run provisioning-install.sh in the chroot now so the post-install power cycle applies
	# the reboot-requiring configuration. provisioning-done records success;
	# without it the first-boot install.sh aborts.
	log "INFO: Running SFC-HBN provisioning install (provisioning-install.sh)"
	if chroot /mnt env PATH=$CHROOT_PATH \
		BR_HBN_UPLINKS="${BR_HBN_UPLINKS}" BR_HBN_REPS="${BR_HBN_REPS}" BR_HBN_SFS="${BR_HBN_SFS}" \
		BR_SFC_UPLINKS="${BR_SFC_UPLINKS}" BR_SFC_REPS="${BR_SFC_REPS}" BR_SFC_SFS="${BR_SFC_SFS}" \
		BR_HBN_SFC_PATCH_PORTS="${BR_HBN_SFC_PATCH_PORTS}" LINK_PROPAGATION="${LINK_PROPAGATION}" \
		ENABLE_BR_SFC="${ENABLE_BR_SFC}" ENABLE_BR_SFC_DEFAULT_FLOWS="${ENABLE_BR_SFC_DEFAULT_FLOWS}" \
		CLOUD_OPTION="${CLOUD_OPTION}" HBN_PROFILE="${HBN_PROFILE}" HBN_IFNAME_WAIT_TIMEOUT="${HBN_IFNAME_WAIT_TIMEOUT}" \
		HBN_IFNAME_WAIT_INTERVAL="${HBN_IFNAME_WAIT_INTERVAL}" BR_HBN_VF_GROUPS="${BR_HBN_VF_GROUPS}" \
		BR_SFC_VF_GROUPS="${BR_SFC_VF_GROUPS}" \
		/opt/mellanox/sfc-hbn/provisioning-install.sh ${ARG_PORT0} ${ARG_PORT1} >> $LOG 2>&1; then
		touch /mnt/var/lib/sfc-hbn/provisioning-done
		log "INFO: SFC-HBN provisioning install (provisioning-install.sh) completed"
	else
		rc=$?
		RC=$((RC+rc))
		err_msg="SFC-HBN provisioning install (provisioning-install.sh) failed"
		log "ERROR: SFC-HBN provisioning install (provisioning-install.sh) failed with rc=$rc; see /var/log/sfc-install.log on the target"
	fi
}

create_initramfs()
{
	kver=$(uname -r)
	if [ ! -d /mnt/lib/modules/$kver ]; then
		kver=$(/bin/ls -1 /mnt/lib/modules/ | tail -1)
	fi

	ADD_DRIVERS=""
	for mod in mlxbf-bootctl dw_mmc dw_mmc-pltfm mmc_block dw_mmc-bluefield \
		armmmci block mmcblk sdhci sdhci-pltfm sdhci-of-dwcmshc mlxbf-tmfifo \
		mlx5_core mlx5_ib mlxfw ib_umad nvme \
		nvme-rdma nvme-tcp ib_ipoib ib_iser \
		mst_pci mst_pciconf bf3_livefish \
		gpio-mlxbf2 gpio-mlxbf3 mlxbf-gige \
		pinctrl-mlxbf3 8021q lan743x \
		ipmi_devintf ipmb_host ipmi_ssif i2c-mlxbf \
		cls_flower act_gact \
		nls_iso8859-1 $ADDON_KERNEL_MODULES
	do
		if (chroot /mnt modinfo -k $kver $mod 2>/dev/null | grep "filename:" | grep -q builtin); then
			continue
		fi
		if ! (chroot /mnt modinfo -k $kver $mod 2>/dev/null); then
			continue
		fi
		ADD_DRIVERS="$ADD_DRIVERS $mod"
	done
	ilog "Drivers to add to the initramfs: $ADD_DRIVERS"

	ilog "Updating $distro initramfs"
	initrd=$(cd /mnt/boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//")
	ilog "$(chroot /mnt dracut --force --add-drivers "$ADD_DRIVERS" --gzip /boot/$initrd ${kver} 2>&1)"
}

configure_grub()
{
	ilog "Configure grub:"
	if [ -n "${grub_admin_PASSWORD}" ]; then
		sed -i -r -e "s/(password_pbkdf2 admin).*/\1 ${grub_admin_PASSWORD}/" /mnt/etc/grub.d/40_custom
	fi

	if (lscpu 2>&1 | grep -wq Grace); then
		async_probe=""
		if [ "${ENABLE_MLX5_ASYNC_PROBE}" = "yes" ]; then
			async_probe=" driver_async_probe=mlx5_core"
		fi
		sed -i -e "s@GRUB_CMDLINE_LINUX=.*@GRUB_CMDLINE_LINUX=\"rw crashkernel=1024M $bootarg keep_bootcon earlycon modprobe.blacklist=mlx5_core,mlx5_ib selinux=0 iommu.passthrough=1${async_probe}\"@" /mnt/etc/default/grub
	fi

	if (lspci -vv | grep -wq SimX); then
		# Remove earlycon from grub parameters on SimX
		sed -i -r -e 's/earlycon=[^ ]* //g' /mnt/etc/default/grub
	fi

	ilog "Creating GRUB configuration"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-install ${device})"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg)"
	ilog "$(chroot /mnt env PATH=$CHROOT_PATH /usr/sbin/grub-set-default 0)"
}

set_root_password()
{
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

	os_installation_flow
}

install_dpu_os()
{

	erase_partitions

	if (echo "${BD_PSIDS}" | grep -qw "${PSID}"); then
		if [ "X$FORCE_UPDATE_DPU_OS" != "Xyes" ]; then
			log "Skip DPU OS installation"
			return
		fi
	fi

	log "INFO: $distro installation started"

	prepare_target_partitions

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

	sync
	log "INFO: $distro installation completed"
}

global_installation_flow

save_log

if [ "X$mode" == "Xmanufacturing" ]; then
	sleep 3
	log "INFO: Rebooting..."
	# Wait for these messages to be pulled by the rshim service
	sleep 3
fi
