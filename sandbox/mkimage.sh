#!/usr/bin/env bash

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob

cleanup() {
	if [ "${CLEANUP:-0}" = 0 ]; then
		return 0
	fi
	if [ -n "${SCRIPT_DIR:-}" ]; then
		cd "$SCRIPT_DIR"
	fi
	echo ">>> Cleaning up..."
	if [ -n "${MOUNTPOINT:-}" ]; then
		declare submount
		for submount in /sys /dev /proc /; do
			if findmnt "${MOUNTPOINT}${submount}" >/dev/null; then
				umount "${MOUNTPOINT}${submount}"
			fi
		done
		rmdir -v "$MOUNTPOINT"
	fi
	if [ -n "${LOOP_DEVICE:-}" ]; then
		# TODO: Detect, if partition has been actually mapped
		kpartx -dv "$LOOP_DEVICE"
		losetup -d "$LOOP_DEVICE"
	fi
}

on_error() {
	declare exit_code=$?
	declare cmd=$BASH_COMMAND
	echo "Failing with code ${exit_code} at ${*} in command: ${cmd}" >&2
	cleanup
	exit "$exit_code"
}

ensure_dependencies() {
	declare updated=0
	declare dep
	for dep in e2fsprogs dosfstools gdisk debootstrap kpartx; do
		if dpkg-query -s "$dep" >/dev/null; then
			continue
		fi
		if [ "$updated" = 0 ]; then
			apt-get update
			updated=1
		fi
		apt-get install -y --no-install-recommends "$dep"
	done
}

prepare_filesystem() {
	echo ">>> Preparing filesystem..."
	MOUNTPOINT=$(mktemp -d)
	mkdir -vp "$MOUNTPOINT"
	truncate -s "$arg_size" "$arg_output_img"
	LOOP_DEVICE=$(losetup --show --find "$arg_output_img")
	sgdisk --clear \
		--new 1::+1M --typecode=1:ef02 --change-name=1:'BIOS boot partition' \
		--new 2::-0 --typecode=2:8300 --change-name=2:'Linux root filesystem' \
		"$LOOP_DEVICE"
	kpartx -av "$LOOP_DEVICE"
	declare loop_name
	loop_name=$(echo "$LOOP_DEVICE" | rev | cut -d '/' -f 1 | rev)
	mkfs.ext4 -v -F -L "root" "/dev/mapper/${loop_name}p2"
	mount "/dev/mapper/${loop_name}p2" "$MOUNTPOINT"
	rm -rf "${MOUNTPOINT}/lost+found"
}

install_os() {
	echo ">>> Installing operating system..."
	mkdir -vp "$arg_cache_dir"
	debootstrap \
		--cache-dir="$arg_cache_dir" \
		--include="$(echo "${packages[*]}" | tr " " ",")" \
		"$arg_release" \
		"$MOUNTPOINT"
	mount -t devtmpfs dev "${MOUNTPOINT}/dev"
	mount -t proc proc "${MOUNTPOINT}/proc"
	mount -t sysfs sys "${MOUNTPOINT}/sys"
	declare root_uuid loop_name
	loop_name=$(echo "$LOOP_DEVICE" | rev | cut -d '/' -f 1 | rev)
	root_uuid=$(blkid "/dev/mapper/${loop_name}p2" -o export | grep ^UUID | cut -d '=' -f 2)
	echo "UUID=${root_uuid} / ext4 defaults 0 0" >> "${MOUNTPOINT}/etc/fstab"
}

configure_os() {
	echo ">>> Configuring operating system..."
	pushd "$MOUNTPOINT" >/dev/null

	sed -i -e "s/^XKBLAYOUT=.*/XKBLAYOUT=\"${arg_keyboard}\"/" etc/default/keyboard
	# TODO: Allow overriding locale
	sed -i -e 's/^# \(en_US.UTF-8 UTF-8\)/\1/' -e 's/^# \(pl_PL.UTF-8 UTF-8\)/\1/' etc/locale.gen
	chroot . locale-gen
	chroot . update-locale LANG=en_US.UTF-8
	chroot . ln -sf "/usr/share/zoneinfo/${arg_timezone}" /etc/localtime

	if [ -n "${ROOT_PASSWORD:-}" ]; then
		echo -e "${ROOT_PASSWORD}\n${ROOT_PASSWORD}" | chroot . passwd
	fi

	truncate -s 0 etc/machine-id || true
	rm -rf var/lib/dbus/machine-id || true

	cat > etc/hosts <<- EOF
		127.0.0.1       localhost
		127.0.1.1       ${arg_hostname}

		# The following lines are desirable for IPv6 capable hosts
		::1     localhost ip6-localhost ip6-loopback
		ff02::1 ip6-allnodes
		ff02::2 ip6-allrouters
	EOF
	echo "$arg_hostname" > etc/hostname

	truncate -s 0 etc/resolv.conf
	declare nameserver
	for nameserver in "${arg_nameservers[@]}"; do
		echo "nameserver ${nameserver}" >> etc/resolv.conf
	done

	popd >/dev/null
}

copy_files() {
	echo ">>> Copying files.."
	declare i
	for i in "${!arg_cp_srcs[@]}"; do
		cp -rv "${arg_cp_srcs["$i"]}" "${arg_cp_dsts["$i"]}"
	done
}

preset_common() {
	apt-get update
	apt-get full-upgrade -y
	apt-get install -y openssh-server

	cat > /etc/systemd/network/80-dhcp.network <<- EOF
		[Match]
		Name=en*
		[Network]
		DHCP=yes
	EOF
	systemctl enable systemd-networkd.service
}

preset_docker() {
	preset_common
	apt-get install -y ca-certificates curl gnupg lsb-release
	curl -fsSL https://download.docker.com/linux/debian/gpg \
		| gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
	{
		echo -n "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg]"
		echo " https://download.docker.com/linux/debian $(lsb_release -cs) stable"
	} > /etc/apt/sources.list.d/docker.list
	apt-get update
	apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
	cat > /etc/docker/daemon.json <<- EOF
		{
			"hosts": [
				"tcp://0.0.0.0:2375",
				"unix:///var/run/docker.sock"
			]
		}
	EOF
}

apply_presets() {
	declare preset
	for preset in "${arg_presets[@]}"; do
		echo ">>> Applying preset ${preset}..."
		{
			echo "export MKIMAGE_PRESET=${preset}"
			cat "$0"
		} | chroot "$MOUNTPOINT" /bin/bash -
	done
}

run_scripts() {
	declare script
	for script in "${arg_scripts[@]}"; do
		echo ">>> Running script ${script}..."
		{
			echo "set -euo pipefail -o errtrace"
			echo "shopt -s inherit_errexit nullglob"
			echo "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
			echo "export DEBIAN_FRONTEND=noninteractive"
			cat "$script"
		} | chroot "$MOUNTPOINT" /bin/bash -
	done
}

install_bootloader() {
	echo ">>> Installing bootloader..."
	chroot "$MOUNTPOINT" /usr/sbin/grub-install "$LOOP_DEVICE"
	chroot "$MOUNTPOINT" /usr/sbin/update-grub
}

parse_arguments() {
	while [ "$#" != 0 ]; do
		declare option=$1; shift
		case "$option" in
		--copy)
			arg_cp_srcs+=("$1"); shift
			arg_cp_dsts+=("$1"); shift
		;;
		--script)
			arg_scripts+=("$1"); shift
		;;
		--release)
			arg_release=$1; shift
		;;
		--size)
			arg_size=$1; shift
		;;
		--cleanup)
			CLEANUP=1
		;;
		--cache-dir)
			arg_cache_dir=$1; shift
		;;
		--hostname)
			arg_hostname=$1; shift
		;;
		--timezone)
			arg_timezone=$1; shift
		;;
		--keyboard)
			arg_keyboard=$1; shift
		;;
		--nameserver)
			arg_nameservers+=("$1"); shift
		;;
		--preset)
			arg_presets+=("$1"); shift
		;;
		*)
			if [ -n "$arg_output_img" ]; then
				echo "Wrong option: ${option}" >&2
				return 1
			else
				arg_output_img=$1; shift
			fi
		;;
		esac
	done
	if [ "${#arg_cp_srcs[@]}" -ne "${#arg_cp_dsts[@]}" ]; then
		# Assert to be safe. It should never happen.
		echo "--copy source entries does not match destination entries" >&2
		return 1
	fi
	if [ -z "$arg_output_img" ]; then
		echo "Output image needs to be specified with --output" >&2
		return 1
	fi
	if [ "${#arg_nameservers[@]}" = 0 ]; then
		arg_nameservers=("1.1.1.1" "8.8.8.8")
	fi
	arg_cache_dir=$(realpath -m "$arg_cache_dir")
}

main() {
	trap 'on_error ${BASH_SOURCE[0]}:${LINENO}' ERR
	SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

	if [ "${MKIMAGE_PRESET:-}" != "" ]; then
		"preset_${MKIMAGE_PRESET}"
		return 0
	fi

	declare -a packages=(
		e2fsprogs
		grub-pc
		wget
		curl
		neovim
		haveged
		cloud-guest-utils
		console-setup
		locales
		dbus
		dbus-user-session
		sudo
		systemd
		systemd-sysv
		linux-image-amd64
		firmware-linux-free
		apt-transport-https
		ca-certificates
	)

	ensure_dependencies

	declare -a arg_cp_srcs=()
	declare -a arg_cp_dsts=()
	declare -a arg_scripts=()
	declare -a arg_presets=()
	declare -a arg_nameservers=()
	declare arg_size="10G"
	declare arg_release="bullseye"
	declare arg_output_img=""
	declare arg_hostname="sandbox"
	declare arg_cache_dir=".cache"
	declare arg_keyboard="pl"
	declare arg_timezone="Europe/Warsaw"
	parse_arguments "$@"

	prepare_filesystem
	install_os
	configure_os
	copy_files
	apply_presets
	run_scripts
	install_bootloader
	cleanup
}

main "$@"
