#!/usr/bin/env bash
######################################################################
# Requirements:
# - cryptsetup
# - losetup
# - findmnt
# - awk
######################################################################

set -o errexit
set -o pipefail
set -o nounset

PROGRAM_NAME=vault
MAPPER_DIR=/dev/mapper

catch_exception() {
	local exit_code=$?
	if [ "$exit_code" -ne 0 ]; then
		echo "Failed with exit code: $exit_code" >&2
	fi
}

program_help() {
cat << EOF
Description:
	Manage LUKS encrypted filesystem containers
	$PROGRAM_NAME supports only file based containers mounted as loop devices
Subcommands:
	mount
	umount
	create
	grow
EOF
}

create_subcommand_help() {
cat << EOF
Description:
	Create LUKS encrypted container with filesystem
Options:
	-d DEST		container destination path
	-s SIZE		container size(defaults to 256M)
	-f CMD		command to create filesystem(defaults to mkfs.ext4)
EOF
}

grow_subcommand_help() {
cat << EOF
Description:
	Enlarge LUKS container and underlying filesystem
Options:
	-d DEST		path do LUKS container
	-s SIZE		MiB to add to container
	-f CMD		filesystem resize command(defaults to resize2fs -f)
EOF
}

mount_subcommand_help() {
cat << EOF
Description:
	Mount LUKS container from regular file
Options:
	-d DEST		path to mount point
	-p PARAMS	parameters passed to mount command
	-c FILE		file with LUKS container
EOF
}

umount_subcommand_help() {
cat << EOF
Description:
	Unmount LUKS container
Options:
	-d DEST		path to mount point
EOF
}

get_md5sum() {
	md5sum | cut -d " " -f 1
}

umount_subcommand() {
	local \
		OPTIND \
		destination=""
	while getopts ":hd:" opt; do
		case "$opt" in
		d)
			destination=$OPTARG
			;;
		h)
			umount_subcommand_help
			exit
			;;
		*)
			echo "Wrong parameters" >&2
			exit 1
			;;
		esac
	done
	[ -n "$destination" ] || {
		echo "No mount point passed" >&2
		exit 1
	}
	local container_name loop_dev
	container_name=$(basename "$(findmnt -flM "$destination" -o SOURCE -l | tail -n +2)")
	loop_dev=$(cryptsetup status "$container_name" | awk '$1 == "device:" { print $2 }')
	umount "$destination"
	cryptsetup close -q "$container_name"
	losetup -d "$loop_dev"
}

mount_subcommand() {
	local \
		OPTIND \
		destination="" \
		container_path="" \
		mount_params=""
	while getopts ":hd:p:c:" opt; do
		case "$opt" in
		p)
			mount_params=$OPTARG
			;;
		c)
			container_path=$(realpath "$OPTARG")
			;;
		d)
			destination=$(realpath "$OPTARG")
			;;
		h)
			mount_subcommand_help
			exit
			;;
		*)
			echo "Wrong parameters" >&2
			exit 1
			;;
		esac
	done
	[ -n "$destination" ] || {
		echo "No mount point defined" >&2
		exit 1
	}
	[ -n "$container_path" ] || {
		echo "No container specified" >&2
		exit 1
	}
	findmnt -o TARGET -l | grep -q "$destination" && {
		echo "Destination is already used as a mount point" >&2
		exit 1
	}
	mkdir -p "$destination"
	local loop_dev container_name password
	read -s -p "Enter container password: " password
	echo
	loop_dev=$(losetup --show -f "$container_path")
	container_name="${PROGRAM_NAME}-$(echo "$container_path" | get_md5sum)"
	echo -n "$password" | cryptsetup open -qd - --type luks "$loop_dev" "${container_name}" || {
		losetup -d "$loop_dev"
		exit 1
	}
	mount $mount_params "${MAPPER_DIR}/${container_name}" "$destination"
}

grow_subcommand(){
	local \
		OPTIND \
		size="" \
		destination="" \
		resize_cmd="resize2fs -f"
	while getopts ":hs:d:f:" opt; do
		case "$opt" in
		s)
			size=$OPTARG
			;;
		d)
			destination=$(realpath "$OPTARG")
			;;
		f)
			resize_cmd=$OPTARG
			;;
		h)
			grow_subcommand_help
			exit
			;;
		*)
			echo "Wrong parameters" >&2
			exit 1
			;;
		esac
	done
	[ -n "$destination" ] || {
		echo "No container destination passed" >&2
		exit 1
	}
	echo "$size" | grep -qE "[0-9]+" || {
		echo "Size must be an integer" >&2
		exit 1
	}
	local loop_dev container_name password
	read -s -p "Enter container password: " password
	echo
	loop_dev=$(losetup --show -f "$destination")
	container_name="${PROGRAM_NAME}-$(echo "$destination" | get_md5sum)"
	echo -n "$password" | cryptsetup open -qd - --type luks "$loop_dev" "${container_name}" || {
		losetup -d "$loop_dev"
		exit 1
	}
	dd if=/dev/zero bs=1M status=none count="$size" >> "$destination"
	echo -n "$password" | cryptsetup resize -qd - "$container_name"
	$resize_cmd "${MAPPER_DIR}/${container_name}"
	cryptsetup close -q "$container_name"
	losetup -d "$loop_dev"
}

create_subcommand() {
	local \
		OPTIND \
		size="256M" \
		destination="" \
		fs_cmd="mkfs.ext4 -q"
	while getopts ":hs:d:f:" opt; do
		case "$opt" in
		s)
			size=$OPTARG
			;;
		d)
			destination=$(realpath "$OPTARG")
			;;
		f)
			fs_cmd=$OPTARG
			;;
		h)
			create_subcommand_help
			exit
			;;
		*)
			echo "Wrong parameters" >&2
			exit 1
			;;
		esac
	done
	[ -n "$destination" ] || {
		echo "No container destination passed" >&2
		exit 1
	}
	[ -a "$destination" ] && {
		echo "Path $destination already exists" >&2
		exit 1
	}
	echo "$size" | grep -qE "[0-9]+" || {
		echo "Size must be an integer" >&2
		exit 1
	}
	local loop_dev container_name password password_verification
	read -s -p "Enter container password: " password
	echo
	read -s -p "Verify container password: " password_verification
	echo
	if [ "$password" != "$password_verification" ]; then
		echo "Passwords doesn't match" >&2
		exit 1
	fi
	truncate -s "${size}" "$destination"
	loop_dev=$(losetup --show -f "$destination")
	echo -n "$password" | cryptsetup luksFormat -qd - "$loop_dev"
	container_name="${PROGRAM_NAME}-$(echo "$destination" | get_md5sum)"
	echo -n "$password" | cryptsetup open -qd - --type luks "$loop_dev" "${container_name}"
	$fs_cmd "${MAPPER_DIR}/${container_name}"
	cryptsetup close -q "$container_name"
	losetup -d "$loop_dev"
}

main() {
	trap catch_exception EXIT
	[ -z "${1:+x}" ] && {
		echo "No subcommand specified" >&2
		exit 1
	}
	local subcommand=$1
	case "$subcommand" in
	mount|umount|create|grow)
		shift
		"${subcommand}_subcommand" "$@"
		;;
	-h)
		program_help
		exit
		;;
	*)
		echo "Wrong subcommand" >&2
		exit 1
		;;
	esac
}

main "$@"
