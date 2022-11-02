#!/usr/bin/env bash
#shellcheck disable=SC2128,SC1090,SC2178
# SC2128: Expanding an array without an index only gives the first element.
# SC1090: Can't follow non-constant source
# SC2178: Variable was used as an array but is now assigned a string.

set -euo pipefail -o errtrace
shopt -s inherit_errexit nullglob lastpipe

declare \
	BUILD_DIR=".devbox" \
	IMAGE_URL="https://cdimage.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2"

on_error() {
	declare \
		cmd=$BASH_COMMAND \
		exit_code=$?
	if [ "$exit_code" != 0 ]; then
		echo "Failing with exit code ${exit_code} at ${*} in command: ${cmd}" >&2
	fi
	exit "$exit_code"
}

on_exit() {
	:
}

check_dependencies() {
	declare dep
	for dep in \
		genisoimage \
		qemu-img \
		curl \
		qemu-system-x86_64
	do
		if ! command -v "$dep" &>/dev/null; then
			echo "Missing dependency: ${dep}" >&2
			return 1
		fi
	done
}

main_help() {
	declare -a msg
mapfile -d "" msg << "EOF"
Run development virtual machine in local network and optionally with selecte directories attached as an 9p volumes.

Options:
  -h|--help             Display this message.
  -v|--volume SRC DEST  Add 9p volume.
  --key KEY             Specify SSH key to use.
  --size SIZE           Resize instance image to SIZE.
  --memory SIZE         Run instance with SIZE megabytes of memory.
  --rebuild             Rebuild instance.
  --bridge BRIDGE       Use BRIDGE for networking instance.
EOF
	echo "$msg"
}

render_meta_data() {
	declare devbox_hostname=$1
	declare -a content
mapfile -d "" content << EOF
instance-id: ${devbox_hostname}
local-hostname: ${devbox_hostname}
EOF
	echo -n "$content"
}

render_user_data() {
	declare \
		ssh_key=${1:-"${HOME}/.ssh/id_rsa.pub"} \
		mounts_len=$2 \
		i \
		n
	declare -a \
		content \
		mounts=() \
		packages
	shift 2
	while (( mounts_len-- > 0 )); do
		mounts+=("$1")
		shift
	done
	packages=(
		tree
		tmux
		strace
		silversearcher-ag
		rsync
		rlwrap
		python3-venv
		python3-pip
		python3-neovim
		python3-dev
		python3
		neovim
		libssl-dev
		libffi-dev
		jq
		haveged
		gpg
		git
		gcc
		dnsutils
		curl
		build-essential
		bpftrace
	)
	echo "#cloud-config"
	if [ -n "$ssh_key" ]; then
		echo "ssh_authorized_keys:"
		mapfile -d "" content < "$ssh_key"
		echo -n "  - ${content}"
	fi
	if [ "${#packages[@]}" != 0 ]; then
		echo "packages:"
		for i in "${packages[@]}"; do
			echo " - ${i}"
		done
	fi
	echo "packages_update: true"
	echo "packages_upgrade: true"
mapfile -d "" content << "EOF"
write_files:
  - path: /etc/issue
    content: "Debian GNU/Linux 11 \\n \\l\nAddress: \\4\n"
  - path: /etc/modules-load.d/9pnet_virtio.conf
    content: |
      9pnet_virtio
EOF
	echo -n "$content"
	if [ "${#mounts[@]}" != 0 ]; then
		echo "mounts:"
		set -- "${mounts[@]}"
		n=0
		while [ "$#" != 0 ]; do
			echo "  - [code${n}, ${2}, 9p, \"trans=virtio,msize=20480\", \"0\", \"0\"]"
			shift 2
			n=$((n + 1))
		done
		echo "bootcmd:"
		set -- "${mounts[@]}"
		while [ "$#" != 0 ]; do
			echo "  - mkdir -p ${2}"
			shift 2
		done
	fi
}

main() {
	declare -a \
		volumes=() \
		qemu_opts=()
	declare \
		devbox_hostname="devbox" \
		root_size="+20G" \
		memory="2048" \
		rebuild=0 \
		bridge="br0" \
		ssh_key \
		n
	while [ "$#" != 0 ]; do
		case "$1" in
		-v|--volume)
			shift
			volumes+=("$1" "$2")
			shift 2
		;;
		--bridge)
			shift
			bridge=$1
			shift
		;;
		--rebuild)
			shift
			rebuild=1
		;;
		--memory)
			shift
			memory=$1
			shift
		;;
		--size)
			shift
			root_size=$1
			shift
		;;
		--key)
			shift
			ssh_key=$1
			shift
		;;
		-h|--help)
			main_help
			return 0
		;;
		*)
			echo "Wrong option: ${1}" >&2
			return 1
		;;
		esac
	done
	check_dependencies

	if [ ! -d "$BUILD_DIR" ]; then
		mkdir -p "$BUILD_DIR"
	fi
	pushd "$BUILD_DIR" >/dev/null
	render_user_data "" "${#volumes[@]}" "${volumes[@]}" > user-data
	render_meta_data "$devbox_hostname" > meta-data
	rm -f seed.iso
	genisoimage -output seed.iso -volid cidata -joliet -rock user-data meta-data
	if [ ! -f "base.qcow2" ]; then
		curl -sSL "$IMAGE_URL" > "base.qcow2"
	fi
	if [ "$rebuild" = 1 ]; then
		rm -f "instance.qcow2"
	fi
	if [ ! -f "instance.qcow2" ]; then
		qemu-img create -f qcow2 -b "base.qcow2" -F qcow2 "instance.qcow2"
		qemu-img resize "instance.qcow2" "$root_size"
	fi
	n=0
	set -- "${volumes[@]}"
	while [ "$#" != 0 ]; do
		popd >/dev/null
		i=$(realpath "$1")
		pushd "$BUILD_DIR" >/dev/null
		qemu_opts+=(
			"-fsdev" "local,id=code${n},path=${i},security_model=mapped-xattr"
			"-device" "virtio-9p-pci,fsdev=code${n},mount_tag=code${n}"
		)
		shift 2
		n=$((n + 1))
	done
	n=$(printf '00-60-2F-%02X-%02X-%02X' "$((RANDOM%256))" "$((RANDOM%256))" "$((RANDOM%256))")
	qemu-system-x86_64 \
		-m "$memory" \
		--enable-kvm \
		-nic bridge,br="$bridge",model=virtio-net-pci,mac="$n" \
		-drive file=instance.qcow2,if=virtio \
		-drive driver=raw,file=seed.iso,if=virtio \
		"${qemu_opts[@]}" \
		-nographic
}

trap 'on_error "${BASH_SOURCE[0]}:${LINENO}"' ERR
trap on_exit EXIT
if [ "$0" = "${BASH_SOURCE:-}" ]; then
	#shellcheck disable=SC2034
	SCRIPT_FILE=$(readlink -f "$0")
	#shellcheck disable=SC2034
	SCRIPT_DIR=$(dirname "$SCRIPT_FILE")
	main "$@"
fi
