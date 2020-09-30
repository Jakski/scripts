#!/usr/bin/env bash

set -euo pipefail
set -x

LOOP_DEVICE=""
CONFIG="./config.json"
MOUNTPOINT=""
OUTPUT_FILE=""
SKIP_CLEANUP="no"

on_exit() {
  local exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    if [ -n "$LOOP_DEVICE" ]; then
      echo ">>> Removing loop device..." >&2
      cleanup_chroot
    fi
  fi
  exit "$exit_code"
}

cleanup_chroot() {
  if [ "$SKIP_CLEANUP" = "yes" ]; then
    return
  fi
  local mounts="/sys /dev /proc /"
  local mountpoint
  for mountpoint in $mounts; do
    if findmnt "${MOUNTPOINT}${mountpoint}" >/dev/null; then
      umount "${MOUNTPOINT}${mountpoint}"
    fi
  done
  kpartx -d "$LOOP_DEVICE"
  losetup -d "$LOOP_DEVICE"
}

print_help() {
cat << EOF
Synopsis:
  Generate Debian system image ready for usage with popular cloud providers.
Options:
  -c CONFIG  configuration JSON file
  -h         display this message
Environment variables:
  ROOT_PASSWORD - root password(required)
EOF
}

get_cfg() {
  local \
    path=$1 \
    raw=${2:-yes}
  if [ "$raw" = "no" ]; then
    raw=""
  else
    raw="-r"
  fi
  echo "$CONFIG" | jq -e $raw "$1"
}

main() {
  if [ "$UID" -ne 0 ]; then
    echo "This program can be run only as root" >&2
    exit 1
  fi
  trap on_exit EXIT
  local opt
  while getopts ":hs:k:no:c:" opt; do
    case "$opt" in
      h)
        print_help
        exit 0
        ;;
      c)
        CONFIG=$OPTARG
        ;;
      *)
        print_help
        exit 1
        ;;
    esac
  done

  get_cfg '.skip_cleanup' && {
    SKIP_CLEANUP="yes"
  }
  CONFIG=$(cat "$CONFIG")
  MOUNTPOINT=$(realpath "$(get_cfg .mountpoint)")
  OUTPUT_FILE=$(realpath "$(get_cfg .output_file)")
  local cache_dir
  cache_dir=$(realpath "$(get_cfg .cache_directory)")
  mkdir -p "$cache_dir"
  echo ">>> Installing host dependencies..."
  apt-get update
  apt-get install -y \
    e2fsprogs \
    dosfstools \
    gdisk \
    debootstrap \
    jq \
    kpartx

  echo ">>> Preparing disk image..."
  mkdir -p "$MOUNTPOINT"
  truncate -s "$(get_cfg .disk_size)" "$OUTPUT_FILE"
  LOOP_DEVICE=$(losetup --show --find "$OUTPUT_FILE")
  sgdisk --clear \
    --new 1::+1M --typecode=1:ef02 --change-name=1:'BIOS boot partition' \
    --new 2::-0 --typecode=2:8300 --change-name=2:'Linux root filesystem' \
    "$LOOP_DEVICE"
  kpartx -a "$LOOP_DEVICE"
  local loop_name
  loop_name=$(echo "$LOOP_DEVICE" | rev | cut -d '/' -f 1 | rev)
  mkfs.ext4 -F -L "root" "/dev/mapper/${loop_name}p2"
  mount "/dev/mapper/${loop_name}p2" "$MOUNTPOINT"
  rm -rf "${MOUNTPOINT}/lost+found"

  echo ">>> Preparing file system..."
  local debootstrap_archive extra_pkgs
  debootstrap_archive=$(realpath "${cache_dir}/debootstrap.tar.gz")
  extra_pkgs="grub-pc,eatmydata,jq,gnupg,curl,wget"
  if ! [ -e "$debootstrap_archive" ]; then
    local tmp_dir
    tmp_dir=$(mktemp -d)
    debootstrap \
      --make-tarball="$debootstrap_archive" \
      --include="$extra_pkgs" \
      buster \
      "$MOUNTPOINT" \
    || {
      rm -rf "$tmp_dir"
    }
  fi
  debootstrap \
    --unpack-tarball="$debootstrap_archive" \
    --include="$extra_pkgs" \
    buster \
    "$MOUNTPOINT"
  mount -t devtmpfs dev "${MOUNTPOINT}/dev"
  mount -t proc proc "${MOUNTPOINT}/proc"
  mount -t sysfs sys "${MOUNTPOINT}/sys"
  local root_uuid
  root_uuid=$(
    blkid "/dev/mapper/${loop_name}p2" -o export \
    | grep ^UUID \
    | cut -d '=' -f 2
  )
  echo "UUID=${root_uuid} / ext4 defaults 0 0" >> "${MOUNTPOINT}/etc/fstab"

  echo ">>> Copying files..."
  mkdir -p "${MOUNTPOINT}/tmp/build-vm"
  cp -rL "$(get_cfg .files_directory)"/* "${MOUNTPOINT}/tmp/build-vm"
  local script
  for script in $(ls -1 "$(get_cfg .hooks_directory)" | sort -n); do
    (
      script="$(get_cfg .hooks_directory)/${script}"
      export FILES_DIR="/tmp/build-vm"
      export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      export DEBIAN_FRONTEND=noninteractive 
      export CONFIG
      echo ">>> Running ${script} in chroot..."
      cat \
        <(type get_cfg | tail -n+2) \
        "$script" \
        | chroot "${MOUNTPOINT}" /bin/bash -
    )
  done
  rm -rf "${MOUNTPOINT}/tmp/build-vm"
  echo ">>> Configuring system"
  chroot "${MOUNTPOINT}" /usr/sbin/grub-install "$LOOP_DEVICE"
  chroot "${MOUNTPOINT}" /usr/sbin/update-grub
  echo "sandbox" > "${MOUNTPOINT}/etc/hostname"

  echo ">>> Cleanup chroot"
  cleanup_chroot
}

main "$@"
