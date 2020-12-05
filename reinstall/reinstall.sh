#!/usr/bin/env bash

set -euo pipefail

TARGET=""
TMP_DIR=""
IMAGE_URL=""

print_help() {
cat << EOF
Synopsis:
  Reinstall virtual private server from external provider.
Options:
  -h                display this message
  -t TARGET         target host to reinstall
                    (actual host configuration can be stored in ssh_config)
  -u IMAGE_URL      URL to download image
Environment variables:
  IMAGE_PASSWORD - GPG password to decrypt image
EOF
}

on_exit() {
  local exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    echo "Failed!" >&2
  fi
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
  exit "$exit_code"
}

main() {
  local opt
  while getopts ":ht:u:" opt; do
    case "$opt" in
      h)
        print_help
        ;;
      t)
        TARGET=$OPTARG
        ;;
      u)
        IMAGE_URL=$OPTARG
        ;;
      *)
        print_help
        exit 1
        ;;
    esac
  done
  [ -z "$TARGET" ] && {
    echo "TARGET must be set to non-empty value" >&2
    exit 1
  }
  [ -z "$IMAGE_PASSWORD" ] && {
    echo "No image GPG password supplied" >&2
    exit 1
  }
  [ -z "$IMAGE_URL" ] && {
    echo "No image URL supplied" >&2
    exit 1
  }
  IMAGE_PASSWORD=$(echo -n "$IMAGE_PASSWORD" | sed 's/[\/&]/\\&/g')
  IMAGE_URL=$(echo -n "$IMAGE_URL" | sed 's/[\/&]/\\&/g')
  TMP_DIR=$(mktemp -d)
  cat ./initramfs-hook.sh \
    | ssh "$TARGET" "sudo tee /etc/initramfs-tools/hooks/reinstall" \
    > /dev/null
  sed \
    -e "s/<<image_password>>/${IMAGE_PASSWORD}/" \
    -e "s/<<image_url>>/${IMAGE_URL}/" \
    > "${TMP_DIR}/initramfs-script.sh" \
    < ./initramfs-script.sh
  cat "${TMP_DIR}/initramfs-script.sh" \
    | ssh "$TARGET" "sudo tee /etc/initramfs-tools/scripts/init-premount/reinstall" \
    > /dev/null
  ssh "$TARGET" "sudo /bin/bash -" \
<< EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y gnupg busybox-static
chmod +x /etc/initramfs-tools/hooks/reinstall
chmod +x /etc/initramfs-tools/scripts/init-premount/reinstall
update-initramfs -u
reboot
EOF
}

main "$@"
