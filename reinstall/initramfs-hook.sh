#!/bin/sh

set -e

case "${1:-}" in
  prereqs)  echo ""; exit 0;;
esac

. /usr/share/initramfs-tools/hook-functions

copy_exec /usr/bin/gpg
