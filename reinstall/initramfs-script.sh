#!/bin/sh

set -e
set -u

IMAGE_URL="<<image_url>>"
IMAGE_PASSWORD="<<image_password>>"

case "${1:-}" in
  prereqs)  echo ""; exit 0;;
esac

ipconfig -d ''
. /run/net-*.conf
# ipconfig has problems, if gateway is outside of subnetwork.
if [ "$(ip route | wc -l)" -lt 2 ]; then
  ip route add "${IPV4GATEWAY}/32" dev "$DEVICE"
  ip route add default via "$IPV4GATEWAY" dev "$DEVICE"
fi
disk=$(ls /sys/class/block | sort -n | head -n 1)
# Default shell doesn't support pipefail, so this part can fail silently.
# Always make sure, that GPG passphrase and image URL are proper.
wget "$IMAGE_URL" -O - \
  | gpg --yes --batch --passphrase="$IMAGE_PASSWORD" -d \
  | zcat > "/dev/${disk}"
reboot -f
