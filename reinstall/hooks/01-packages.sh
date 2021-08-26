#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing apt-fast..."
echo "deb http://ppa.launchpad.net/apt-fast/stable/ubuntu bionic main" > /etc/apt/sources.list.d/apt-fast.list
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys A2166B8DE8BDC3367D1901C11EE2FF37CA8DA16B
apt-get update
apt-get install -y apt-fast
mv "${FILES_DIR}/apt-fast.conf" /etc/apt-fast.conf
apt-fast install -y $(echo -n "$(get_cfg '.packages[]')" | tr '\n' ' ')
