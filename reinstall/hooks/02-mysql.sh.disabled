#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing Percona Server for MySQL..."
wget https://repo.percona.com/apt/percona-release_latest.$(lsb_release -sc)_all.deb
dpkg -i percona-release_latest.$(lsb_release -sc)_all.deb
rm percona-release_latest.$(lsb_release -sc)_all.deb
percona-release setup ps80
apt-fast install -y percona-server-server
systemctl disable mysql.service
