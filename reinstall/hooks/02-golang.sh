#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing Golang..."
wget -O golang.tar.gz https://dl.google.com/go/go1.17.linux-amd64.tar.gz
tar -C /usr/local -xzf golang.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
rm golang.tar.gz
