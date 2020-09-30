#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing NodeJS..."
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-fast install -y nodejs
