#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing NodeJS..."
curl -sL https://deb.nodesource.com/setup_14.x | bash -
apt-fast install -y nodejs
