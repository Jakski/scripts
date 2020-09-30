#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing PostgreSQL..."
echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
  > /etc/apt/sources.list.d/postgresql.list
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc \
  | apt-key add -
apt-get update
apt-fast install -y postgresql-12
systemctl disable postgresql.service
