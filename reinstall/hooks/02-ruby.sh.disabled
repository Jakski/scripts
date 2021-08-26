#!/usr/bin/env bash

set -euo pipefail

echo ">>> Installing Ruby..."
curl -sSL https://raw.githubusercontent.com/fullstaq-labs/fullstaq-ruby-server-edition/main/fullstaq-ruby.asc \
  | apt-key add -
echo "deb https://apt.fullstaqruby.org debian-10 main" \
  > /etc/apt/sources.list.d/fullstaq-ruby.list
apt-get update
apt-fast install -y fullstaq-ruby-common
apt-fast install -y fullstaq-ruby-2.6
echo 'export PATH=$PATH:/usr/lib/fullstaq-ruby/versions/2.6/bin' \
  > /etc/profile.d/fullstaq-ruby.sh
