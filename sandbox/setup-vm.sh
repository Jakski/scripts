#!/usr/bin/env bash
################################################################################
# Setup optional repositories and configuration in virtual machine image
################################################################################

set -e

### NodeJS
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-get install -y nodejs

### Yarn package manager
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" > /etc/apt/sources.list.d/yarn.list
apt-get update
apt-get install -y yarn

### Golang
wget -O golang.tar.gz https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
tar -C /usr/local -xzf golang.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
rm golang.tar.gz
