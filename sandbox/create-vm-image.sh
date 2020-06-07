#!/usr/bin/env bash
################################################################################
# Provision fresh system image for local virtual machine
################################################################################

PACKAGES="\
haveged
rsync
neovim
dnsutils
strace
tcpdump
libcap2-bin
sudo
curl
tmux
wget
gcc
bpftrace
python3
python3-pip
python3-dev
python3-venv
python3-neovim
python
python-dev
python-pip
git
subversion
tree
silversearcher-ag
libssl-dev
libffi-dev
sqlite3
build-essential
"

virt-builder \
  debian-10 \
  -o debian-10.qcow2 \
  --size 50G \
  --format qcow2 \
  --arch x86_64 \
  --ssh-inject root:file:"$HOME"/.ssh/local_dev.pub \
  --root-password password:debian-10 \
  --install "$(echo "$PACKAGES" | tr "\n" ",")" \
  --run "$(dirname "$(realpath "$0")")/setup-vm.sh" \
  --run-command "useradd --groups sudo --create-home --shell /bin/bash developer" \
  --ssh-inject developer:file:"$HOME"/.ssh/local_dev.pub \
  --hostname debian-10 \
  --timezone Europe/Warsaw \
  --update
