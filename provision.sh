#!/usr/bin/env bash
################################################################################
# Provision fresh system image for local virtual machine
################################################################################

virt-builder \
  debian-10 \
  -o debian-10.qcow2 \
  --size 50G \
  --format qcow2 \
  --arch x86_64 \
  --ssh-inject root:file:"$HOME"/.ssh/local_dev.pub \
  --root-password password:debian-10 \
  --install haveged,neovim,dnsutils,strace,tcpdump,libcap2-bin,sudo,curl \
  --hostname debian-10 \
  --timezone Europe/Warsaw \
  --update
