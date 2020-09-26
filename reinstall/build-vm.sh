#!/usr/bin/env bash

set -euo pipefail

LOOP_DEVICE=""
MOUNTPOINT=/mnt/debian
PACKAGES="\
apt-transport-https
bpftrace
build-essential
ca-certificates
cloud-guest-utils
curl
dbus
dbus-user-session
default-jdk
dnsutils
e2fsprogs
firmware-linux-free
gcc
gdisk
git
grub-pc
haveged
libcap2-bin
libffi-dev
libssl-dev
linux-image-amd64
neovim
openssh-server
lsb-release
python
python3
python3-dev
python3-neovim
python3-pip
python3-venv
python-dev
python-pip
rsync
silversearcher-ag
sqlite3
strace
subversion
sudo
redis
systemd
systemd-sysv
tcpdump
tinc
tmux
tree
nftables
fail2ban
wget\
"
SSH_KEY=""
DISK_SIZE=""
SKIP_CLEANUP="no"

on_exit() {
  local exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    if [ -n "$LOOP_DEVICE" ]; then
      echo ">>> Removing loop device..." >&2
      cleanup_chroot
    fi
  fi
  exit "$exit_code"
}

cleanup_chroot() {
  if [ "$SKIP_CLEANUP" = "yes" ]; then
    return
  fi
  local mounts="/sys /dev /proc /"
  local mountpoint
  for mountpoint in $mounts; do
    if findmnt "${MOUNTPOINT}${mountpoint}" >/dev/null; then
      umount "${MOUNTPOINT}${mountpoint}"
    fi
  done
  kpartx -d "$LOOP_DEVICE"
  losetup -d "$LOOP_DEVICE"
}

print_help() {
cat << EOF
Synopsis:
  Generate Debian system image ready for usage with popular cloud providers.
Options:
  -k SSH_KEY    path to authorized SSH key for root user
  -s DISK_SIZE  disk size in format acceptable by truncate(1)
  -n            skip cleanup procedure - it will leave chroot mounted
  -h            display this message
Environment variables:
  ROOT_PASSWORD - root password(required)
EOF
}

main() {
  if [ "$UID" -ne 0 ]; then
    echo "This program can be run only as root" >&2
    exit 1
  fi
  trap on_exit EXIT
  local opt
  while getopts ":hs:k:n" opt; do
    case "$opt" in
      h)
        print_help
        exit 0
        ;;
      k)
        SSH_KEY=$OPTARG
        ;;
      s)
        DISK_SIZE=$OPTARG
        ;;
      n)
        SKIP_CLEANUP="yes"
        ;;
      *)
        print_help
        exit 1
        ;;
    esac
  done
  [ -z "$SSH_KEY" ] && {
    echo "No SSH key path given" >&2
    exit 1
  }
  [ -z "$DISK_SIZE" ] && {
    echo "No disk size given" >&2
    exit 1
  }
  [ -z "$ROOT_PASSWORD" ] && {
    echo "No root password given" >&2
    exit 1
  }

  echo ">>> Installing host dependencies..."
  apt-get update
  apt-get install -y \
    e2fsprogs \
    dosfstools \
    gdisk \
    debootstrap \
    kpartx

  echo ">>> Preparing disk image..."
  mkdir -p "$MOUNTPOINT"
  truncate -s "$DISK_SIZE" debian.img
  LOOP_DEVICE=$(losetup --show --find debian.img)
  sgdisk --clear \
    --new 1::+1M --typecode=1:ef02 --change-name=1:'BIOS boot partition' \
    --new 2::-0 --typecode=2:8300 --change-name=2:'Linux root filesystem' \
    "$LOOP_DEVICE"
  kpartx -a "$LOOP_DEVICE"
  local loop_name
  loop_name=$(echo "$LOOP_DEVICE" | rev | cut -d '/' -f 1 | rev)
  mkfs.ext4 -F -L "root" "/dev/mapper/${loop_name}p2"
  mount "/dev/mapper/${loop_name}p2" "$MOUNTPOINT"

  echo ">>> Preparing file system..."
  debootstrap --include=eatmydata,gnupg,curl,wget buster "$MOUNTPOINT"
  mount -t devtmpfs dev "${MOUNTPOINT}/dev"
  mount -t proc proc "${MOUNTPOINT}/proc"
  mount -t sysfs sys "${MOUNTPOINT}/sys"
  local root_uuid
  root_uuid=$(blkid "/dev/mapper/${loop_name}p2" -o export | grep ^UUID | cut -d '=' -f 2)
  echo "UUID=${root_uuid} / ext4 defaults 0 0" >> "${MOUNTPOINT}/etc/fstab"

  echo ">>> Installing packages..."
  cat > "${MOUNTPOINT}/etc/apt-fast.conf.override" \
<< "EOF"
_APTMGR=apt-get
DOWNLOADBEFORE=true
_MAXNUM=16
_MAXCONPERSRV=10
_SPLITCON=8
_MINSPLITSZ=1M
_PIECEALGO=default
DLLIST='/tmp/apt-fast.list'
_DOWNLOADER='aria2c --no-conf -c -j ${_MAXNUM} -x ${_MAXCONPERSRV} -s ${_SPLITCON} --min-split-size=${_MINSPLITSZ} --stream-piece-selector=${_PIECEALGO} -i ${DLLIST} --connect-timeout=600 --timeout=600 -m0 --header "Accept: */*"'
DLDIR='/var/cache/apt/apt-fast'
APTCACHE='/var/cache/apt/archives'
MIRRORS=( 'http://ftp.by.debian.org/debian/', 'http://ftp.ru.debian.org/debian/', 'ftp.sk.debian.org/debian/', 'ftp.cz.debian.org/debian/', 'http://ftp.pl.debian.org/debian/', 'http://deb.debian.org/debian', 'http://ftp.debian.org/debian, http://ftp2.de.debian.org/debian, http://ftp.de.debian.org/debian, ftp://ftp.uni-kl.de/debian' )
EOF
  chroot "${MOUNTPOINT}" /usr/bin/bash - \
<< EOF
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive 

echo ">>> Installing apt-fast..."
echo "deb http://ppa.launchpad.net/apt-fast/stable/ubuntu bionic main" > /etc/apt/sources.list.d/apt-fast.list
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys A2166B8DE8BDC3367D1901C11EE2FF37CA8DA16B
apt-get update
apt-get install -y apt-fast
cp /etc/apt-fast.conf.override /etc/apt-fast.conf
apt-fast install -y $(echo -n "$PACKAGES" | tr '\n' ' ')

echo ">>> Installing NodeJS..."
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-fast install -y nodejs

echo ">>> Installing Yarn..."
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" > /etc/apt/sources.list.d/yarn.list
apt-get update
apt-fast install -y yarn

echo ">>> Installing Golang..."
wget -O golang.tar.gz https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz
tar -C /usr/local -xzf golang.tar.gz
echo 'export PATH=\$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
rm golang.tar.gz

echo ">>> Installing Ruby..."
curl -sSL https://raw.githubusercontent.com/fullstaq-labs/fullstaq-ruby-server-edition/main/fullstaq-ruby.asc | apt-key add -
echo "deb https://apt.fullstaqruby.org debian-10 main" > /etc/apt/sources.list.d/fullstaq-ruby.list
apt-get update
apt-fast install -y fullstaq-ruby-common
apt-fast install -y fullstaq-ruby-2.6
echo 'export PATH=\$PATH:/usr/lib/fullstaq-ruby/versions/2.6/bin' > /etc/profile.d/fullstaq-ruby.sh

echo ">>> Installing Podman..."
echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/Debian_10/Release.key | apt-key add -
apt-get update
apt-fast install -y podman

echo ">>> Installing PostgreSQL..."
echo "deb http://apt.postgresql.org/pub/repos/apt \$(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/postgresql.list
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
apt-get update
apt-fast install -y postgresql-12
systemctl disable postgresql.service

echo ">>> Installing Percona Server for MySQL..."
wget https://repo.percona.com/apt/percona-release_latest.\$(lsb_release -sc)_all.deb
dpkg -i percona-release_latest.\$(lsb_release -sc)_all.deb
rm percona-release_latest.\$(lsb_release -sc)_all.deb
percona-release setup ps80
apt-fast install -y percona-server-server
systemctl disable mysql.service

systemctl disable redis-server.service
EOF

  echo ">>> Configuring system"
  chroot "${MOUNTPOINT}" /usr/sbin/grub-install "$LOOP_DEVICE"
  chroot "${MOUNTPOINT}" /usr/sbin/update-grub
  echo "sandbox" > "${MOUNTPOINT}/etc/hostname"
  cat > "${MOUNTPOINT}/etc/hosts" \
<< EOF
127.0.0.1       localhost
127.0.1.1       sandbox

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
  chroot "${MOUNTPOINT}" /usr/bin/bash - \
<< EOF
set -euo pipefail

echo -e "${ROOT_PASSWORD}\n${ROOT_PASSWORD}" | passwd
useradd -m -s /bin/bash -G sudo developer
mkdir /home/developer/.ssh
chmod 700 /home/developer/.ssh
echo '$(cat "$SSH_KEY")' > /home/developer/.ssh/authorized_keys
chmod 600 /home/developer/.ssh/authorized_keys
chown -R developer:developer /home/developer
truncate -s 0 /etc/machine-id || true
rm -rf /var/lib/dbus/machine-id || true
systemctl enable systemd-networkd
EOF
  cat > "${MOUNTPOINT}/etc/systemd/network/80-dhcp.network" \
<< EOF
[Match]
Name=en*
[Network]
DHCP=yes
EOF
  cat > "${MOUNTPOINT}/etc/ssh/sshd_config" \
<< EOF
Port 22
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
PermitRootLogin no
AllowUsers developer
PasswordAuthentication no
EOF
  cat > "${MOUNTPOINT}/etc/nftables.conf" \
<< EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport {22} accept
  }
  chain forward {
    type filter hook forward priority 0;
  }
  chain output {
    type filter hook output priority 0;
  }
}
EOF
  chmod 750 "${MOUNTPOINT}/etc/nftables.conf"
  cat > "${MOUNTPOINT}/etc/fail2ban/jail.local" \
<< EOF
[sshd]
enabled = true
port = 22
EOF
  echo "developer ALL = (ALL) NOPASSWD: ALL" > "${MOUNTPOINT}/etc/sudoers.d/developer"
  chmod 440 "${MOUNTPOINT}/etc/sudoers.d/developer"
  cat > "${MOUNTPOINT}/etc/rc.local" \
<< "EOF"
#!/usr/bin/env bash

set -euo pipefail

disk=$(ls /sys/class/block | sort -n | head -n 1)
growpart "/dev/${disk}" 2
resize2fs "$(findmnt / -o SOURCE -n)"
EOF
  chmod +x "${MOUNTPOINT}/etc/rc.local"

  echo ">>> Cleanup chroot"
  cleanup_chroot
}

main "$@"
