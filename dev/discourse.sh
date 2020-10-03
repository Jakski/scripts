#!/usr/bin/env bash

set -euo pipefail
trap 'ret=$?; test $ret -ne 0 && printf "failed\n\n" >&2; exit $ret' EXIT

DISCOURSE_ARCHIVE_URL="https://github.com/discourse/discourse/archive/master.tar.gz"
CONFIG_DIR="${HOME}/.config/discourse-setup"
if which apt-fast; then
  APT_GET="apt-fast"
else
  APT_GET="apt-get"
fi

mkdir -p "$CONFIG_DIR"
export DEBIAN_FRONTEND=noninteractive
echo "gem: --no-rdoc --no-ri" > ~/.gemrc
sudo -i gem install bundler mailcatcher
sudo yarn global add svgo
sudo apt-fast install -y \
  git \
  build-essential \
  libxslt1-dev \
  libcurl4-openssl-dev \
  libksba8 \
  libksba-dev \
  libreadline-dev \
  libssl-dev \
  zlib1g-dev \
  libsnappy-dev \
  libsqlite3-dev \
  sqlite3 \
  libmagick++-dev \
  imagemagick \
  advancecomp \
  gifsicle \
  jpegoptim \
  libjpeg-progs \
  optipng \
  pngcrush \
  pngquant \
  jhead \
  libpq-dev
if ! [ -e "discourse-master" ]; then
  curl -sSL "$DISCOURSE_ARCHIVE_URL" | tar -xzf -
fi

cd discourse-master
sudo systemctl start postgresql redis-server
! [ -e "${CONFIG_DIR}/psql_user" ] && {
  sudo -u postgres createuser -s "$USER"
  touch "${CONFIG_DIR}/psql_user"
}
bundle install
! [ -e "${CONFIG_DIR}/psql_db" ] && {
  bundle exec rake db:create
  touch "${CONFIG_DIR}/psql_db"
}
bundle exec rake db:migrate
RAILS_ENV=test bundle exec rake db:create db:migrate
