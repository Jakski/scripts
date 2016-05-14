#!/bin/bash
# Script assumes it's working on Debian based container, so you should
# change distro related commands, if you plan to use it with other system.

set -e

USER=${USER:-devel}

case $1 in
'shell')
    docker exec -it $2 /bin/bash
    ;;
'user')
    docker exec $2 useradd --uid $(id -u) \
        --user-group \
        --home-dir /home/$USER \
        --shell /bin/bash \
        -m $USER
    ;;
'git')
    docker exec $2 apt-get install -y git
    ;;
*)
    (>&2 echo $1: no such command)
    ;;
esac
