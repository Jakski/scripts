#!/bin/bash
# Script assumes it's working on Debian based container, so you should
# change distro related commands, if you plan to use it with other system.

set -e

USER=${USER:-devel}

for i in "$@"
do
    case $1 in
    '-s')
        OPEN_SHELL=yes
        ;;
    '-u')
        SET_USER=yes
        ;;
    '-g')
        INSTALL_GIT=yes
        ;;
    *)
        CONTAINER=$1
        ;;
    esac
    shift
done

if [[ $SET_USER == yes ]]; then
    docker exec $CONTAINER useradd --uid $(id -u) \
        --user-group \
        --home-dir /home/$USER \
        --shell /bin/bash \
        -m $USER
fi

if [[ $INSTALL_GIT == yes ]]; then
    docker exec $CONTAINER apt-get install -y git
fi

if [[ $OPEN_SHELL == yes ]]; then
    docker exec -it $CONTAINER /bin/bash
fi
