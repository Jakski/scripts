#!/usr/bin/env python3

import errno
import os
from argparse import ArgumentParser
from enum import IntFlag
from functools import partial
from ctypes import CDLL, get_errno, c_int
from ctypes.util import find_library


class Namespace(IntFlag):
    '''Taken from <sched.h>.'''

    MOUNT = 0x00020000
    IPC = 0x08000000
    USER = 0x10000000
    NET = 0x40000000
    PID = 0x20000000


class Mount(IntFlag):
    '''Taken from <sys/mount.h>'''

    RDONLY = 1
    NOSUID = 2
    NODEV = 4
    NOEXEC = 8
    NOATIME = 1024
    NODIRATIME = 2048
    BIND = 4096
    REC = 16384
    PRIVATE = 1 << 18


class LibraryError(Exception):

    def __init__(self, msg, errno=None):
        super().__init__(msg)
        self.errno = errno


class Library(CDLL):

    def __init__(self, name):
        if lib_path := find_library(name):
            super().__init__(lib_path, use_errno=True)
        else:
            raise LibraryError(f'Failed to find {name} library')

    def __getattr__(self, name):
        def check_errno(func, *args, **kwargs):
            r = func(*args, **kwargs)
            if e := get_errno():
                raise LibraryError(
                    f'Function failed with: {errno.errorcode[e]}',
                    errno=e,
                )
            return r
        return partial(check_errno, super().__getattr__(name))


def map_ids(uids, gids):
    with open('/proc/self/uid_map', 'w') as f:
        for internal, external in uids:
            f.write(f'{internal} {external} 1\n')
    with open('/proc/self/setgroups', 'w') as f:
        f.write('deny\n')
    with open('/proc/self/gid_map', 'w') as f:
        for internal, external in gids:
            f.write(f'{internal} {external} 1\n')


def main():
    parser = ArgumentParser(description='configure sandbox')
    parser.add_argument(
        '--profile', '-p', type=str,
        action='store', dest='profile', default='sandbox',
        help='AppArmor profile name',
    )
    parser.add_argument(
        '--dir', '-d', type=str,
        action='store', dest='dir', required=True,
        help='path to alternative home directory',
    )
    parser.add_argument(
        dest='args',
        nargs='*', default=['/bin/bash'],
        help='command to run in sandboxed environment',
    )
    args = parser.parse_args()
    uid = os.getuid()
    gid = os.getgid()
    home = os.path.expanduser('~')
    if args.profile:
        apparmor = Library('apparmor')
    libc = Library('c')
    libc.unshare(Namespace.USER | Namespace.MOUNT)
    map_ids(
        ((0, uid),),
        ((0, gid),),
    )
    os.chdir('/')
    libc.mount(args.dir.encode(), home.encode(), None, Mount.BIND, None)
    os.chdir(home)
    libc.unshare(Namespace.USER | Namespace.IPC)
    map_ids(
        ((uid, 0),),
        ((gid, 0),),
    )
    if args.profile:
        apparmor.aa_change_onexec(args.profile.encode())
    os.execv(args.args[0], args.args)


if __name__ == '__main__':
    main()
