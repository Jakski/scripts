#!/usr/bin/env python3

import errno
import time
import socket
import os
import dbus
from distutils.spawn import find_executable
from argparse import ArgumentParser
from enum import IntFlag
from functools import partial
from ctypes import CDLL, get_errno, c_int
from ctypes.util import find_library

import dbus


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
                fn = func.__name__
                code = errno.errorcode[e]
                raise LibraryError(
                    f'Function {fn} failed with: {code}',
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

def get_runtime_dir():
    if not (runtime_dir := os.environ.get('XDG_RUNTIME_DIR')):
        uid = os.getuid()
        runtime_dir = f'/run/user/{uid}'
    return runtime_dir

def ensure_dbus_proxy(name, src, dest):
    runtime_dir = get_runtime_dir()
    if not (program := find_executable('xdg-dbus-proxy')):
        raise RuntimeError('Could not find xdg-dbus-proxy executable in PATH')
    manager = dbus.Interface(
        dbus.SessionBus().get_object(
            'org.freedesktop.systemd1',
            '/org/freedesktop/systemd1',
        ),
        dbus_interface='org.freedesktop.systemd1.Manager',
    )
    try:
        if unit := manager.GetUnit(name):
            # TODO: What, if service is stopped?
            return
    except dbus.exceptions.DBusException:
        pass
    manager.StartTransientUnit(
        name, 'replace',
        [
            ('Description', 'DBus filtering proxy for sandbox'),
            ('Type', 'simple'),
            ('ExecStart', [(program, [
                program,
                f'unix:path={runtime_dir}/{src}',
                f'{runtime_dir}/{dest}',
                '--filter',
            ], True)]),
        ],
        [],
    )
    # TODO: xdg-dbus-proxy supports signaling readiness over file descriptor.
    time.sleep(1)


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
    args.dir = os.path.realpath(args.dir)
    # TODO: Can it be done simpler?
    ensure_dbus_proxy('dbus-sandbox-bus.service', 'bus', 'bus-sandbox')
    ensure_dbus_proxy(
        'dbus-sandbox-systemd.service',
        'systemd/private',
        'systemd/private-sandbox'
    )
    uid = os.getuid()
    gid = os.getgid()
    home = os.path.expanduser('~')
    runtime_dir = get_runtime_dir()
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
    libc.mount(
        f'{runtime_dir}/bus-sandbox'.encode(),
        f'{runtime_dir}/bus'.encode(),
        None, Mount.BIND, None,
    )
    libc.mount(
        f'{runtime_dir}/systemd/private-sandbox'.encode(),
        f'{runtime_dir}/systemd/private'.encode(),
        None, Mount.BIND, None,
    )
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
