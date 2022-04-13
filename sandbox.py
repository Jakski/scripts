#!/usr/bin/env python3

import errno
import time
import os
import dbus
from distutils.spawn import find_executable
from argparse import ArgumentParser
from enum import IntFlag
from ctypes import (
    CFUNCTYPE,
    CDLL,
    get_errno,
    c_int,
    c_char_p,
    c_ulong,
    c_void_p,
)
from ctypes.util import find_library

import dbus


class Namespace(IntFlag):
    """Taken from <sched.h>."""

    MOUNT = 0x00020000
    IPC = 0x08000000
    USER = 0x10000000
    NET = 0x40000000
    PID = 0x20000000


class Mount(IntFlag):
    """Taken from <sys/mount.h>"""

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


class Library:
    def __init__(self, name):
        if lib_path := find_library(name):
            self._cdll = CDLL(lib_path, use_errno=True)
        else:
            raise LibraryError(f"Failed to find {name} library")

    @staticmethod
    def check_errno(name):
        def check_errno(result, func, args):
            if result != 0:
                e = get_errno()
                code = errno.errorcode[e]
                raise LibraryError(
                    f"Foreign function {name} failed with: {code}",
                    errno=e,
                )
            return args

        return check_errno


class AppArmor(Library):
    def __init__(self):
        super().__init__("apparmor")
        self.aa_change_onexec = CFUNCTYPE(c_int, c_char_p, use_errno=True)(
            ("aa_change_onexec", self._cdll),
            ((1, "profile"),),
        )
        self.aa_change_onexec.errcheck = self.check_errno("aa_change_onexec")


class Libc(Library):
    def __init__(self):
        super().__init__("c")
        self.unshare = CFUNCTYPE(c_int, c_int, use_errno=True)(
            ("unshare", self._cdll),
            ((1, "flags"),),
        )
        self.unshare.errcheck = self.check_errno("unshare")
        self.mount = CFUNCTYPE(
            c_int,
            c_char_p,
            c_char_p,
            c_char_p,
            c_ulong,
            c_void_p,
            use_errno=True,
        )(
            ("mount", self._cdll),
            (
                (1, "source"),
                (1, "target"),
                (1, "filesystemtype"),
                (1, "mountflags"),
                (1, "data"),
            ),
        )
        self.mount.errcheck = self.check_errno("mount")


def map_ids(uids, gids):
    with open("/proc/self/uid_map", "w") as f:
        for internal, external, count in uids:
            f.write(f"{internal} {external} {count}\n")
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")
    with open("/proc/self/gid_map", "w") as f:
        for internal, external, count in gids:
            f.write(f"{internal} {external} {count}\n")


def get_runtime_dir():
    if not (runtime_dir := os.environ.get("XDG_RUNTIME_DIR")):
        uid = os.getuid()
        runtime_dir = f"/run/user/{uid}"
    return runtime_dir


def ensure_dbus_proxy(name, src, dest):
    runtime_dir = get_runtime_dir()
    if not (program := find_executable("xdg-dbus-proxy")):
        raise RuntimeError("Could not find xdg-dbus-proxy executable in PATH")
    manager = dbus.Interface(
        dbus.SessionBus().get_object(
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
        ),
        dbus_interface="org.freedesktop.systemd1.Manager",
    )
    try:
        if unit := manager.GetUnit(name):
            return
    except dbus.exceptions.DBusException:
        pass
    manager.StartTransientUnit(
        name,
        "replace",
        [
            ("Description", "DBus filtering proxy for sandbox"),
            ("Type", "simple"),
            (
                "ExecStart",
                [
                    (
                        program,
                        [
                            program,
                            f"unix:path={runtime_dir}/{src}",
                            f"{runtime_dir}/{dest}",
                            "--filter",
                        ],
                        True,
                    )
                ],
            ),
        ],
        [],
    )
    for i in range(5):
        if os.path.exists(f"{runtime_dir}/{dest}"):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(
            f"DBus proxy {name} failed to create socket in {runtime_dir}/{dest}"
        )


def parse_arguments():
    parser = ArgumentParser(description="configure sandbox")
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        action="store",
        dest="profile",
        default="sandbox",
        help="AppArmor profile name",
    )
    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        action="store",
        dest="dir",
        required=True,
        help="path to alternative home directory",
    )
    parser.add_argument(
        dest="args",
        nargs="*",
        default=["/bin/bash"],
        help="command to run in sandboxed environment",
    )
    return parser.parse_args()


def setup_mountpoints(libc, args, home):
    runtime_dir = get_runtime_dir()
    libc.mount(
        source=args.dir.encode(),
        target=home.encode(),
        filesystemtype=None,
        mountflags=Mount.BIND,
        data=None,
    )
    libc.mount(
        source=f"{runtime_dir}/bus-sandbox".encode(),
        target=f"{runtime_dir}/bus".encode(),
        filesystemtype=None,
        mountflags=Mount.BIND,
        data=None,
    )
    libc.mount(
        source=f"{runtime_dir}/systemd/private-sandbox".encode(),
        target=f"{runtime_dir}/systemd/private".encode(),
        filesystemtype=None,
        mountflags=Mount.BIND,
        data=None,
    )
    libc.mount(
        source="tmpfs".encode(),
        target="/tmp".encode(),
        filesystemtype="tmpfs".encode(),
        mountflags=Mount.NOSUID | Mount.NOEXEC | Mount.NODEV,
        data="size=1G".encode(),
    )


def main():
    args = parse_arguments()
    args.dir = os.path.realpath(args.dir)
    ensure_dbus_proxy("dbus-sandbox-bus.service", "bus", "bus-sandbox")
    ensure_dbus_proxy(
        "dbus-sandbox-systemd.service", "systemd/private", "systemd/private-sandbox"
    )
    uid = os.getuid()
    gid = os.getgid()
    home = os.path.expanduser("~")
    if args.profile:
        apparmor = AppArmor()
    libc = Libc()
    libc.unshare(Namespace.USER | Namespace.MOUNT)
    map_ids(
        ((0, uid, 1),),
        ((0, gid, 1),),
    )
    os.chdir("/")
    setup_mountpoints(libc, args, home)
    os.chdir(home)
    libc.unshare(Namespace.USER | Namespace.IPC)
    map_ids(
        ((uid, 0, 1),),
        ((gid, 0, 1),),
    )
    if args.profile:
        try:
            apparmor.aa_change_onexec(args.profile.encode())
        except LibraryError as e:
            if e.errno == errno.ENOENT:
                raise RuntimeError(f"Failed to apply AppArmor profile: {args.profile}")
            raise e
    os.execv(args.args[0], args.args)


if __name__ == "__main__":
    main()
