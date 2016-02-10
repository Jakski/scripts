#!/usr/bin/python3

import argparse
import os
import subprocess
import time

parser = argparse.ArgumentParser(prog='watcher.py',
        description='Simple filesystem watcher')
parser.add_argument('-l', '--files-list',
        help='document with list of files to observe')
parser.add_argument('-f', '--files', nargs='*',
        help='files to observe')
parser.add_argument('-c', '--command',
        help='command to execute')
parser.add_argument('-n', '--no-shell', action='store_false',
        help='do not use shell while evaluating command')

args = parser.parse_args()
if args.files_list != None:
    files = [line.rstrip('\n') for line in open(args.files_list)]
elif args.files:
    files = args.files
else:
    files = os.listdir()

# get initial modification time for files
for k, v in enumerate(files):
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(v)
    files[k] = [v, mtime]

args.command = '' if not args.command else args.command
process = subprocess.Popen(args.command, shell=args.no_shell)

# watch & restart loop
while 1:
    reloaded = False
    for k, v in enumerate(files):
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(v[0])
        if mtime != v[1] and not reloaded:
            process.send_signal(1)
            process.wait()
            process = subprocess.Popen(args.command, shell=args.no_shell)
            reloaded = True
        files[k][1] = mtime
    time.sleep(1)
