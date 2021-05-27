import subprocess
import os
from getpass import getpass
from argparse import ArgumentParser

from pykeepass import PyKeePass


def create_entry(passdb, path, passfile):
    passfile = '.'.join(passfile.split('.')[:-1])
    path = path.split('/')
    acc = []
    while len(acc) != len(path):
        acc.append(path[len(acc)])
        if acc not in [g.path for g in passdb.groups]:
            passdb.add_group(
                passdb.find_groups(path=acc[:-1], first=True),
                acc[-1]
            )
    entry = subprocess.run(
        ['pass', 'show', '/'.join(acc) + '/' + passfile],
        universal_newlines=True,
        check=True,
        stdout=subprocess.PIPE
    ).stdout.split('\n')
    username = None
    url = None
    username_prefixes = ['username', 'mail', 'email', 'login', 'user']
    for line in entry[1:]:
        for prefix in username_prefixes:
            if username is None and line.startswith(prefix + ': '):
                username = line[len(prefix + ': '):]
                break
        if line.startswith('url: '):
            url = line[len('url: '):]
    entry = [entry[0]] + list(filter(
        lambda x: not any(
            [
                x.startswith(prefix) or x.startswith('url: ')
                for prefix in username_prefixes
            ]
        ),
        entry[1:]
    ))
    passdb.add_entry(
        passdb.find_groups(path=acc, first=True),
        title=passfile,
        username=username or '',
        password=entry[0],
        url=url,
        notes='\n'.join(map(
            lambda x: x[len('comment: '):] if x.startswith('comment: ') else x,
            entry[1:]
        )),
    )


def main():
    parser = ArgumentParser(description='pass to keepass database converter')
    parser.add_argument(
        '--pass-dir', type=str,
        action='store', dest='pass_dir', required=True,
        help='Directory with pass repository'
    )
    parser.add_argument(
        '--keepass-db', type=str,
        action='store', dest='keepass_db', required=True,
        help='Output KDBX file'
    )
    args = parser.parse_args()
    password = getpass('Enter KDBX password: ')
    passdb = PyKeePass(args.keepass_db, password)
    for root, _, files in os.walk(args.pass_dir):
        root = os.path.relpath(root, args.pass_dir)
        if root.startswith('.git'):
            continue
        for passfile in files:
            if passfile == '.gpg-id' or passfile == '.gitattributes':
                continue
            create_entry(passdb, root, passfile)
    passdb.save()
