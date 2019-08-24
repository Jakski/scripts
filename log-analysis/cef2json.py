#!/usr/bin/env python3

import re
import json
import sys
from argparse import ArgumentParser


def main():
    parser = ArgumentParser(description='Common Event Format to JSON converter')
    parser.add_argument(
        '-f', '--file', type=str,
        action='store', dest='file', required=True,
        help='file with logs or "-" to read from stdin')
    parser.add_argument(
        '-s', '--separator', type=str,
        action='store', dest='separator', default=' ',
        help='field separator')
    parser.add_argument(
        '-q', '--quote', type=str,
        action='store', dest='quote', default='"',
        help='quote character')
    args = parser.parse_args()
    if args.file == '-':
        source = sys.stdin
    else:
        source = open(args.file, 'r')
    entry_pattern = re.compile(
        f'(\\S+)=({args.quote}.*?(?<!\\\\){args.quote}'
        f'|[^{args.separator}{args.quote}]*)')
    while True:
        line = source.readline().rstrip()
        if not line:
            break
        print(json.dumps({i[0]: i[1] for i in entry_pattern.findall(line)}))


if __name__ == '__main__':
    main()
