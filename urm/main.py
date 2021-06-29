#!/usr/bin/env python3
# main.py -*-python-*-

import argparse
import re

import urm.config
import urm.pool

# pylint: disable=unused-import
from urm.log import PDLOG_SET_LEVEL, DEBUG, INFO, ERROR, FATAL


def main():
    parser = argparse.ArgumentParser(description='urm')
    parser.add_argument('-c', '--config', default=None,
                        help='Configuration file')
    parser.add_argument('--dump', action='store_true',
                        default=False, help='Dump configuration and exit')
    parser.add_argument('-n', '--dry-run', action='store_true',
                        default=False, help='Do not execuate remote commands')
    parser.add_argument('-d', '--debug', action='store_true',
                        default=False, help='Display remote debugging info')
    parser.add_argument('--username', default=None, help='Username')
    parser.add_argument('--password', default=None, help='Password')
    parser.add_argument('--ip', default=None, help='Temporary IP')
    parser.add_argument('target', type=str, nargs='?',
                        help='Target host or set of hosts')
    parser.add_argument('command', type=str, nargs=argparse.REMAINDER,
                        help='Command to execute')
    args = parser.parse_args()

    if args.config:
        config = urm.config.Config(paths=[args.config],
                                   username=args.username,
                                   password=args.password)
    else:
        config = urm.config.Config(username=args.username,
                                   password=args.password)

    if args.dump:
        print(config.dump())
        return 0

    if args.target is None:
        parser.print_help()
        return -1
    INFO('args.target=%s', args.target)
    if re.search(',', args.target):
        target_list = args.target.split(',')
    else:
        target_list = args.target
    INFO('target_list=%s', target_list)
    target_list = config.expand_target_list(target_list)

    INFO('target_list=%s', target_list)
    if args.ip is not None and len(target_list) > 1:
        FATAL('The --ip argument is only valid for one target')
    pool = urm.pool.Pool(config, target_list, dry_run=args.dry_run,
                         debug=args.debug, ip=args.ip)
    pool.run(' '.join(args.command))
    return 0
