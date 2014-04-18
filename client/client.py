#!/usr/etc/env python
# Author: Lin Dong

import os
import sys

try:
    from bencode import bencode, bdecode
except:
    print "Please have bencode installed by running pip install bencode."
    sys.exit()

def main(args):
    if len(args) == 1:
        torrent = raw_input("Please enter the name of torrent file: ")
    else:
        torrent = args[1]
    parse_torrent(torrent)

def parse_torrent(torrent):
    with open(torrent, 'r') as f:
            file_data = f.read()
    data = list(file_data)
    for d in data:
        print d,

if __name__ == '__main__':
    main(sys.argv)
