#!/usr/etc/env python
# Author: Lin Dong

import os
import sys
from pprint import pprint as pp
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

def parse_torrent(torrent_file):
    with open(torrent_file, 'rb') as t:
            torrent_data = t.read()
    torrent = bdecode(torrent_data)
    pp(torrent)
    print 'announce: ', torrent['announce']

if __name__ == '__main__':
    main(sys.argv)
