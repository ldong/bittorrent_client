#!/usr/bin/env python
# Author: Lin Dong

import sys
import httplib
from pprint import pprint as pp
try:
    from bencode import bencode, bdecode
except:
    print "Please have bencode installed by running pip install bencode."
    sys.exit()

# import local torrent module
import btorrent

def main(args):
    if len(args) == 1:
        torrent_file = raw_input("Please enter the name of torrent file: ")
    else:
        torrent_file = args[1]
    torrent = parse_torrent(torrent_file)
    response = connect_torrent_file(torrent)

def connect_torrent_file(torrent):
    sha1_info = torrent.get_sha1()
    print sha1_info
    return None

def parse_torrent(torrent_file):
    with open(torrent_file, 'rb') as t:
            torrent_data = t.read()
    torrent_info = bdecode(torrent_data)
    torrent = btorrent.torrent(torrent_info)
    return torrent

if __name__ == '__main__':
    main(sys.argv)
