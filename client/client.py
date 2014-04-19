#!/usr/bin/env python
# Author: Lin Dong

import sys
import requests
from pprint import pprint as pp

import btorrent

def main(args):
    if len(args) == 1:
        torrent_file = raw_input("Please enter the name of torrent file: ")
    else:
        torrent_file = args[1]
    torrent = btorrent.parse_torrent(torrent_file)
    response = connect_torrent_file(torrent)

def connect_torrent_file(torrent):
    # sha1_info = torrent.info_hash
    # print sha1_info
    response = None
    return response


if __name__ == '__main__':
    main(sys.argv)
