import os
import hashlib
import urllib
try:
    from bencode import bencode, bdecode
except:
    print "Please have bencode installed by running pip install bencode."
    sys.exit()

class torrent(object):
    ''' Torrent class'''

    def __init__(self, torrent_metainfo):
        """Make a torrent info clas"""
        self.metainfo = torrent_metainfo
        self.announce = torrent_metainfo.get('announce', None)
        self.info = torrent_metainfo.get('info', None)
        # self.info_hash = self._get_info_hash_w_urlencoded()
        self.info_hash = self._get_info_hash_wo_urlencoded()

    def _get_info_hash_w_urlencoded(self):
        ''' Generate info hash with url encoded'''
        return urllib.urlencode(self._get_info_hash_wo_urlencoded())

    def _get_info_hash_wo_urlencoded(self):
        ''' Generate info hash without url encoded '''
        sha1_info = hashlib.sha1()
        sha1_info.update(bencode(self.info))
        print sha1_info.hexdigest()
        return sha1_info.hexdigest()
        # return sha1_info.digest()

    def __str__(self):
        return str(self.announce)

def parse_torrent(torrent_file):
    with open(torrent_file, 'rb') as t:
            torrent_data = t.read()
    torrent_info = bdecode(torrent_data)
    _torrent = torrent(torrent_info)
    return _torrent
