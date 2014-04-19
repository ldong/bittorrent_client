import os
import hashlib
import requests

from pprint import pprint as pp
try:
    from bencode import bencode, bdecode
except:
    print "Please have bencode installed by running pip install bencode."
    sys.exit()

class torrent(object):
    ''' Torrent class'''

    def __init__(self, torrent_metainfo):
        ''' Make a torrent info clas '''
        self.metainfo = torrent_metainfo
        self.announce = torrent_metainfo.get('announce', None)
        self.info = torrent_metainfo.get('info', None)
        # pp(self.info)
        self.info_hash = self._get_info_hash()
        self.peer_id = self._get_peer_id()
        self.port = self._get_port()
        self.event = self._get_event()

    def _get_info_hash(self):
        ''' Generate info has '''
        sha1_info = hashlib.sha1(bencode(self.info))
        # print sha1_info.hexdigest()
        # return unicode(sha1_info.digest(), 'utf-8')
        # pp(sha1_info.digest().decode('utf-8','ignore'))
        return sha1_info.digest()

    def _get_peer_id(self):
        ''' Return 20 bytes long string, using Azureus-style '''
        peer_id = '-LD0001-'+'000000000001'
        return peer_id

    def _get_port(self):
        ''' Return listening port from client, typically 6881-6889 '''
        return '6881'

    def _get_uploaded(self):
        return None

    def _get_downloaded(self):
        return None

    def _get_left(self):
        return 100

    def _get_compact(self):
        return 1

    def _get_event(self):
        ''' States: started, stopped, compleeted '''
        return 'started'

    def _get_ip(self):
        return None

    def _get_numwant(self):
        return None

    def _get_key(self):
        return None

    def _get_trackerid(self):
        return None

    def _get_request_params(self):
        ''' list of params for sending request to tracker '''
        params = {}

        # required params
        params['info_hash'] = self.info_hash
        params['peer_id'] = self.peer_id
        params['port'] = self.port
        params['uploaded'] = self._get_uploaded()
        params['downloaded'] = self._get_downloaded()
        # params['left'] = self._get_left()
        params['left'] = self._get_length()
        params['compact'] = self._get_compact()
        params['event'] = self.event

        # optional params
#        params['ip'] = self._get_ip()
#        params['numwant'] = self._get_numwant()
#        params['key'] = self._get_key()
#        params['trackerid'] = self._get_trackerid()
        pp(params)
        return params

    def get_response(self):
        print self.announce
        r = requests.get(self.announce, params = self._get_request_params())
        r.raise_for_status()
        return bdecode(r.content)

    def _get_length(self):
        return self.info['length']

    def __str__(self):
        return str(self.announce)

def parse_torrent(torrent_file):
    with open(torrent_file, 'rb') as t:
            torrent_data = t.read()
    torrent_info = bdecode(torrent_data)
    _torrent = torrent(torrent_info)
    return _torrent
