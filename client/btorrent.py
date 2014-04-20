import os
import hashlib
import requests
import socket

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
        self.handshake_state = 0

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
        _port = '6881'
        return _port

    def _get_uploaded(self):
        return None

    def _get_downloaded(self):
        return None

    def _get_left(self):
        return 100

    def _get_compact(self):
        ''' 1 for compact, 0 for non-compact
            For 1, the tracker response msg will be binary model
            For 0, the tracker response msg will be dictionary model '''
        return 0

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
#        pp(params)
        return params

    def _get_response(self):
        #print self.announce
        r = requests.get(self.announce, params = self._get_request_params())
        r.raise_for_status()
        return bdecode(r.content)

    def _get_length(self):
        return self.info['length']

    def parse_tracker_response(self):
        ''' Parse the response sent from the trackers '''
        response = self._get_response()
        #pp(response)
        # First 4 bytes is IP
        #_peer_ip = response['peers'][:4]
        #pp(_peer_ip)
        # Last 2 bytes is port number
        #_peer_port = response['peers'][-2:]
        #pp(_peer_port)
        #_peer_port = int(_peer_port, 16)
        #pp(_peer_port)
        self._ip_id_ports = []
        for peer in response['peers']:
            other_peer_ip = peer['ip']
            other_peer_id = peer['peer id']
            other_peer_port = peer['port']
            ip_id_port = (other_peer_ip, other_peer_id, other_peer_port)
            self._ip_id_ports.append(ip_id_port)
            #print ip_id_port

        return response

    def handshake_with_peer(self):
        handshake_message = (chr(19)+"BitTorrent Protocol"+8*chr(0) +
                self.info_hash + self.peer_id)
        print len(handshake_message), handshake_message

        data = None
        while self.handshake_state == 0:
            for index, ip_id_port in enumerate(self._ip_id_ports):
                (other_peer_ip, other_peer_id, other_peer_port) = ip_id_port
                print index, '/', len(self._ip_id_ports),
                print 'IP: ', other_peer_ip,
                print 'Port: ', other_peer_port
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((str(other_peer_ip), other_peer_port))
                    s.sendall(handshake_message)
                    BUFFER_SIZE = 10240
                    data = s.recv(BUFFER_SIZE)
                except socket.error, e:
                    print "Socket exception and errors"
                except IOError, e:
                    print "IO Error"
                if data != None:
                    self.handshake_state = 1
                    print 'Data Length: ', len(data), ' Data: ', data
                else:
                    print 'Data: Nothing'
                data = None
                s.close()



    def __str__(self):
        return str(self.announce)

def parse_torrent(torrent_file):
    with open(torrent_file, 'rb') as t:
            torrent_data = t.read()
    torrent_info = bdecode(torrent_data)
    _torrent = torrent(torrent_info)
    return _torrent
