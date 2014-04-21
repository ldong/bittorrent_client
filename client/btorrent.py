import os
import hashlib
import requests
import socket
import binascii
import struct

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
        self.ip = self._get_ip()
        self.port = self._get_port()
        self.event = self._get_event()
        self.handshake_state = 0
        self.peer_connection_state = self._get_peer_connection_state()

    def _get_info_hash(self):
        ''' Generate info has '''
        sha1_info = hashlib.sha1(bencode(self.info))
        # print sha1_info.hexdigest()
        # return unicode(sha1_info.digest(), 'utf-8')
        # pp(sha1_info.digest().decode('utf-8','ignore'))
        return sha1_info.digest()

    def _get_info_hash_hex(self):
        return hashlib.sha1(bencode(self.info)).hexdigest()


    def _get_peer_id(self):
        ''' Return 20 bytes long string, using Azureus-style '''
        peer_id = '-LD0001-'+'000000000001'
        return peer_id

    def _get_port(self):
        ''' Return listening port from client, typically 6881-6889 '''
        _port = 6882
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
        ''' States: started, stopped, completed '''
        return 'started'

    def _get_ip(self):
        ''' Return ip of the localhost '''
        return str([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
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
#        params['ip'] = self.ip
#        params['numwant'] = self._get_numwant()
#        params['key'] = self._get_key()
#        params['trackerid'] = self._get_trackerid()
        return params

    def _get_response(self):
        #print self.announce
        r = requests.get(self.announce, params = self._get_request_params())
        r.raise_for_status()
        return bdecode(r.content)

    def _get_length(self):
        return self.info['length']

    def _parse_tracker_response(self):
        ''' Parse the response sent from the trackers '''
        response = self._get_response()
        self._ip_id_ports = []
        for peer in response['peers']:
            other_peer_ip = peer['ip']
            other_peer_id = peer['peer id']
            other_peer_port = peer['port']
            ip_id_port = (other_peer_ip, other_peer_id, other_peer_port)
            self._ip_id_ports.append(ip_id_port)
        return response

    def connect_to_peer(self, ip= '127.0.0.1', port = 52220):
        self._parse_tracker_response()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        self._handshake_with_peer(s)
        self._exchange_msg(s)
        s.close()

    def _exchange_msg(self, s):
        ''' Exchange msg from client to other peer'''
        BUFFER_SIZE = 32
        msg_buffer = s.recv(BUFFER_SIZE)

        prefix, = struct.unpack('!4s', msg_buffer[0:4])
        print_msg_in_hex(prefix)
        for p in prefix:
            print 'p:', int(p, 16)
        #print_msg_in_hex('1')
        #while msg_buffer != 0:
        #    prefix = struct.unpack('!4i', msg_buffer[1:4])
        #    print prefix
        #    bitfield_length = int(binascii.hexlify(bitfield_buffer[0:4]), 16) - int('0001', 16)
        #    print 'value:', int(binascii.hexlify(bitfield_buffer[0:4]), 16)
        #    print int('0001', 16)
        #    print 'length: ', bitfield_length
        #    bitfield_data = bitfield_buffer[5:5+bitfield_length]
        #    print 'bitfield_data: ',
        #    print_msg_in_hex(bitfield_data)
        #    buffer = s.recv(BUFFER_SIZE)

        # send choke and not interested on the initialization
        #s.sendall(self._send_message('choke'))
        data = s.recv(BUFFER_SIZE)
        print 'Data: ',
        print_msg_in_hex(data)

       # prefix = data[0:4]
       # print 'Prefix: ',
       # print_msg_in_hex(prefix)
       # fifth = data[4]
       # print 'Fifth: ',
       # print_msg_in_hex(fifth)

       # s.sendall(self._send_message('not interested'))
       # data = s.recv(BUFFER_SIZE)
       # #print 'Data: ', print_msg_in_hex(data)

       # prefix = data[0:4]
       # print 'Prefix: ', print_msg_in_hex(prefix)
       # fifth = data[4]
       # print 'Fifth: ',
       # print_msg_in_hex(fifth)

       # (chocked, interested) = self.peer_connection_state

       # while choked:
       #     s.sendall()
       #     (chocked, interested) = self.peer_connection_state

       # s.sendall(self._send_message('interested'))
       # data = s.recv(BUFFER_SIZE)
       # print 'Data: ', print_msg_in_hex(data)



    def _handshake_with_peer(self, s):
        handshake_message = (chr(19)+"BitTorrent protocol"+8*chr(0) +
                self.info_hash + self.peer_id)
        #print len(handshake_message), ': ', handshake_message, 'hash: ', \
        #    hashlib.sha1(handshake_message).hexdigest()

        data = None
#        while self.handshake_state == 0:
#        ''' keep handshakes until find a seeder '''
#            #self.parse_tracker_response()
#            for index, ip_id_port in enumerate(self._ip_id_ports):
#                (other_peer_ip, other_peer_id, other_peer_port) = ip_id_port
#                print index, '/', len(self._ip_id_ports),
#                print 'IP: ', other_peer_ip,
#                print 'Port: ', other_peer_port
#                try:
#                    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                    t.settimeout(1)
#                    #s.bind((self.ip, self.port))
#                    t.connect((str(other_peer_ip), other_peer_port))
#                    t.sendall(handshake_message)
#                    BUFFER_SIZE = 10240
#                    data = s.recv(BUFFER_SIZE)
#                except socket.error, e:
#                    print "Socket exception and errors"
#                except IOError, e:
#                    print "IO Error"
#                if data != None and len(data) == 68:
#                    self.handshake_state = 1
#                    print 'Data Length: ', len(data), ' Data: ', data
#                    break
#                t.close()

        BUFFER_SIZE = 68
        s.sendall(handshake_message)
        data = s.recv(BUFFER_SIZE)
        if len(data) == BUFFER_SIZE:
            print 'Data: ', data
        else:
            print 'Bad data'

    def _send_message(self, msg_state):
        ''' send message to other peer
            0 - choke            no payload
            1 - unchoke          no payload
            2 - interested       no payload
            3 - not interested   no payload
            4 - have
            5 - bitfield
            6 - request
            7 - piece
            8 - cancel '''
        msg_length_prefix = {'keep-alive': '0000', 'choke': '00010',
                            'unchoke': '00011', 'interested': '00012',
                            'not interested': '00013', 'have': '0005',
                            'bitfield': '0001', 'request' : '0013',
                            'piece': '0009', 'cancel': '0013',
                            'port' : '0003' }

        if(msg_state == 'keep-alive' or
                msg_state == 'choke' or
                msg_state == 'unchoke' or
                msg_state == 'interested' or
                msg_state == 'not interested'):
            return msg_length_prefix[msg_state]

    def _parse_message(self):
        ''' parse message received from other peer '''
        pass

    def _get_peer_connection_state(self):
        ''' return a tuple of states: chocked or not and interested or not'''
        chocked = True
        interested = False
        return (chocked, interested)

    def __str__(self):
        return str(self.announce)


def print_msg_in_hex(line):
    msg = len(line), ':'.join(x.encode('hex') for x in line)
    print msg
    return msg

def parse_torrent(torrent_file):
    with open(torrent_file, 'rb') as t:
            torrent_data = t.read()
    torrent_info = bdecode(torrent_data)
    _torrent = torrent(torrent_info)
    return _torrent
