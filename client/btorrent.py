import os
import hashlib
import requests
import socket
import binascii
import struct
import math
import time
from bitstring import BitArray
from pprint import pprint as pp

try:
    from bencode import bencode, bdecode
except:
    print "Please have bencode installed by running pip install bencode."
    sys.exit()

BLOCK_LENGTH = 16384
AUTHOR_NAME = '__LIN_DONG__'
IP = '127.0.0.1'
PORT =52220
LOCAL =True

class torrent(object):
    ''' Torrent class'''

    def __init__(self, torrent_metainfo):
        ''' Make a torrent info clas '''
        self.metainfo = torrent_metainfo
        self.announce = torrent_metainfo.get('announce', None)
        self.info = torrent_metainfo.get('info', None)
        # print 'info: '
        # pp(self.info)
        print 'pieces info: '
        print type(self.info['pieces'])
        print_msg_in_hex(self.info['pieces'])
        time.sleep(1)
        self._FILE_LENGTH = int(self.info.get('length', None))
        self._PIECE_LENGTH = int(self.info.get('piece length', None))
        self._NUMBER_OF_PIECES = int(math.ceil(float(self._FILE_LENGTH) / \
                                float(self._PIECE_LENGTH)))
        # print '# of pieces: ', self._NUMBER_OF_PIECES

        # record the length of the last piece manually
        self._PIECE_LENGTH_OF_LAST = self._FILE_LENGTH % self._PIECE_LENGTH
        # print 'last piece: ', self._PIECE_LENGTH_OF_LAST
        self._NUMBER_OF_BLOCKS_FOR_EACH_PIECE = \
         int(math.ceil(float(self._PIECE_LENGTH)/float(BLOCK_LENGTH)))

        self._NUMBER_OF_BLOCKS_FOR_LAST_PIECE = \
         int(math.ceil(float(self._PIECE_LENGTH_OF_LAST)/float(BLOCK_LENGTH)))
        self._LAST_PIECE_BLOCK = self._PIECE_LENGTH_OF_LAST % BLOCK_LENGTH
        print '_last_piece_block', self._LAST_PIECE_BLOCK

        self.info_hash = self._get_info_hash()
        self.peer_id = self._get_peer_id()
        self.ip = self._get_ip()
        self.port = self._get_port()
        self.event = self._get_event()
        self.handshake_state = 0

        # both of dict are key = piece_index: value = False if not received
        self._peer_pieces_index_from_bitfield = {}
        self._peer_pieces_index_from_haves = {}

        print '# of blocks for each piece', self._NUMBER_OF_BLOCKS_FOR_EACH_PIECE
        print '# of blocks for last piece', self._NUMBER_OF_BLOCKS_FOR_LAST_PIECE
        print '# of pieces for the file', self._NUMBER_OF_PIECES
        print 'file length', self._FILE_LENGTH
        print 'piece length', self._PIECE_LENGTH
        print 'piece length last', self._PIECE_LENGTH_OF_LAST


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
        return self._FILE_LENGTH

    def _get_compact(self):
        '''1 for compact, 0 for non-compact
        For 1, the tracker response msg will be binary model
        For 0, the tracker response msg will be dictionary model
        '''
        return 0

    def _get_event(self):
        ''' States: started, stopped, completed '''
        return 'started'

    def _get_ip(self):
        ''' Return ip of the localhost '''
        return str([(s.connect(('8.8.8.8', 80)), s.getsockname()[0], \
            s.close()) for s in \
            [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
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
        params['left'] = self._get_left()
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

    def __get_number_of_piece(self):
        return self._NUMBER_OF_PIECES

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

    def connect_to_peer(self, ip= IP, port = PORT):
        self._parse_tracker_response()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        self._handshake_with_peer(s)
        self._unpack_msg(s)

        # starting state
        self._send_message('choke', s)
        self._send_message('not interested', s)
        choked = True
        interested = False
        self._set_peer_connection_state(choked, interested)

        while choked:
            self._send_message('unchoke', s)
            self._unpack_msg(s)

            self._send_message('interested', s)
            self._unpack_msg(s)
            choked, interested = self._get_peer_connection_state()
            # print 'while current state: choked:', choked, 'interested:', interested
            time.sleep(5)
        # else:
            # print 'else: current state: choked:', choked, 'interested:', interested
            # self._set_peer_connection_state(choked, interested)
        self._download_file(s)
        # final step
        s.close()

    def _download_file(self, s=None):
        ''' start to download the whole file, split into pieces '''
        print 'download file'
        file_list = [] # (file_name, sha1)
        for piece_index, downloaded in \
                self._peer_pieces_index_from_bitfield.iteritems():
            if not downloaded:
                print 'start to download file index:', piece_index
                piece_buff = self.__download_piece(s, piece_index, 0)
                a_sha1 = print_msg_in_hex(self.info['pieces'])
                b_sha1 = print_msg_in_hex(sha1_of_the_buffer(piece_buff))
                if a_sha1[1].find(b_sha1[1]) != -1:
                    print 'verified: ', b_sha1
                    file_list.append((save_piece_to_file(piece_buff, piece_index),\
                        sha1_of_the_buffer(piece_buff)))
                else:
                    print 'somethings up'
                    print 'a_sha1'
                    print a_sha1
                    pp(a_sha1)
                    print 'b_sha1'
                    print b_sha1
                    pp(b_sha1)

        combine_pieces_to_a_file([f for f, sha1 in file_list], self.info['name'])
        print ' ---finished download---'

    def __download_piece(self, s=None, piece_index=0, curr_block_index=0):
        ''' start to download each piece, split into blocks '''
        print 'download pieces: ', piece_index, '/', self._NUMBER_OF_PIECES
        print 'start block index:', curr_block_index
        piece_buff = ''

        if piece_index == self._NUMBER_OF_PIECES-1:
            print 'download the last piece'
            total_blocks = self._NUMBER_OF_BLOCKS_FOR_LAST_PIECE
        else:
            print 'download the regular piece'
            total_blocks = self._NUMBER_OF_BLOCKS_FOR_EACH_PIECE

        print '# of blocks to download:', total_blocks
        while curr_block_index < total_blocks:
            print 'curr block index:', curr_block_index
            # calculate offset
            offset = curr_block_index * BLOCK_LENGTH

            new_piece = self.__download_block(s, piece_index, offset)
            if new_piece != None:
                piece_buff += new_piece
                curr_block_index += 1

        self.__update_piece_info(piece_index, True)
        print 'piece buff assembled: ', piece_index
        # pp(piece_buff)
        return piece_buff

    def __download_block(self, s=None, piece_index=0, offset=0,\
            left=BLOCK_LENGTH):
        ''' start to download each block '''
        print 'download blocks:',
        self._send_message('request', s, (piece_index, offset, left))
        print 'piece_index:', piece_index,
        print 'offset:', offset,
        print 'left:', left
        block_buff = self._unpack_msg(s)
        if block_buff != None:
            return block_buff
            # offset += BLOCK_LENGTH
            # left -= BLOCK_LENGTH
            # print 'next_block_offset:', offset
            # print 'next_block_left', left
            # downloaded = self.__is_curr_block_index_is_total_blocks(piece_index)
        # print 'block buff: ',
        # pp(block_buff)

    def __update_piece_info(self, piece_index = None, downloaded = False):
        ''' update the piece information in bitfield '''
        self._peer_pieces_index_from_bitfield[piece_index] = downloaded

    def __is_current_piece_index_last_piece(self, piece_index):
        ''' return True or False '''
        return piece_index == self._NUMBER_OF_PIECES-1

    def __is_curr_block_index_is_total_blocks(self, piece_index):
        ''' return if the curr piece index is the total number of blocks '''
        if self.__is_current_piece_index_last_piece(piece_index):
            return piece_index == self._NUMBER_OF_BLOCKS_FOR_EACH_PIECE
        return piece_index == self._NUMBER_OF_BLOCKS_FOR_EACH_PIECE


    def __get_length_of_piece(self):
        ''' return the length of piece '''
        return self.__get_number_of_piece

    def _unpack_msg(self, s):
        ''' Unpack the message sent from other peer
        return the downloaded block data if necessary
        '''
        buff = self.__get_the_buffer_from_socket(s)
        # print 'Buff length: ',len(buff)
        # pp(buff)

        block_data = None
        while len(buff) > 0:
            msg_size = struct.unpack('!i', buff[0:4])[0]
            if msg_size > 0:
                msg_buff = buff[4:4+msg_size] # wrap the next n bits into a buff
                # print 'msg_buff: ',
                # print_msg_in_hex(msg_buff)
                block_data = self._extract_msg(msg_buff, msg_size)

                # trim buffer to the head
                buff = buff[4+msg_size:]
            else:
                print 'msg_size: ', msg_size
                break
        return block_data

    def __get_the_buffer_from_socket(self, s):
        ''' Combine each trunk buffer from the socket to a whole,
            this is a wrapper I wrote for __recv_timeout '''
        buff = self.__recv_timeout(s)
        return buff

    def __recv_timeout(self, the_socket, timeout=2):
        ''' Combine all recv buff, from http://tinyurl.com/n2xttfw '''
        #make socket non blocking
        the_socket.setblocking(0)

        #total data partwise in an array
        total_data=[];
        data='';

        #beginning time
        begin=time.time()
        while True:
            #if you got some data, then break after timeout
            if total_data and time.time()-begin > timeout:
                break
            #if you got no data at all, wait a little longer, twice the timeout
            elif time.time()-begin > timeout*2:
                break
            #recv something
            try:
                data = the_socket.recv(8192)
                if data:
                    total_data.append(data)
                    #change the beginning time for measurement
                    begin=time.time()
                else:
                    #sleep for sometime to indicate a gap
                    time.sleep(0.1)
            except:
                pass
        #join all parts to make final string
        return ''.join(total_data)

    def _extract_msg(self, msg_buffer, prefix):
        ''' extract msg from the whole buffer
        return recv block data if necessary
        '''
        msg_id = ord(struct.unpack('!c', msg_buffer[0])[0])
        block_data = None
        if msg_id == 0:
            # choke
            print 'set to choke'
            choked, interested = self._get_peer_connection_state()
            self._set_peer_connection_state(choked=True, interested=interested)
        elif msg_id == 1:
            # unchoke
            print 'set to unchoke'
            choked, interested = self._get_peer_connection_state()
            self._set_peer_connection_state(choked=False, interested=interested)
        elif msg_id == 2:
            # interested
            print 'set to interested'
            choked, interested = self._get_peer_connection_state()
            self._set_peer_connection_state(choked=choked,interested=False)
        elif msg_id == 3:
            # not interested
            print 'set to not interested'
            choked, interested = self._get_peer_connection_state()
            self._set_peer_connection_state(choked=choked,interested=True)
        elif msg_id == 4:
            # have
            piece_index = struct.unpack('!i', msg_buffer[1:])[0]
            self._peer_pieces_index_from_haves[piece_index] = False
            # print 'have, piece_index: ',
            # pp(piece_index)
        elif msg_id == 5:
            # bitfield
            bitfield_length = prefix - 1
            bitfield_payload = struct.unpack('!'+str(bitfield_length)+'s',
                    msg_buffer[1:1+bitfield_length])[0]
            # print 'bitfield length: ', bitfield_length
            # print 'bitfield payload: ', bitfield_payload

            if LOCAL:
                for idx in xrange(self._NUMBER_OF_PIECES):
                    self._peer_pieces_index_from_bitfield[idx] = False
                # self._peer_pieces_index_from_bitfield[0] = False
            else:
                for (index, exist) in enumerate(BitArray(bytes= bitfield_payload)):
                    if exist:
                        self._peer_pieces_index_from_bitfield[index] = False


        elif msg_id == 6:
            # request
            print 'recv request'
            pass
        elif msg_id == 7:
            # piece
            print 'recv piece'
            # print 'prefix:', prefix
            block_length = prefix - 9
            # print 'block_length: ', block_length
            # print 'from: ', 8+block_length
            index, begin, block = struct.unpack('!2i'+str(block_length)+'s',
                    msg_buffer[1:9+block_length])
            print 'Downloading piece_index: ', index
            # return block here
            block_data = block

        elif msg_id == 8:
            # cancel
            pass
        elif msg_id == 9:
            # port
            pass
        else:
            pass
        return block_data

    def _handshake_with_peer(self, s):
        ''' transmit a handshake to other peer '''
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
        recv_data = s.recv(BUFFER_SIZE)

    def _send_message(self, msg_state, s, block=None):
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
        if msg_state == 'interested':
            print 'sending interested'
            msg = (3*chr(0)+chr(1)+chr(2))
            s.sendall(msg)
        elif msg_state == 'not interested':
            print 'sending not interested'
            msg = (3*chr(0)+chr(1)+chr(3))
            s.sendall(msg)
        elif msg_state == 'choke':
            print 'sending choke'
            msg = (3*chr(0)+chr(1)+chr(0))
            s.sendall(msg)
        elif msg_state == 'request':
            print 'sending request'
            piece_index = None
            # pp(self._peer_pieces_index_from_bitfield)
            for piece_index, downloaded in\
                    self._peer_pieces_index_from_bitfield.iteritems():
                if not downloaded:
                    print 'piece index:', piece_index
                    break

            if block != None:
                (piece_index, offset, left) = block
                print 'offset:', offset
                download_length = BLOCK_LENGTH
                # if the last piece and the last block
                if (piece_index == self._NUMBER_OF_PIECES-1):
                    if BLOCK_LENGTH > self._PIECE_LENGTH_OF_LAST - offset:
                        download_length = self._PIECE_LENGTH_OF_LAST - offset
            print 'download length', download_length
            msg = struct.pack('!ib3i', 13, 6, piece_index, offset, download_length)
            # pp(msg)
            print_msg_in_hex(msg)
            s.sendall(msg)

    def _parse_message(self):
        ''' parse message received from other peer '''
        pass

    def _set_peer_connection_state(self, choked=True, interested=False):
        ''' return a tuple of states: chocked or not and interested or not'''
        self.__peer_connection_state = (choked, interested)


    def _get_peer_connection_state(self):
        ''' return a tuple of states: chocked or not and interested or not'''
        return self.__peer_connection_state

    def __str__(self):
        return str(self.announce)

def sha1_of_the_buffer(buff):
    return hashlib.sha1(buff).digest()

def verify_file_with_hash(small, large):
    ''' return if smalls sha1 is in larges'''
    # return large.lower().find(small.lower()) != -1
    return small == large

def save_piece_to_file(piece_buff, piece_index, prefix=AUTHOR_NAME):
    '''save piece into individual file
    return the name of file
    '''
    with open(prefix+str(piece_index), 'a') as piece:
        piece.write(piece_buff)
        print 'SHA1 buff', hashlib.sha1(piece_buff).hexdigest()
    return prefix+str(piece_index)

def combine_pieces_to_a_file(file_list, file_name):
    ''' combine pieces files into one file'''
    with open(file_name, 'w') as outfile:
        for fname in file_list:
            with open(fname) as infile:
                outfile.write(infile.read())
                os.remove(fname) # clean up after combined


def _list_of_bits_(target):
    return [__is_this_index_bit_set(target) for i in xrange(target.bit_length())]

def __is_this_index_bit_set(target, index):
    return 1<<index & target >0

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
