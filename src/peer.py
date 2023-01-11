import pickle
import argparse

# import hashlib
import socket
import struct
import select
import sys
import os
from time import time
import copy
import math

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from util import bt_utils
from util import simsocket
from collections import deque

# configurations
BUF_SIZE = 1400
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024
CHUNK_DATA_SIZE = 512 * 1024
MAGIC = 52305
HASHLEN = 40
SENDPKT = ">HBBHHII"
RECVPKT = ">HBBHHII"
RDT_TIMEOUT = 3

# packet types
WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5
pkt_types = ["WHOHAS", "IHAVE", "GET", "DATA", "ACK", "DENIED"]

# states of other peers
DISCONNECTED = -1
HANDSHAKE = 0
SEND = 1
RECV = 2

# congection control state
SLOW_START = 0
CONGECTION_AVOIDANCE = 1

receiving_chunks = {}


class Peer:
    """
    A Peer keeps track of the state of a peer.
    """

    def __init__(self, configuration):
        self.ex_output_file = None
        # {team number : checksum}, records the data that is being downloaded from peers
        self.downloading = {}
        # [checksum of chunks to be downloaded], records the data that should be downloaded later
        self.demand = []
        # [(team number, ip, port, state)], records the address of other peers
        self.peers = {int(n): (i, p, DISCONNECTED) for n, i, p in configuration.peers}
        # {checksum(bytes) : data}, records the data that this peer already has
        self.haschunks = {
            bytes(x, "ascii"): config.haschunks[x] for x in config.haschunks
        }
        # {team number : checksum}, record the chunks of the peers that have initiated handshake
        self.peerchunks = {}
        self.team = configuration.identity
        self.maxconn = configuration.max_conn
        # ==========reliable data transmit==========
        self.sendBuffer = (
            {}
        )  # {team number : checksum}, records the data that is being sent to peers
        self.sentWindow = {}  # {team: packet}
        self.sendWin_lower = {}  # lower edge of sendWindow
        self.sendWin_upper = {}  # upper edge of sendWindow
        self.recvBuffer = {}
        self.expectedSeqNum = {}
        self.rdt_timer = {}
        self.GET_timer = {}
        # ==========congestion control: GBN protocol==========
        self.congWinSize = {}                   # congestion Window, initialized to 1
        self.ssthreshold = {}               # congestion threshold
        self.dupACKcount = {}                # duplicate ACK
        self.congState = {}         # default state: slow start
        first_timeout = {int(n): False for n, _, _ in configuration.peers}

        self.first_timeout = {int(n): False for n, _, _ in configuration.peers}

    def constr_packet(self, packet_type, seq, ack, data: bytes):
        # |2byte magic|1byte team|1byte type|
        # |2byte  header len  |2byte pkt len |
        # |      4byte  seq                  |
        # |      4byte  ack                  |
        header = struct.pack(
            SENDPKT,
            socket.htons(MAGIC),
            self.team,
            packet_type,
            socket.htons(HEADER_LEN),
            socket.htons(HEADER_LEN + len(data)),
            socket.htonl(seq),
            socket.htonl(ack),
        )
        pkt = header + data
        return pkt

    def constr_whohas(self, download_hash):
        data = b""
        for d in download_hash:
            data += d
        return self.constr_packet(WHOHAS, 0, 0, data)

    def constr_ihave(self, pkt_list):
        data = b""
        for p in pkt_list:
            data += p
        return self.constr_packet(IHAVE, 0, 0, data)

    def constr_denied(self):
        return self.constr_packet(DENIED, 0, 0, b"")

    def initial_download(self, sock, chunkfile, outputfile):
        """
        if DOWNLOAD is used, the peer will keep getting files until it is done
        parameter
        ---------
        chunkfile: chunks needed {*.chunkhash}
        outputfile: download path {*.fragment}
        """
        self.ex_output_file = outputfile
        with open(chunkfile, "r", encoding="utf-8") as cf:
            lines = cf.readlines()
            for line in lines:
                _, datahash_str = line.strip().split(" ")
                datahash_str = bytes(datahash_str, encoding="ascii")
                if (
                    datahash_str not in self.demand
                    and datahash_str not in self.haschunks
                    and datahash_str not in self.downloading.values()
                ):
                    receiving_chunks.update({datahash_str: bytes()})
                    self.demand.append(datahash_str)

        self.broadcast(sock)

    def process_inbound_udp(self, sock):
        # Receive pkt
        pkt, from_addr = sock.recvfrom(BUF_SIZE)
        _, Team, Type, hlen, plen, Seq, Ack = struct.unpack(RECVPKT, pkt[:HEADER_LEN])
        hlen = socket.ntohs(hlen)  # head length
        plen = socket.ntohs(plen)  # pkt length
        dlen = plen - hlen  # data length
        data = pkt[hlen:]  # data containt
        seq_num = socket.ntohl(Seq)
        ack_num = socket.ntohl(Ack)
        print(
            f"received {pkt_types[Type]} pkt: [from team: {Team}; head length: {hlen}; data length: {dlen}; seq: {seq_num}; ack: {ack_num};"
        )
        if Type == WHOHAS:
            # received an WHOHAS pkt
            # see what chunk the sender has
            whohas_chunk_hash_list = []
            i = 0
            while i < dlen:
                whohas_chunk_hash = data[i : i + HASHLEN]
                # print(f"whohas_chunk_hash = {whohas_chunk_hash}")
                i += HASHLEN
                if whohas_chunk_hash not in whohas_chunk_hash_list:
                    whohas_chunk_hash_list.append(whohas_chunk_hash)

            print(f"has: {list(self.haschunks.keys())}")
            ihave_pkt_list = [h for h in whohas_chunk_hash_list if h in self.haschunks]
            print(f"ihave_pkt_list = {ihave_pkt_list}")
            print("=================================")
            if len(self.sendBuffer) < MAX_PAYLOAD and ihave_pkt_list:
                # send back IHAVE pkt
                ihave_pkt = self.constr_ihave(ihave_pkt_list)
                sock.sendto(ihave_pkt, from_addr)

                # change the state to HANDSHAKE
                self.peers[Team] = (*self.peers[Team][0:2], HANDSHAKE)
            elif len(self.sendBuffer) >= self.maxconn and ihave_pkt_list:
                denied_header = self.constr_denied()
                sock.sendto(denied_header, from_addr)
        elif Type == IHAVE:
            # received an IHAVE pkt
            # see what chunk the sender has
            get_chunk_hash_list = []
            i = 0
            while i < dlen:
                get_chunk_hash = data[i : i + HASHLEN]
                i += HASHLEN
                get_chunk_hash_list.append(get_chunk_hash)
            self.peerchunks.update({Team: get_chunk_hash_list})
            print(f"Team {Team} has: {get_chunk_hash_list}")
            print("=================================")
            # change the state to HANDSHAKE

            self.peers[Team] = (*self.peers[Team][0:2], HANDSHAKE)
        elif Type == GET:
            # 当发送端收到GET请求时，就初始化sendBuffer，并且发送第一个DATA包
            print(f"receive get from peer {Team}")
            # received a GET pkt
            send_chunk_checksum = data[:HASHLEN]
            print(f"send_chunk_checksum = {send_chunk_checksum}")

            # init sendBuffer, sendWindow
            self.sendBuffer[Team] = [self.haschunks[send_chunk_checksum][i*MAX_PAYLOAD: (i+1)*MAX_PAYLOAD] for i in range(512)]
            self.sendWin_lower[Team] = 1
            self.sendWin_upper[Team] = 1
            self.sentWindow[Team] = deque()
            self.dupACKcount[Team] = 1
            # init congection controller
            self.congWinSize[Team] = 1
            self.congState[Team] = SLOW_START
            self.ssthreshold[Team] = 1024

            while self.sendWin_upper[Team] < self.sendWin_lower[Team] + self.congWinSize[Team]:
                chunk_data = self.sendBuffer[Team][self.sendWin_upper[Team] - 1]
                data_header = struct.pack(
                    SENDPKT,
                    socket.htons(MAGIC),
                    self.team,
                    DATA,
                    socket.htons(HEADER_LEN),
                    socket.htons(HEADER_LEN + len(chunk_data)),
                    socket.htonl(self.sendWin_upper[Team]),
                    0,
                )
                data_pkt = data_header + chunk_data
                self.sentWindow[Team].append(data_pkt)
                sock.sendto(data_pkt, from_addr)

                print(f"Send DATA pkt in sendBuffer No.{self.sendWin_upper[Team]}")

                if self.sendWin_lower[Team] == self.sendWin_upper[Team]:
                    self.rdt_timer[Team] = time()

                self.sendWin_upper[Team] += 1

            # change the state to SEND
            self.peers[Team] = (*self.peers[Team][0:2], SEND)
            print("=================================")

        elif Type == DATA:
            # received a DATA pkt
            self.peers[Team] = (*self.peers[Team][0:2], RECV)
            h = self.downloading[Team]
            receiving_chunks[h] = receiving_chunks[h] + data

            # send back ACK

            if seq_num == self.expectedSeqNum[Team]:
                self.expectedSeqNum[Team] += 1
                ack_pkt = struct.pack(
                    SENDPKT,
                    socket.htons(MAGIC),
                    self.team,
                    ACK,
                    socket.htons(HEADER_LEN),
                    socket.htons(HEADER_LEN),
                    socket.htonl(0),  # Seq
                    socket.htonl(seq_num),  # Ack
                )
                # GET收到DATA，更新计时器
                self.GET_timer[Team] = time()

                sock.sendto(ack_pkt, from_addr)
                print(f"send ACK pkt: ack: {seq_num}")
                # see if finished
                print(
                    f"In process_inbound_udp:DATA: len(receiving_chunks[h]) = {len(receiving_chunks[h])}"
                )
                print("=================================")
                if len(receiving_chunks[self.downloading[Team]]) == CHUNK_DATA_SIZE:
                    # add to this peer's haschunk:
                    self.haschunks[self.downloading[Team]] = receiving_chunks[
                        self.downloading[Team]
                    ]
                    print(
                        f"Team = {Team}, self.downloading = {self.downloading[Team]}, self.demand = {self.demand}"
                    )

                    # delete the chunk from self.downloading
                    self.downloading.pop(Team)

                    # finished downloading this chunkdata!
                    # dump your received chunk to file in dict form using pickle
                    if len(self.downloading) == 0:
                        received = {
                            str(i, "ascii"): receiving_chunks[i]
                            for i in receiving_chunks
                        }
                        with open(self.ex_output_file, "wb") as wf:
                            pickle.dump(received, wf)
                        # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                        print(f"GOT {self.ex_output_file}")
                        print("=================================")

                    # change the state to DISCONNECTED
                    self.peers[Team] = (*self.peers[Team][0:2], DISCONNECTED)

                    # initial another handshake session
                    self.initial_download(sock, chunkf, outf)

                    # # The following things are just for illustration, you do not need to print out in your design.
                    # sha1 = hashlib.sha1()
                    # sha1.update(self.ex_received_chunk[self.ex_downloading_chunkhash])
                    # received_chunkhash_str = sha1.hexdigest()
                    # print(f"Expected chunkhash: {self.ex_downloading_chunkhash}")
                    # print(f"Received chunkhash: {received_chunkhash_str}")
                    # success = self.ex_downloading_chunkhash == received_chunkhash_str
                    # print(f"Successful received: {success}")
                    # if success:
                    #     print("Congrats! You have completed the example!")
                    # else:
                    #     print("Example fails. Please check the example files carefully.")
            else:
                ack_pkt = struct.pack(
                    SENDPKT,
                    socket.htons(MAGIC),
                    self.team,
                    ACK,
                    socket.htons(HEADER_LEN),
                    socket.htons(HEADER_LEN),
                    socket.htonl(0),
                    socket.htonl(self.expectedSeqNum[Team] - 1),
                )
                sock.sendto(ack_pkt, from_addr)
                print(f"【dupACK】ack No.{self.expectedSeqNum[Team] - 1}")
                print("=================================")

        elif Type == ACK:
            # TODO: 1. When get new ACK, congWin += 1.
            #       2. When get duplicated ACK, dupACKcount += 1.
            #       3. deal timeout
            #       4. deal dupACKcount
            #       5. deal congWin > ssthreshold

            # delete the packet in self.sentWindow
            # idx = next(
            #     i
            #     for i, v in enumerate(self.sentWindow)
            #     if v[1] + 1 == ack_num and v[2] == Team
            # )
            # self.sentWindow.pop(idx)

            # received an ACK pkt
            self.first_timeout[Team] = False
            if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending!!")
                print("=================================")
                # change the state to DISCONNECTED
                self.peers[Team] = (*self.peers[Team][0:2], DISCONNECTED)

            else:
                if ack_num == self.sendWin_lower[Team]:
                    self.sentWindow[Team].popleft()
                    self.sendWin_lower[Team] += 1

                    # congection control
                    if self.congState[Team] == SLOW_START:
                        self.congWinSize[Team] += 1
                    else:
                        self.congWinSize[Team] += 1 / self.congWinSize[Team]
                    if self.congWinSize[Team] >= self.ssthreshold[Team]:
                        self.congState[Team] = CONGECTION_AVOIDANCE

                    # send next data
                    self.rdt_timer[Team] = time()
                    while self.sendWin_upper[Team] <= 512 and self.sendWin_upper[Team] < self.sendWin_lower[Team] + self.congWinSize[Team]:
                        next_data = self.sendBuffer[Team][self.sendWin_upper[Team] - 1]
                        data_header = struct.pack(
                            SENDPKT,
                            socket.htons(MAGIC),
                            self.team,
                            DATA,
                            socket.htons(HEADER_LEN),
                            socket.htons(HEADER_LEN + len(next_data)),
                            socket.htonl(self.sendWin_upper[Team]),
                            socket.htonl(0),
                        )
                        next_data_pkt = data_header + next_data
                        self.sentWindow[Team].append(next_data_pkt)
                        sock.sendto(next_data_pkt, from_addr)
                        
                        print(f"send next data No.{self.sendWin_upper[Team]}")

                        self.sendWin_upper[Team] += 1
                    print("=================================")
                else:
                    self.dupACKcount[Team] += 1
                    if self.dupACKcount[Team] == 3:
                        self.dupACKcount[Team] = 1
                        retransmit = copy.deepcopy(self.sentWindow[Team])
                        # congection control
                        if self.congState[Team] == CONGECTION_AVOIDANCE:
                            self.ssthreshold[Team] = max(math.floor(self.congWinSize[Team] / 2) , 2)
                            self.congState[Team] = SLOW_START
                        else:
                            self.ssthreshold[Team] = max(math.floor(self.congWinSize[Team]),2)
                        self.congWinSize[Team] = 1
                        # fast retransmit
                        while retransmit:
                            # sock.sendto(peer.sentWindow[0][3], (dest[1], int(dest[2])))
                            retransmit_pkt = retransmit.popleft()
                            sock.sendto(retransmit_pkt, from_addr)
                            print(
                                f"【Retransmit: because of dupACK】send data No.{socket.ntohl(struct.unpack(RECVPKT, retransmit_pkt[:HEADER_LEN])[5])}"
                            )
                        self.rdt_timer[Team] = time()
                        print("=================================")
        elif Type == DENIED:
            # received an DENIED pkt
            pass
        else:
            # received an unidentifiable pkt
            pass

    def process_user_input(self, sock):
        global chunkf
        global outf
        command, chunkf, outf = input().split(" ")
        if command == "DOWNLOAD":
            self.initial_download(sock, chunkf, outf)
        else:
            pass

    def broadcast(self, sock):
        whohas_pkt = self.constr_whohas(self.demand)
        for p in self.peers:
            if p != self.team and self.peers[p][2] != RECV:
                sock.sendto(whohas_pkt, (self.peers[p][0], int(self.peers[p][1])))

    def get(self, sock):
        # randomly choose peers for desired chunks, send GET
        for d in self.demand:  # d: chunkhash
            for team in self.peerchunks:
                if self.peers[team][2] == HANDSHAKE and d in self.peerchunks[team]:
                    # change the state to RECV
                    self.peers[team] = (*self.peers[team][0:2], RECV)
                    self.downloading.update({team: d})
                    self.peerchunks[team].remove(d)
                    self.demand.remove(d)
                    get_pkt = self.constr_packet(GET, 0, 0, d)
                    # if team in self.sentWindow.keys():
                    #     self.sentWindow[team].append(get_pkt)
                    # else:
                    #     self.sentWindow[team] = [get_pkt]

                    # init receiver parameter
                    self.expectedSeqNum[team] = 1
                    self.GET_timer[team] = time()
                    sock.sendto(
                        get_pkt, (self.peers[team][0], int(self.peers[team][1]))
                    )
                    # self.sentWindow.append((time(), 0, p, get_pkt))
                    print(f"send GET to {team} for {d}")
                    print("=================================")
        # TODO: DISCONNECT OTHERS


def peer_run(configuration):
    addr = (configuration.ip, configuration.port)
    sock = simsocket.SimSocket(
        configuration.identity, addr, verbose=configuration.verbose
    )
    peer = Peer(configuration)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if sock in read_ready:
                    peer.process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    peer.process_user_input(sock)
            else:
                # No pkt nor input arrives during this period
                if len(peer.demand) > 0:
                    peer.broadcast(sock)
                    peer.get(sock)
                for team in peer.peers:
                    if peer.first_timeout[team] and (
                        (
                            team in peer.rdt_timer.keys()
                            and time() - peer.rdt_timer[team] > RDT_TIMEOUT
                        )
                        or (
                            team in peer.GET_timer.keys()
                            and time() - peer.GET_timer[team] > RDT_TIMEOUT
                        )
                    ):
                        print("second time out")
                        # change the state to DISCONNECTED
                        peer.peers[team] = (*peer.peers[team][0:2], DISCONNECTED)
                        peer.first_timeout[team] = False
                        # discard the incomplete data in receiving_chunks
                        if team in peer.GET_timer.keys():
                            peer.GET_timer.pop(team)
                            print(f"peer.downloading={peer.downloading}")
                            receiving_chunks[peer.downloading[team]] = bytes()
                            peer.expectedSeqNum.pop(team)
                        elif team in peer.rdt_timer.keys():
                            peer.rdt_timer.pop(team)
                            peer.sendBuffer.pop(team)
                            peer.sendWin_lower.pop(team)
                            peer.sendWin_upper.pop(team)
                            peer.sentWindow.pop(team)
                        # delete the downloading chunk from peer.downloading and add it back to peer.demand
                        peer.demand.append(peer.downloading.pop(team))
                        peer.initial_download(sock, chunkf, outf)

                    if (
                        peer.peers[team][2] == SEND
                        and peer.sentWindow[team]
                        and time() - peer.rdt_timer[team] > RDT_TIMEOUT
                    ):
                        print("first time out")
                        retransmit = copy.deepcopy(peer.sentWindow[team])
                        while retransmit:
                            # sock.sendto(peer.sentWindow[0][3], (dest[1], int(dest[2])))
                            retransmit_pkt = retransmit.popleft()
                            sock.sendto(
                                retransmit_pkt,
                                (peer.peers[team][0], int(peer.peers[team][1])),
                            )
                            print(
                                f"【Retransmit because of timeout】send data No.{socket.ntohl(struct.unpack(RECVPKT, retransmit_pkt[:HEADER_LEN])[5])}"
                            )
                        print("=================================")

                    if (
                        peer.peers[team][2] == RECV
                        and time() - peer.GET_timer[team] > RDT_TIMEOUT
                    ):
                        print("first time out")
                        peer.first_timeout[team] = True

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    # -p: Peer list file, it will be in the form "*.map" like nodes.map.
    # -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils.
    #   The loaded dictionary has the form: {chunkhash: chunkdata}
    # -m: The max number of peer that you can send chunk to concurrently.
    #   If more peers ask you for chunks, you should reply "DENIED"
    # -i: ID, it is the index in nodes.map
    # -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    # -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set,
    #   you should not change this time out. The timeout will be set when running test scripts.
    #   PLEASE do not change timeout if it set.

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", type=str, help="<peerfile>     The list of all peers", default="nodes.map"
    )
    parser.add_argument(
        "-c",
        type=str,
        help="<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}",
    )
    parser.add_argument(
        "-m", type=int, help="<maxconn>      Max # of concurrent sending"
    )
    parser.add_argument("-i", type=int, help="<identity>     Which peer # am I?")
    parser.add_argument("-v", type=int, help="verbose level", default=0)
    parser.add_argument("-t", type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
