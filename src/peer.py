import pickle
import argparse

# import hashlib
import socket
import struct
import select
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from util import bt_utils
from util import simsocket

# configurations
BUF_SIZE = 1400
HEADER_LEN = struct.calcsize("HBBHHII")
MAX_PAYLOAD = 1024
CHUNK_DATA_SIZE = 512 * 1024
MAGIC = 52305
HASHLEN = 40
SENDPKT = ">HBBHHII"
RECVPKT = ">HBBHHII"

# packet types
WHOHAS = 0
IHAVE = 1
GET = 2
DATA = 3
ACK = 4
DENIED = 5

# states of other peers
DISCONNECTED = -1
HANDSHAKE = 0
SEND = 1
RECV = 2


receiving_chunks = {}
# indicate whether the user have instructed to download
download_instruction = False


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
        # {team number : checksum}, records the data that is being sent to peers
        self.sending = {}
        # [(team number, ip, port, state)], records the address of other peers
        self.peers = [(n, i, p, DISCONNECTED) for n, i, p in configuration.peers]
        # {checksum(str) : data}, records the data that this peer already has
        self.haschunks = {
            bytes(x, "ascii"): config.haschunks[x] for x in config.haschunks
        }
        # {team number : checksum}, record the chunks of the peers that have initiated handshake
        self.peerchunks = {}
        self.team = configuration.identity
        self.maxconn = configuration.max_conn

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
        """
        self.ex_output_file = outputfile
        download_hash = bytes()
        with open(chunkfile, "r", encoding="utf-8") as cf:
            lines = cf.readlines()
            for line in lines:
                _, datahash_str = line.strip().split(" ")
                datahash_str = bytes(datahash_str, encoding="ascii")
                receiving_chunks.update({datahash_str: bytes()})
                if (
                    datahash_str not in self.demand
                    and datahash_str not in self.haschunks
                ):
                    self.demand.append(datahash_str)

            datahash = b""
            for s in self.demand:
                datahash += s
            download_hash = download_hash + datahash

        self.broadcast(sock)

    def process_inbound_udp(self, sock):
        # Receive pkt
        pkt, from_addr = sock.recvfrom(BUF_SIZE)
        _, Team, Type, hlen, plen, Seq, Ack = struct.unpack(RECVPKT, pkt[:HEADER_LEN])
        hlen = socket.ntohs(hlen)
        plen = socket.ntohs(plen)
        dlen = plen - hlen
        data = pkt[hlen:]
        seq_num = socket.ntohl(Seq)
        ack_num = socket.ntohl(Ack)
        print(f"received pkt: {Team} {Type} {hlen} {dlen} {seq_num} {ack_num}")
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
            if len(self.sending) < MAX_PAYLOAD and ihave_pkt_list:
                # send back IHAVE pkt
                ihave_pkt = self.constr_ihave(ihave_pkt_list)
                sock.sendto(ihave_pkt, from_addr)

                # change the state to HANDSHAKE
                idx = next(i for i, v in enumerate(self.peers) if v[0] == str(Team))
                self.peers[idx] = (*self.peers[idx][0:3], HANDSHAKE)
            elif len(self.sending) >= self.maxconn and ihave_pkt_list:
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

            # change the state to HANDSHAKE
            idx = next(i for i, v in enumerate(self.peers) if v[0] == str(Team))
            self.peers[idx] = (*self.peers[idx][0:3], HANDSHAKE)
        elif Type == GET:
            print(f"receive get from peer {Team}")
            # received a GET pkt
            send_chunk_checksum = data[:HASHLEN]
            print(f"send_chunk_checksum = {send_chunk_checksum}")
            self.sending.update({Team: send_chunk_checksum})
            chunk_data = self.haschunks[self.sending[Team]][:MAX_PAYLOAD]

            # send back DATA
            data_header = struct.pack(
                SENDPKT,
                socket.htons(MAGIC),
                self.team,
                DATA,
                socket.htons(HEADER_LEN),
                socket.htons(HEADER_LEN + len(chunk_data)),
                socket.htonl(1),
                0,
            )
            sock.sendto(data_header + chunk_data, from_addr)

            # change the state to SEND
            idx = next(i for i, v in enumerate(self.peers) if v[0] == str(Team))
            self.peers[idx] = (*self.peers[idx][0:3], SEND)
        elif Type == DATA:
            # change the state to RECV
            idx = next(i for i, v in enumerate(self.peers) if v[0] == str(Team))
            self.peers[idx] = (*self.peers[idx][0:3], RECV)
            # received a DATA pkt
            h = self.downloading[Team]
            receiving_chunks[h] = receiving_chunks[h] + data

            # send back ACK
            ack_pkt = struct.pack(
                SENDPKT,
                socket.htons(MAGIC),
                self.team,
                ACK,
                socket.htons(HEADER_LEN),
                socket.htons(HEADER_LEN),
                socket.htonl(ack_num),
                socket.htonl(seq_num + 1),
            )
            sock.sendto(ack_pkt, from_addr)

            # see if finished
            print(
                f"In process_inbound_udp:DATA: len(receiving_chunks[h]) = {len(receiving_chunks[h])}"
            )
            if len(receiving_chunks[self.downloading[Team]]) == CHUNK_DATA_SIZE:
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle
                if len(self.demand) == 0:
                    with open(self.ex_output_file, "wb") as wf:
                        pickle.dump(receiving_chunks, wf)
                    # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                    print(f"GOT {self.ex_output_file}")

                # add to this peer's haschunk:
                self.haschunks[self.downloading[Team]] = receiving_chunks[
                    self.downloading[Team]
                ]
                if self.downloading[Team] in self.demand:
                    self.demand.remove(self.downloading[Team])

                # change the state to DISCONNECTED
                idx = next(i for i, v in enumerate(self.peers) if v[0] == str(Team))
                self.peers[idx] = (*self.peers[idx][0:3], DISCONNECTED)

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
        elif Type == ACK:
            # received an ACK pkt
            if (ack_num - 1) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending {self.sending[Team]}")

                # change the state to DISCONNECTED
                idx = next(i for i, v in enumerate(self.peers) if v[0] == str(Team))
                self.peers[idx] = (*self.peers[idx][0:3], DISCONNECTED)
            else:
                left = (ack_num - 1) * MAX_PAYLOAD
                right = min((ack_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = self.haschunks[self.sending[Team]][left:right]
                # send next data
                data_header = struct.pack(
                    SENDPKT,
                    socket.htons(MAGIC),
                    self.team,
                    DATA,
                    socket.htons(HEADER_LEN),
                    socket.htons(HEADER_LEN + len(next_data)),
                    socket.htonl(ack_num),
                    socket.htonl(seq_num),
                )
                sock.sendto(data_header + next_data, from_addr)
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
            globals()["download_instruction"] = True
            self.initial_download(sock, chunkf, outf)
        else:
            pass

    def broadcast(self, sock):
        whohas_pkt = self.constr_whohas(self.demand)
        for p in self.peers:
            if int(p[0]) != self.team:
                sock.sendto(whohas_pkt, (p[1], int(p[2])))

    def get(self, sock):
        # randomly choose peers for desired chunks, send GET
        for d in self.demand:
            for p in self.peerchunks:
                peer_idx = next(i for i, v in enumerate(self.peers) if v[0] == str(p))
                if self.peers[peer_idx][3] == HANDSHAKE and d in self.peerchunks[p]:
                    # change the state to HANDSHAKE
                    self.peers[peer_idx] = (*self.peers[peer_idx][0:3], RECV)

                    self.downloading.update({p: d})
                    self.peerchunks[p].remove(d)
                    self.demand.remove(d)
                    get_pkt = self.constr_packet(GET, 0, 1, d)
                    dest = next(x for x in self.peers if x[0] == str(p))
                    sock.sendto(get_pkt, (dest[1], int(dest[2])))
                    print(f"send get to {p} for {d}")


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
                if download_instruction:
                    peer.get(sock)
                pass
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
