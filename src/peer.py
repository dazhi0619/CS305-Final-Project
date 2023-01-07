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
CHUNK_DATA_SIZE = 512 * 1024
MAX_PAYLOAD = 1024
MAGIC = 52305

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
        # {checksum : data}, records the data that this peer already has
        self.haschunks = config.haschunks
        # {team number : checksum}, record the chunks of the peers that have initiated handshake
        self.peerchunks = {}
        self.team = configuration.identity
        self.maxconn = configuration.max_conn

    def constr_packet(self, packet_type, seq, ack, data: bytes):
        # |2byte magic|1byte type |1byte team|
        # |2byte  header len  |2byte pkt len |
        # |      4byte  seq                  |
        # |      4byte  ack                  |
        header = struct.pack(
            "HBBHHII",
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
        byte = b""
        for d in download_hash:
            byte += bytes(d, "ascii")
        return self.constr_packet(WHOHAS, 0, 0, byte)

    def constr_ihave(self, pkt_list):
        return self.constr_packet(IHAVE, 0, 0, bytes(pkt_list))

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
                receiving_chunks.update({datahash_str: bytes()})
                self.demand.append(datahash_str)

            # hex_str to bytes
            datahash = b""
            for s in self.demand:
                datahash += bytes.fromhex(s)
            download_hash = download_hash + datahash

        self.broadcast(sock)

    def process_inbound_udp(self, sock):
        # Receive pkt
        pkt, from_addr = sock.recvfrom(BUF_SIZE)
        _, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
        dlen = plen - hlen
        data = pkt[hlen:]
        if Type == WHOHAS:
            # received an WHOHAS pkt
            # see what chunk the sender has
            whohas_chunk_hash_list = []
            i = 0
            while i < dlen:
                whohas_chunk_hash = data[i : i + 20]
                i += 20
                # bytes to hex_str
                chunkhash_str = bytes.hex(whohas_chunk_hash)
                whohas_chunk_hash_list.append(chunkhash_str)

            for s in whohas_chunk_hash_list:
                print(f"whohas: {s}")
            print(f"has: {list(config.haschunks.keys())}")
            ihave_pkt_list = [
                h for h in whohas_chunk_hash_list if h in config.haschunks
            ]
            if len(self.sending) < MAX_PAYLOAD and ihave_pkt_list:
                # send back IHAVE pkt
                ihave_pkt = self.constr_ihave(ihave_pkt_list)
                sock.sendto(ihave_pkt, from_addr)

                # change the state to HANDSHAKE
                idx = next(i for i, v in self.peers if v[0] == Team)
                self.peers[idx] = (self.peers[idx][0:2], HANDSHAKE)
            elif len(self.sending) >= self.maxconn and ihave_pkt_list:
                denied_header = self.constr_denied()
                sock.sendto(denied_header, from_addr)
        elif Type == 1:
            # received an IHAVE pkt
            # see what chunk the sender has
            get_chunk_hash_list = []
            i = 0
            while i < dlen:
                get_chunk_hash = data[i : i + 20]
                i += 20
                chunkhash_str = bytes.hex(get_chunk_hash)
                get_chunk_hash_list.append(chunkhash_str)
            self.peerchunks.update({Team: get_chunk_hash_list})

            # change the state to HANDSHAKE
            idx = next(i for i, v in self.peers if v[0] == Team)
            self.peers[idx] = (self.peers[idx][0:2], HANDSHAKE)
        elif Type == 2:
            print(f"receive get from peer {Team}")
            # received a GET pkt
            send_chunk_checksum = data[hlen : hlen + 20]
            self.sending.update({Team: send_chunk_checksum})
            chunk_data = self.haschunks[self.sending[Team]][:MAX_PAYLOAD]

            # send back DATA
            data_header = struct.pack(
                "HBBHHII",
                socket.htons(MAGIC),
                self.team,
                DATA,
                socket.htons(HEADER_LEN),
                socket.htons(HEADER_LEN),
                socket.htonl(1),
                0,
            )
            sock.sendto(data_header + chunk_data, from_addr)

            # change the state to SEND
            idx = next(i for i, v in self.peers if v[0] == Team)
            self.peers[idx] = (self.peers[idx][0:2], SEND)
        elif Type == 3:
            # change the state to RECV
            idx = next(i for i, v in self.peers if v[0] == Team)
            self.peers[idx] = (self.peers[idx][0:2], RECV)
            # received a DATA pkt
            receiving_chunks[self.downloading[Team]] += data

            # send back ACK
            ack_pkt = struct.pack(
                "HBBHHII",
                socket.htons(MAGIC),
                self.team,
                ACK,
                socket.htons(HEADER_LEN),
                socket.htons(HEADER_LEN),
                0,
                Seq,
            )
            sock.sendto(ack_pkt, from_addr)

            # see if finished
            if len(receiving_chunks[self.downloading[Team]]) == CHUNK_DATA_SIZE:
                # finished downloading this chunkdata!
                # dump your received chunk to file in dict form using pickle
                with open(self.ex_output_file, "wb") as wf:
                    pickle.dump(receiving_chunks, wf)

                # add to this peer's haschunk:
                self.haschunks[self.downloading[Team]] = receiving_chunks[
                    self.downloading[Team]
                ]

                # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                print(f"GOT {self.ex_output_file}")

                # change the state to DISCONNECTED
                idx = next(i for i, v in self.peers if v[0] == Team)
                self.peers[idx] = (self.peers[idx][0:2], DISCONNECTED)

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
        elif Type == 4:
            # received an ACK pkt
            ack_num = socket.ntohl(Ack)
            if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
                # finished
                print(f"finished sending {self.sending[Team]}")

                # change the state to DISCONNECTED
                idx = next(i for i, v in self.peers if v[0] == Team)
                self.peers[idx] = (self.peers[idx][0:2], DISCONNECTED)
            else:
                left = (ack_num) * MAX_PAYLOAD
                right = min((ack_num + 1) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                next_data = self.haschunks[self.sending[Team]][left:right]
                # send next data
                data_header = struct.pack(
                    "HBBHHII",
                    socket.htons(MAGIC),
                    35,
                    3,
                    socket.htons(HEADER_LEN),
                    socket.htons(HEADER_LEN + len(next_data)),
                    socket.htonl(ack_num + 1),
                    0,
                )
                sock.sendto(data_header + next_data, from_addr)
        elif Type == 5:
            # received an DENIED pkt
            pass
        else:
            # received an unidentifiable pkt
            pass

    def process_user_input(self, sock):
        command, chunkf, outf = input().split(" ")
        if command == "DOWNLOAD":
            self.initial_download(sock, chunkf, outf)
            self.get(sock)
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
            print(f"{d} is in self.demand")
            for p in self.peerchunks:
                print(f"{p} is in self.peerchunks")
                if d in self.peerchunks[p]:
                    # change the state to HANDSHAKE
                    idx = next(i for i, v in self.peers if v[0] == p)
                    self.peers[idx] = (self.peers[idx][0:2], HANDSHAKE)

                    self.downloading.update({p: d})
                    self.peerchunks[p].remove(d)
                    self.demand.remove(d)
                    get_pkt = self.constr_packet(GET, 0, 0, d)
                    dest = next(x for x in self.peers if x[0] == p)
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
                pass
                # peer.broadcast(sock)
                # peer.get(sock)
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
