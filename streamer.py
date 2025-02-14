# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from concurrent.futures import ThreadPoolExecutor
import time
import hashlib
from threading import Lock

#sent data = 0
#acknowledged data = 1
#fin data = 2


class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.seq_num=0
        self.recv_buffer={}
        self.expected_seq=0
        self.ack_received={}
        self.closed=False
        self.fin_received=False

        self.executor=ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)
        self.lock=Lock()


    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # Your code goes here!  The code below should be changed!
        header_size=struct.calcsize("!B")+struct.calcsize("!I")#+struct.calcsize("!16s")
        #^type+seq_num+hash = 1+4+16=21
        #header_size=struct.calcsize("!BI16s")
        chunk_size=1472-header_size-16
        total_size=len(data_bytes)
        offset=0

        while offset<total_size:
            chunk=data_bytes[offset: offset+chunk_size]
            #pr_hash=hashlib.md5(chunk).digest()
            #print(f"hash: {pr_hash} and length", len(pr_hash))
            #hash=3
            header = struct.pack("!BI", 0, self.seq_num)
            #print(f"new_header formed: {header}")
            packet=header+chunk
            hash = hashlib.md5(packet).digest()
            final_packet=hash+packet
            #print(f"seqnum: {self.seq_num}, packet header: {header}, sent: {packet}")
            self.socket.sendto(final_packet, (self.dst_ip, self.dst_port))
            #print("Sent!")
            start_time=time.time()
            while True:
                time.sleep(0.01)
                with self.lock:
                    if self.ack_received.get(self.seq_num, False):
                        break #ack was recevied - dont have to wait
                    if time.time()-start_time>0.25:#timeout
                        self.socket.sendto(final_packet, (self.dst_ip, self.dst_port))
                        start_time=time.time()

            offset+=chunk_size
            with self.lock:
                self.seq_num+=1
            #print(f"new seq_num: {self.seq_num}, offset: {offset}\n")
        # for now I'm just sending the raw application-level data in one UDP payload
        #self.socket.sendto(data_bytes, (self.dst_ip, self.dst_port))

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        # your code goes here!  The code below should be changed!
        #ordered_data=bytearray()
        while True:
            with self.lock:
                if self.expected_seq in self.recv_buffer:
                    payload=self.recv_buffer.pop(self.expected_seq)
                    self.expected_seq +=1
                    print(f"returning payload: {payload}")
                    return payload
                elif self.close:
                    return b''
                else:
                    continue #wait until expected packet
            time.sleep(0.01)

    def listener(self):
        while not self.closed:
            try:
    
                header_size=struct.calcsize("!B")+struct.calcsize("!I")
                hash_size=struct.calcsize("!BI16s")
                #^type+seq_num+hash
                data, addr=self.socket.recvfrom()
                
                if hashlib.md5(data[hash_size:]).digest()!=data[:hash_size]:
                    continue #corrupt
                
                type, seq_num=struct.unpack("!BI", data[hash_size:header_size+hash_size])
                payload=data[header_size+hash_size:]

                #print(f"type: {type}, seq_num: {seq_num}, hash: {hash}")
                with self.lock:
                    #computed_hash=hashlib.md5(payload).digest()
                    #if computed_hash!=recv_hash:
                     #continue #corrupted packet was detected
                    if type==1:#packet was ACK
                        self.ack_received[seq_num]=True
                    elif type==0: #packet was data not ack
                        self.recv_buffer[seq_num]=payload
                        ack_header=struct.pack("!BI", 1, seq_num)
                        self.socket.sendto(ack_header, (self.dst_ip, self.dst_port))
                    elif type==2: #Fin packet
                    #print("got fin packet")
                        self.fin_received=True
                        fin_ack=struct.pack("!BI", 1, seq_num)
                        self.socket.sendto(fin_ack, (self.dst_ip, self.dst_port))
                    #^send ack of the fin pack
            except Exception as e:
                print("listener died!")
                print(e)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # your code goes here, especially after you add ACKs and retransmissions.
        #print("Closing connection...")
        fin_packet=struct.pack("!BI", 2, self.seq_num)
        self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
        #print("Sent FIN packet")

        start_time=time.time() #wait for ack of fin
        while True:
            time.sleep(0.01)
            with self.lock:
                if self.ack_received.get(self.seq_num, False):
                    break #Fin ack received
                if time.time()-start_time>0.25:
                    self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
                    start_time=time.time()
            
        #print("FIN ACK received")
        while True:
            with self.lock:
                if self.fin_received:
                    break
            time.sleep(0.01)

        #print("Received FIN from the other side")

        #wait 2 seconds
        time.sleep(2) 
        with self.lock:
           self.closed=True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)
        #print("Connection closed")
        pass
