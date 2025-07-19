'''
TCP HEADER FORMAT

 0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   pseudo header
   +--------+--------+--------+--------+
   |           Source Address          |
   +--------+--------+--------+--------+
   |         Destination Address       |
   +--------+--------+--------+--------+
   |  zero  |  PTCL  |    TCP Length   |
   +--------+--------+--------+--------+

'''
import struct
import socket

class TCPPacket:
    def __init__(self,
                 src_ip   : str,
                 src_port : int,
                 dst_ip   : str,
                 dst_port : int,
                 flags    : int=2 # flag is SYN by default
                 ):   
        
        self.src_ip   = src_ip
        self.src_port = src_port
        self.dst_ip   = dst_ip
        self.dst_port = dst_port
        self.flags    = flags

    def build(self):
        tcp_header = struct.pack(
            '!HHIIBBHHH', 
            self.src_port,  # 2B-> H
            self.dst_port,  # 2B-> H
            0,              # seq num   4B-> I 
            0,              # ack num   4B-> I
            5<<4,           # data offset*4  1B-> B
            self.flags,     #                1B-> I
            4096,           # window size    2B-> H
            0,              # checksum       2B-> H
            0               # urgent pointer 2B-> H
        )
       
        pseudo_header = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(self.src_ip), # 4B-> 4s
            socket.inet_aton(self.dst_ip), # 4B-> 4s
            0,                             # 1B-> B 
            socket.IPPROTO_TCP,            # 1B-> B 
            len(tcp_header)                # 2B-> H
        ) 
        
        check_sum = checkSum(pseudo_header + tcp_header)
        check_sum = struct.pack('H' , check_sum) 

        packet = tcp_header[:16] + check_sum + tcp_header[18:]
        
        return packet

def checkSum(data):

    if len(data)%2 != 0:
        data += b'\x00'  # pad if odd len
    
    check_sum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8 ) + data[i+1]
        check_sum += word

        check_sum = (check_sum & 0xffff) + (check_sum >> 16)

    return ~check_sum & 0xffff
 
    



