'''
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Data                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

'''

import struct
import socket


def calculate_checksum(header: bytes) -> int:

    if len(header) % 2 == 1:
        header += b'\x00'  # pad if odd len

    total = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i+1]
        total += word

    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)

    checksum = ~total & 0xFFFF
    return checksum



class IPPacket:

    total_length = 104

    def __init__(self,
                 src_ip : str,
                 dst_ip : str
                ):
        
        self.src_ip = src_ip
        self.dst_ip = dst_ip

        self.protocol = 6
    
    def build(self):

        ip_header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,                          # Version (4)
                0x00,                          # Type of Service
                IPPacket.total_length,         
                0xabcd,                        # Identification
                0x0000,                        # Flags + Fragment Offset
                0xff,                          # TTL
                self.protocol,                 # Protocol (e.g., TCP = 6)
                0,                              # Header Checksum (precomputed or 0 if computing later)
                socket.inet_aton(self.src_ip),  
                socket.inet_aton(self.dst_ip) 
            )
        
        # Calculate checksum
        checksum = calculate_checksum(ip_header)
        
        ip_header = struct.pack(
                '!BBHHHBBH4s4s',
                0x45,                          # Version (4)
                0x00,                          # Type of Service
                IPPacket.total_length,         
                0xabcd,                        # Identification
                0x0000,                        # Flags + Fragment Offset
                0xff,                          # TTL
                self.protocol,                 # Protocol (e.g., TCP = 6)
                checksum,                      # Header Checksum
                socket.inet_aton(self.src_ip),  
                socket.inet_aton(self.dst_ip) 
            )    
        
        return ip_header
        