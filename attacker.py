import tcp_scratch as ts
import ip_scratch as ips
import struct
import socket
import time

if __name__ == "__main__":

    src_ip = "192.168.0.102" 
    # dont use multiple single digits
    src_port = 3001
    # dst_ip = "20.40.57.81"
    dst_ip = "0.0.0.0"
    # dst_ip = "172.174.246.178"
    # dst_ip="192.168.0.103"
    dst_port = 8081

    # msg = input("Enter your msg: ")
    msg = "hello"
    msg_bytes = msg.encode()[:64]
    msg_bytes = msg_bytes.ljust(64, b'\x00')  # Pad to 64 bytes
    data = struct.pack('!64B', *msg_bytes)

    segment = ts.TCPPacket(src_ip, src_port, dst_ip, dst_port).build()
    # print(f"Segment length: {len(segment)} bytes")
    packet = ips.IPPacket(src_ip, dst_ip).build() + segment + data
    # print(f"Packet length: {len(packet)} bytes")


    # Raw socket for crafted packet
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    #while(True):
    s.sendto(packet, (dst_ip, 0))
        #time.sleep(0.05)  # Pause for 50ms

