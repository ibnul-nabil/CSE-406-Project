import tcp_scratch as ts
import ip_scratch as ips
import struct
import socket

if __name__ == "__main__":

    src_ip = "192.168.10.56"
    src_port = 20
    #dst_ip = "192.168.10.56"
    dst_ip = "0.0.0.0"
    dst_port =  8080

    #msg = input("Enter your msg: ")
    msg = "my name is nabil."
    msg_bytes = msg.encode()[:64]
    msg_bytes = msg_bytes.ljust(64, b'\x00')  # Pad to 32 bytes
    data = struct.pack('!64B', *msg_bytes)

    segment = ts.TCPPacket(src_ip, src_port, dst_ip, dst_port).build()
    packet = ips.IPPacket(src_ip, dst_ip).build() + segment + data


    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(packet, (dst_ip, 0)) 

