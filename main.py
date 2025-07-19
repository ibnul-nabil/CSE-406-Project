import tcp_scratch as ts
import socket

if __name__ == "__main__":

    src_ip = "192.168.10.151"
    src_port = 20
    dst_ip = "192.168.10.55"
    dst_port = 666

    packet = ts.TCPPacket(src_ip, src_port, dst_ip, dst_port , "helo")

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    s.sendto(packet.build(), (dst_ip, 0)) 


