import tcp_scratch as ts
import ip_scratch as ips
import socket

if __name__ == "__main__":

    src_ip = "192.168.0.110"
    src_port = 56356
    # dst_ip = "20.40.57.81"
    dst_ip = "0.0.0.0"
    dst_port = 8082

    segment = ts.TCPPacket(src_ip, src_port, dst_ip, dst_port , "helo").build()
    packet = ips.IPPacket(src_ip, dst_ip).build() + segment



    # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # s.sendto(packet.build(), (dst_ip, 0)) 

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    
    s.sendto(packet, (dst_ip, 0)) 

