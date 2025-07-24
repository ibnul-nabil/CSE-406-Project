import socket
import struct
import sys
import time
import threading
# import tcp_scratch as ts
# import ip_scratch as ips

defend = True

#store requests for blocking attacker ip addresses
ip_log = {}
ip_blockList=[]

def log_src_ip(ip):
    if ip in ip_log:
        ip_log[ip]+=1
    else:
        ip_log[ip]=1

def handle_connection(s, src_adr, dst_adr='', src_port=0, dst_port=0):
    if defend:
        s.sendto("mock SYN-ACK packet with Cookie".encode('utf-8'), (src_adr, 0))
        # Simulate a less coslty action for server
        time.sleep(0.1)
    else:
        # Costly server actions
        s.sendto("mock SYN-ACK packet".encode('utf-8'), (src_adr, 0))
        time.sleep(1)
        s.sendto("mock SYN-ACK packet".encode('utf-8'), (src_adr, 0))
        time.sleep(2)
        s.sendto("mock SYN-ACK packet".encode('utf-8'), (src_adr, 0))
        time.sleep(4)

def monitor_ip():
    while True:
        time.sleep(2)  # check every 2 seconds for DoS
        for ip in list(ip_log):  
            if ip_log[ip] > 50:
                print(f"Blocking '{ip}' due to possible DoS")
                ip_log[ip] = 0
                ip_blockList.append(ip)
            ip_log[ip]=0

class TCPPacketCapture:
    def __init__(self, port):
        self.port = port
        self.socket = None

        self.dst_adr=0x0000 # this stores dst of request. which is src_ip of server
        self.dst_port=0

        self.src_port=0
        self.src_adr=0x0000

    def parse_tcp_header(self, packet):
        
        # IP header is 20 bytes, TCP header starts after that
        ip_header = packet[0:20]
        
        # Extract IP header info
        try:
            ip_header_unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header)
        except Exception as e:
            print(f"Error unpacking IP header: {e}")
        version_ihl = ip_header_unpacked[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        #print(f"IP Header Length: {iph_length} bytes")
        
        # Extract source and dest IP
        s_addr = socket.inet_ntoa(ip_header_unpacked[8])
        d_addr = socket.inet_ntoa(ip_header_unpacked[9])
        self.dst_adr = d_addr
        self.src_adr = s_addr
        
        tcp_start = iph_length
        # print(f"Packet length: {len(packet)} bytes")
        # print(f"TCP starts at: {tcp_start}")

        tcp_header = packet[iph_length:iph_length+20]
        try:
            tcp_header_unpacked = struct.unpack('!HHLLBBHHH', tcp_header)
        except Exception as e:
            print(f"Error unpacking TCP header: {e}")
            return None

        source_port = tcp_header_unpacked[0]
        dest_port = tcp_header_unpacked[1]
        seq_num = tcp_header_unpacked[2]
        ack_num = tcp_header_unpacked[3]
        doff_reserved = tcp_header_unpacked[4]
        flags = tcp_header_unpacked[5]

        self.dst_port = dest_port
        self.src_port = source_port
        
        
        # Extract flags
        syn_flag = bool(flags & 0x02)
        ack_flag = bool(flags & 0x10)
        fin_flag = bool(flags & 0x01)
        rst_flag = bool(flags & 0x04)
        
        return {
            'src_ip': s_addr,
            'dst_ip': d_addr,
            'src_port': source_port,
            'dst_port': dest_port,
            'seq': seq_num,
            'ack': ack_num,
            'syn': syn_flag,
            'ack_flag': ack_flag,
            'fin': fin_flag,
            'rst': rst_flag
        }
    
    def start_capture(self):
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            
            print(f"Raw socket server listening for TCP packets on port {self.port}")
            print("Press Ctrl+C to stop")
            
            while True:
                # Receive packet max size 65565 bytes
                packet, addr = self.socket.recvfrom(65565)
                
                try:
                    tcp_info = self.parse_tcp_header(packet)

                    ip_src_chk  = tcp_info['src_ip']
                    if defend:
                        if ip_src_chk in ip_blockList:
                            print(f"IP: {ip_src_chk} is blocked")
                            continue
                        log_src_ip(ip_src_chk)

                    # Filter for target port only
                    if tcp_info['dst_port'] == self.port:
                        print(f"\n--- Packet to port {self.port} ---")
                        print(f"From: {tcp_info['src_ip']}:{tcp_info['src_port']}")
                        print(f"To: {tcp_info['dst_ip']}:{tcp_info['dst_port']}")
                        print(f"Sequence: {tcp_info['seq']}")
                        print(f"Flags: SYN={tcp_info['syn']}, ACK={tcp_info['ack_flag']}, "
                              f"FIN={tcp_info['fin']}, RST={tcp_info['rst']}")
                        
                        if tcp_info['syn'] and not tcp_info['ack_flag']:
                            print("---SYN packet detected!---")
                            self.handle_syn_packet(tcp_info)
                            
                except Exception as e:
                    print(f"Error parsing packet: {e}")
                    continue
                    
        except PermissionError:
            print("Error: Raw sockets require root privileges")
            print("Run: sudo python3 server.py")
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def handle_syn_packet(self, tcp_info):
        
        print(f"Processing SYN from {tcp_info['src_ip']}:{tcp_info['src_port']}")

        try:
            # print(f"trying to send from {self.dst_port} to {tcp_info['src_port']}")
            #segment = ts.TCPPacket(self.dst_adr, self.dst_port, tcp_info['src_ip'], tcp_info['src_port']).build()
            print(f"trying to send from {self.dst_adr} to {tcp_info['src_ip']}")
            #packet = ips.IPPacket(self.dst_adr, tcp_info['src_ip']).build() + segment
            #print('Completed Making response')
        except Exception as e:
            print(f"Error creating response packets: {e}")

        try:
            # self.socket.sendto(packet, (self.src_adr, 0))
            # self.socket.sendto("mock SYN-ACK packet".encode('utf-8'), (self.src_adr, 0))
            t = threading.Thread(target=handle_connection, daemon=True) 
            t.start

        except Exception as e:
            print(f"Error sending: {e}")

if __name__ == "__main__":

    port = 8081
    print("Starting tcp packet capture")

    if defend:  
        monitor_thread = threading.Thread(target=monitor_ip, daemon=True) #daemon: stop thread with program
        monitor_thread.start() # For checking logs and blocking DoS attacker IP
    
    capture = TCPPacketCapture(port)
    capture.start_capture()