import socket
import struct
import sys
import tcp_scratch as ts
import ip_scratch as ips

class TCPPacketCapture:
    def __init__(self, port=8082):
        self.port = port
        self.socket = None

        self.dst_adr=0x0000 # this stores dst of request. which is src_ip of server
        self.dst_port = '0.0.0.0'
        self.src_port = '0.0,0,0/////'
        
    def parse_tcp_header(self, packet):
        """Parse TCP header from raw packet"""
        # IP header is typically 20 bytes, TCP header starts after that
        ip_header = packet[0:20]
        
        # Extract IP header info
        ip_header_unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = ip_header_unpacked[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        
        # Extract source and dest IP
        s_addr = socket.inet_ntoa(ip_header_unpacked[8])
        d_addr = socket.inet_ntoa(ip_header_unpacked[9])
        self.dst_adr = d_addr
        
        # TCP header starts after IP header
        tcp_header = packet[iph_length:iph_length+20]
        tcp_header_unpacked = struct.unpack('!HHLLBBHHH', tcp_header)
        
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
        """Start capturing TCP packets"""
        try:
            # Create raw socket (requires root/admin privileges)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            
            print(f"Raw socket server listening for TCP packets on port {self.port}")
            print("Note: This requires root/administrator privileges")
            print("Press Ctrl+C to stop")
            
            while True:
                # Receive packet
                packet, addr = self.socket.recvfrom(65565)
                
                try:
                    tcp_info = self.parse_tcp_header(packet)
                    
                    # Filter for our target port
                    if tcp_info['dst_port'] == self.port:
                        print(f"\n--- Packet to port {self.port} ---")
                        print(f"From: {tcp_info['src_ip']}:{tcp_info['src_port']}")
                        print(f"To: {tcp_info['dst_ip']}:{tcp_info['dst_port']}")
                        print(f"Sequence: {tcp_info['seq']}")
                        print(f"Flags: SYN={tcp_info['syn']}, ACK={tcp_info['ack_flag']}, "
                              f"FIN={tcp_info['fin']}, RST={tcp_info['rst']}")
                        
                        if tcp_info['syn'] and not tcp_info['ack_flag']:
                            print("*** SYN packet detected! ***")
                            # Here you can add your custom response logic
                            self.handle_syn_packet(tcp_info)
                            
                except Exception as e:
                    print(f"Error parsing packet: {e}")
                    continue
                    
        except PermissionError:
            print("Error: Raw sockets require root/administrator privileges")
            print("Run with: sudo python3 script.py")
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def handle_syn_packet(self, tcp_info):
        """Handle detected SYN packet"""
        print(f"Processing SYN from {tcp_info['src_ip']}:{tcp_info['src_port']}")
        # Add your custom logic here
        # You could craft a response packet, log to database, etc.
        segment = ts.TCPPacket(self.dst_adr, self.dst_port, tcp_info['src_ip'], tcp_info['src_port'] , "helo").build()
        packet = ips.IPPacket(self.dst_adr, tcp_info['src_ip']).build() + segment
        print('Making response')
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(packet, (self.src_port, 0)) 
        print('Sent reply to user pc')

if __name__ == "__main__":
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 8082
    
    print("Warning: This script captures raw TCP packets and requires root privileges")
    print("It will show SYN packets sent to the specified port")
    
    capture = TCPPacketCapture(port)
    capture.start_capture()