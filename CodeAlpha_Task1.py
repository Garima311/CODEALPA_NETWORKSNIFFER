

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
import datetime
import json

class PacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        
    def analyze_packet(self, packet):
        """Analyze and display packet information"""
        self.packet_count += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n{'='*80}")
        print(f"Packet #{self.packet_count} - {timestamp}")
        print(f"{'='*80}")
        
        
        if packet.haslayer(Ether):
            eth = packet[Ether]
            print(f"[ETHERNET] Source MAC: {eth.src} | Dest MAC: {eth.dst}")
            print(f"[ETHERNET] Type: {hex(eth.type)}")
        
        
        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"[IP] Version: {ip.version} | Header Length: {ip.ihl*4} bytes")
            print(f"[IP] Source: {ip.src} | Destination: {ip.dst}")
            print(f"[IP] Protocol: {ip.proto} | TTL: {ip.ttl} | Length: {ip.len}")
            
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                self.protocol_stats['TCP'] += 1
                print(f"[TCP] Source Port: {tcp.sport} | Dest Port: {tcp.dport}")
                print(f"[TCP] Sequence: {tcp.seq} | Acknowledgment: {tcp.ack}")
                print(f"[TCP] Flags: {tcp.flags} | Window: {tcp.window}")
                
            
                common_ports = {
                    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                    23: 'Telnet', 25: 'SMTP', 53: 'DNS', 110: 'POP3'
                }
                
                if tcp.dport in common_ports:
                    print(f"[APPLICATION] Likely Protocol: {common_ports[tcp.dport]}")
                elif tcp.sport in common_ports:
                    print(f"[APPLICATION] Likely Protocol: {common_ports[tcp.sport]}")
                
                
                if tcp.payload:
                    payload = bytes(tcp.payload)
                    if len(payload) > 0:
                        print(f"[PAYLOAD] Size: {len(payload)} bytes")
                        
                        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload[:100])
                        if printable.strip():
                            print(f"[PAYLOAD] Data: {printable}")
            
            
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                self.protocol_stats['UDP'] += 1
                print(f"[UDP] Source Port: {udp.sport} | Dest Port: {udp.dport}")
                print(f"[UDP] Length: {udp.len}")
                
                
                if udp.dport == 53 or udp.sport == 53:
                    print(f"[APPLICATION] DNS Query/Response")
                
                
                elif udp.dport == 67 or udp.sport == 68:
                    print(f"[APPLICATION] DHCP Traffic")
            
            
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                self.protocol_stats['ICMP'] += 1
                print(f"[ICMP] Type: {icmp.type} | Code: {icmp.code}")
                
                icmp_types = {
                    0: 'Echo Reply', 3: 'Destination Unreachable',
                    8: 'Echo Request', 11: 'Time Exceeded'
                }
                
                if icmp.type in icmp_types:
                    print(f"[ICMP] Description: {icmp_types[icmp.type]}")
        
        
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            self.protocol_stats['ARP'] += 1
            print(f"[ARP] Operation: {arp.op} ({'Request' if arp.op == 1 else 'Reply'})")
            print(f"[ARP] Source IP: {arp.psrc} | Source MAC: {arp.hwsrc}")
            print(f"[ARP] Target IP: {arp.pdst} | Target MAC: {arp.hwdst}")
        
        else:
            self.protocol_stats['Other'] += 1
            print(f"[OTHER] Protocol not analyzed")
        
        
        print(f"[SUMMARY] Total Length: {len(packet)} bytes")
        print(f"[RAW] {packet.summary()}")
    
    def print_statistics(self):
        """Print capture statistics"""
        print(f"\n{'='*60}")
        print("CAPTURE STATISTICS")
        print(f"{'='*60}")
        print(f"Total Packets Captured: {self.packet_count}")
        print("Protocol Distribution:")
        for protocol, count in self.protocol_stats.items():
            if count > 0:
                percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
                print(f"  {protocol}: {count} packets ({percentage:.1f}%)")

def packet_filter_examples():
    """Show examples of packet filters"""
    print("\nPacket Filter Examples:")
    print("- 'tcp': Capture only TCP packets")
    print("- 'udp': Capture only UDP packets")
    print("- 'icmp': Capture only ICMP packets")
    print("- 'host 192.168.1.1': Packets to/from specific IP")
    print("- 'port 80': Packets on port 80")
    print("- 'tcp and port 443': HTTPS traffic")
    print("- 'not arp': Exclude ARP packets")

def main():
    print("Educational Network Packet Sniffer")
    print("=" * 50)
    print("WARNING: Use only on networks you own or have permission to monitor!")
    print("This tool is for educational purposes only.\n")
    
    analyzer = PacketAnalyzer()
    
    
    packet_filter_examples()
    
    
    filter_input = input("\nEnter packet filter (or press Enter for all packets): ").strip()
    packet_filter = filter_input if filter_input else None
    

    try:
        count = int(input("Number of packets to capture (0 for continuous): "))
        count = None if count == 0 else count
    except ValueError:
        count = 10
        print(f"Invalid input, defaulting to {count} packets")
    
    print(f"\nStarting packet capture...")
    print(f"Filter: {packet_filter if packet_filter else 'None (all packets)'}")
    print(f"Count: {count if count else 'Continuous (Ctrl+C to stop)'}")
    print("Press Ctrl+C to stop capture\n")
    
    try:
        
        sniff(
            filter=packet_filter,
            prn=analyzer.analyze_packet,
            count=count,
            store=False  
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except PermissionError:
        print("Error: Permission denied. Try running as administrator/root")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        analyzer.print_statistics()


def explain_protocols():
    """Educational content about network protocols"""
    protocols_info = {
        "TCP": {
            "name": "Transmission Control Protocol",
            "characteristics": "Reliable, connection-oriented, ordered delivery",
            "use_cases": "Web browsing, email, file transfer",
            "ports": "80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP)"
        },
        "UDP": {
            "name": "User Datagram Protocol", 
            "characteristics": "Fast, connectionless, no guaranteed delivery",
            "use_cases": "DNS, video streaming, gaming",
            "ports": "53 (DNS), 67/68 (DHCP), 123 (NTP)"
        },
        "ICMP": {
            "name": "Internet Control Message Protocol",
            "characteristics": "Network diagnostics and error reporting",
            "use_cases": "Ping, traceroute, network troubleshooting",
            "ports": "N/A (uses IP directly)"
        },
        "ARP": {
            "name": "Address Resolution Protocol",
            "characteristics": "Maps IP addresses to MAC addresses",
            "use_cases": "Local network communication",
            "ports": "N/A (operates at data link layer)"
        }
    }
    
    print("\nNetwork Protocol Overview:")
    print("=" * 50)
    for proto, info in protocols_info.items():
        print(f"\n{proto} - {info['name']}")
        print(f"  Characteristics: {info['characteristics']}")
        print(f"  Use Cases: {info['use_cases']}")
        print(f"  Common Ports: {info['ports']}")

def show_packet_structure():
    """Show basic packet structure"""
    print("\nBasic Packet Structure (TCP/IP):")
    print("=" * 50)
    print("┌─────────────────┐")
    print("│ Ethernet Header │ ← Layer 2 (Data Link)")
    print("├─────────────────┤")
    print("│   IP Header     │ ← Layer 3 (Network)")
    print("├─────────────────┤") 
    print("│  TCP/UDP Header │ ← Layer 4 (Transport)")
    print("├─────────────────┤")
    print("│ Application Data│ ← Layer 5-7 (Application)")
    print("└─────────────────┘")

if __name__ == "__main__":
    choice = input("Choose option:\n1. Run packet sniffer\n2. Learn about protocols\n3. Show packet structure\nEnter choice (1-3): ")
    
    if choice == "1":
        main()
    elif choice == "2":
        explain_protocols()
    elif choice == "3":
        show_packet_structure()
    else:
        print("Invalid choice, running packet sniffer...")
        main()