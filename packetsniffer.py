import socket
import struct
import textwrap

# Function to format multi-line data output
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# Main function to start packet sniffing
def sniff_packets():
    # Create a raw socket for Windows
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    
    # Bind the socket to the local IP address
    conn.bind(('127.0.0.1', 0))
    
    # Set socket options to include the IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    # Enable promiscuous mode
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        # Capture the raw packet data
        raw_data, addr = conn.recvfrom(65536)
        
        # Unpack Ethernet frame
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')
        
        # If the Ethernet protocol is IPv4, proceed to unpack it
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f'IPv4 Packet: Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source: {src}, Target: {target}')
            
            # Check for ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f'ICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(format_multi_line('   Data:', data))
                
            # Check for TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                print(f'TCP Segment: Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'Flags: {flags}')
                print(format_multi_line('   Data:', data))
                
            # Check for UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(f'UDP Segment: Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(format_multi_line('   Data:', data))
                
            # Other protocols
            else:
                print(f'Other IPv4 Protocol: {proto}')
                print(format_multi_line('   Data:', data))

# Helper function to unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Helper function to unpack IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Helper function to unpack ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Helper function to unpack TCP segments
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

# Helper function to unpack UDP segments
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Function to return a properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Function to return a properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Main entry point
if __name__ == "__main__":
    sniff_packets()
