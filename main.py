from scapy.all import *
import sys
import re

from scapy.layers.inet import TCP, IP


def packet_callback(packet):
    # Check for TCP layer and port 8080
    if packet.haslayer(TCP) and (packet[TCP].sport == 8080 or packet[TCP].dport == 8080):
        # Fallback for IPs if IP layer is missing (common on loopback)
        src_ip : str = packet[IP].src if packet.haslayer(IP) else "127.0.0.1"
        dst_ip : str = packet[IP].dst if packet.haslayer(IP) else "127.0.0.1"
        src_port : str = packet[TCP].sport
        dst_port :str = packet[TCP].dport

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # For requests (to server on port 8080): Extract HTTP request line (method + path + version)
                if packet[TCP].dport == 8080:
                    match = re.match(r'^([A-Z]+) (\S+) HTTP/([0-9.]+)', payload)
                    if match:
                        method, path, version = match.groups()
                        print(f"📨 HTTP Request from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                        print(f"Request URL/Path: {method} {path} HTTP/{version}")
                        print("Full Request Payload:")
                        print(payload)
                        print("-" * 50)
                    else:
                        print(f"📨 Non-HTTP or malformed request from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                        print("Payload:")
                        print(payload)
                        print("-" * 50)

                # For responses (from server on port 8080): Extract HTTP response line
                elif packet[TCP].sport == 8080:
                    match = re.match(r'^HTTP/([0-9.]+) (\d+) (.*)', payload)
                    if match:
                        version, status, reason = match.groups()
                        print(f"📨 HTTP Response from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                        print(f"Response: HTTP/{version} {status} {reason}")
                        print("Full Response Payload:")
                        print(payload)
                        print("-" * 50)
                    else:
                        print(f"📨 Non-HTTP or malformed response from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                        print("Payload:")
                        print(payload)
                        print("-" * 50)
            except UnicodeDecodeError:
                print(f"📨 Non-text data from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                print("Data (hex):")
                print(packet[Raw].load.hex())
                print("-" * 50)


if __name__ == "__main__":
    if sys.platform != 'win32':
        print("This script is designed for Windows.")
        sys.exit(1)

    # Use Scapy's configured loopback name
    loopback_iface = conf.loopback_name  # Automatically set to \Device\NPF_Loopback if Npcap is detected

    print(f"👂 Sniffing all HTTP traffic on port 8080 via loopback interface ({loopback_iface})...")
    print("Displays request URL/path for any endpoint. Run your server and client, then press Ctrl+C to stop.")

    try:
        # No BPF filter (to avoid loopback issues); use lfilter for TCP + port 8080
        sniff(iface=loopback_iface, prn=packet_callback, store=0,
              lfilter=lambda p: p.haslayer(TCP) and (p[TCP].sport == 8080 or p[TCP].dport == 8080))
    except KeyboardInterrupt:
        print("Stopping sniffing...")
    except Exception as e:
        print(f"Error: {e}")
        print("Reinstall Npcap with loopback support and run as administrator. Verify with Wireshark.")