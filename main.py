from scapy.all import *
import sys
import re
import argparse

from scapy.layers.inet import TCP, IP

def log_print(s, logf=None):
    print(s)
    if logf:
        logf.write(s + '\n')
        logf.flush()

def packet_callback(packet, ports, logf):
    # Fallback for IPs if IP layer is missing (common on loopback)
    src_ip = packet[IP].src if packet.haslayer(IP) else "127.0.0.1"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "127.0.0.1"
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Try to match HTTP request line
            match_req = re.match(r'^([A-Z]+) (\S+) HTTP/([0-9.]+)', payload)
            if match_req:
                method, path, version = match_req.groups()
                log_print(f"📨 HTTP Request from {src_ip}:{src_port} to {dst_ip}:{dst_port}", logf)
                log_print(f"Request URL/Path: {method} {path} HTTP/{version}", logf)
                log_print("Full Request Payload:", logf)
                log_print(payload, logf)
                log_print("-" * 50, logf)
                return

            # Try to match HTTP response line
            match_resp = re.match(r'^HTTP/([0-9.]+) (\d+) (.*)', payload)
            if match_resp:
                version, status, reason = match_resp.groups()
                log_print(f"📨 HTTP Response from {src_ip}:{src_port} to {dst_ip}:{dst_port}", logf)
                log_print(f"Response: HTTP/{version} {status} {reason}", logf)
                log_print("Full Response Payload:", logf)
                log_print(payload, logf)
                log_print("-" * 50, logf)
                return

            # If neither, treat as non-HTTP
            log_print(f"📨 Non-HTTP or malformed payload from {src_ip}:{src_port} to {dst_ip}:{dst_port}", logf)
            log_print("Payload:", logf)
            log_print(payload, logf)
            log_print("-" * 50, logf)

        except UnicodeDecodeError:
            log_print(f"📨 Non-text data from {src_ip}:{src_port} to {dst_ip}:{dst_port}", logf)
            log_print("Data (hex):", logf)
            log_print(packet[Raw].load.hex(), logf)
            log_print("-" * 50, logf)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniff HTTP traffic on specified ports and interface.")
    parser.add_argument('--ports', type=str, default='common',
                        help='Comma-separated ports (e.g., "80,8080"), or "all" for all TCP ports with payload, or "common" for common HTTP ports (80,443,8000,8080,8888).')
    parser.add_argument('--iface', type=str, default=None,
                        help='Network interface to sniff on (default: loopback).')
    parser.add_argument('--log', type=str, default=None,
                        help='Path to log file to export output (appends if exists).')

    args = parser.parse_args()

    # Determine interface
    if args.iface is None:
        if sys.platform == 'win32':
            iface = conf.loopback_name  # e.g., \Device\NPF_Loopback
        else:
            iface = 'lo'
    else:
        iface = args.iface

    # Determine ports
    if args.ports == 'all':
        ports = None
        ports_desc = "all TCP ports with payload"
    elif args.ports == 'common':
        ports = [80, 443, 8000, 8080, 8888]
        ports_desc = f"common ports: {', '.join(map(str, ports))}"
    else:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        ports_desc = f"ports: {', '.join(map(str, ports))}"

    # Log file setup
    logf = None
    if args.log:
        logf = open(args.log, 'a', encoding='utf-8')

    print(f"👂 Sniffing HTTP traffic on {ports_desc} via interface ({iface})...")
    print("Displays request URL/path for any endpoint. Run your server and client, then press Ctrl+C to stop.")
    if args.log:
        print(f"Logging to: {args.log}")

    try:
        # Define lambda filter
        if ports is None:
            lfilter_func = lambda p: p.haslayer(TCP) and p.haslayer(Raw)
        else:
            lfilter_func = lambda p: p.haslayer(TCP) and p.haslayer(Raw) and (p[TCP].sport in ports or p[TCP].dport in ports)

        # Sniff
        sniff(iface=iface, prn=lambda p: packet_callback(p, ports, logf), store=0, lfilter=lfilter_func)
    except KeyboardInterrupt:
        print("Stopping sniffing...")
    except Exception as e:
        print(f"Error: {e}")
        print("On Windows, reinstall Npcap with loopback support and run as administrator. On Linux, run with sudo. Verify with Wireshark.")
    finally:
        if logf:
            logf.close()