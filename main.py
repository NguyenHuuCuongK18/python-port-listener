#!/usr/bin/env python3
"""
Packet sniffer with simplified single-line logging.

Console and capture-file output format:
    [Timestamp]: [Method] detected from [source] to [dest]: [information package]

Where:
- [Timestamp] is YYYY-MM-DD HH:MM:SS
- [Method] is the detected protocol/label (e.g., "HTTP Request (GET ...)",
  "HTTP Response (HTTP/1.1 200 OK)", "TCP", "UDP")
- [source] and [dest] are "IP:port"
- [information package] is a concise single-line payload summary:
    - For HTTP Request: "GET /path HTTP/1.1" (Host appended if available)
    - For HTTP Response: "HTTP/1.1 200 OK"
    - For others: first line or truncated preview of payload (or hex for binary)

Note: This remains a packet-by-packet sniffer (no TCP stream reassembly).
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from typing import List, Optional, Tuple, Callable

from scapy.all import sniff, conf, get_if_list  # type: ignore
from scapy.layers.inet import IP, TCP, UDP  # type: ignore
from scapy.packet import Packet, Raw  # type: ignore

# Toggle debug payload preview printed to console (not the main one-line format)
DEBUG: bool = False

# Primary capture file (single-line simplified records)
SIMPLE_CAPTURE_FILE: str = "captured_packets_simple.txt"

# Optionally also keep a full payload file for debugging/forensics (multi-line)
FULL_PAYLOAD_FILE: str = "captured_packets_full.txt"


# -------------------------
# Helpers: formatting & IO
# -------------------------
def now_timestamp() -> str:
    """Return current timestamp string used across all records."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def write_simple_record(line: str) -> None:
    """Append a single-line record to SIMPLE_CAPTURE_FILE (UTF-8)."""
    with open(SIMPLE_CAPTURE_FILE, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()


def write_full_payload_record(header: str, payload: Optional[str]) -> None:
    """Append a detailed multi-line payload record to FULL_PAYLOAD_FILE (UTF-8)."""
    with open(FULL_PAYLOAD_FILE, "a", encoding="utf-8") as fh:
        fh.write(header + "\n")
        fh.write((payload or "None") + "\n")
        fh.write("-" * 80 + "\n")
        fh.flush()


def console_and_optional_log_line(line: str, external_log_file: Optional[object]) -> None:
    """
    Print a single-line summary to stdout and optionally append that same line to external_log_file.

    Both console and external log will receive the identical simplified line.
    """
    print(line)
    if external_log_file:
        try:
            external_log_file.write(line + "\n")
            external_log_file.flush()
        except Exception:
            # Avoid crashing sniff loop if logging fails
            print("Warning: failed to write to external log.")


# -------------------------
# Compact information extraction
# -------------------------
def get_information_package(protocol_label: str, decoded_payload: Optional[str]) -> str:
    """
    Produce a concise, single-line 'information package' describing the payload.

    Rules:
    - If protocol_label suggests an HTTP Request and a request-line exists, return:
        "METHOD path HTTP/x.y [Host: hostvalue]" (host appended when present)
    - If HTTP Response, return "HTTP/x.y status reason"
    - Otherwise:
        - If decoded_payload contains at least one printable line, return the first
          non-empty line truncated to 200 characters.
        - If no printable text, return a short hex preview of up to 64 hex chars.
    """
    # Safe empty payload
    if not decoded_payload:
        return "No payload"

    # Normalize for search (keep original for returned fragments)
    payload = decoded_payload

    # HTTP Request detection (strong)
    req_match = re.search(
        r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)",
        payload,
        flags=re.IGNORECASE,
    )
    if req_match:
        method, path, version = req_match.groups()
        # Try Host header in payload
        host_search = re.search(r"(?mi)^\s*Host:\s*(.+)$", payload)
        host_fragment = f" Host:{host_search.group(1).strip()}" if host_search else ""
        return f"{method} {path} HTTP/{version}{host_fragment}"

    # HTTP Response detection
    resp_match = re.search(r"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", payload, flags=re.IGNORECASE)
    if resp_match:
        version, status_code, reason = resp_match.groups()
        return f"HTTP/{version} {status_code} {reason.strip()}"

    # Fallback: take first non-empty text line
    first_line_match = re.search(r"(?m)^[^\r\n]+", payload)
    if first_line_match:
        first_line = first_line_match.group(0).strip()
        # Truncate to a reasonable length for one-line logging
        if len(first_line) > 200:
            first_line = first_line[:200] + " ... (truncated)"
        # Replace newlines/tabs to keep single-line integrity
        return first_line.replace("\n", " ").replace("\r", " ").replace("\t", " ")

    # If no text line found, return hex preview (up to 64 hex chars)
    try:
        # If payload looks like hex already, keep a small preview
        hex_preview = payload.encode("utf-8", errors="ignore").hex()[:64]
        return f"hex:{hex_preview}..."
    except Exception:
        return "Non-text payload"


# -------------------------
# Packet processing
# -------------------------
def process_packet(
    packet: Packet,
    monitored_ports: Optional[List[int]],
    external_log_file: Optional[object],
) -> None:
    """
    Scapy packet callback that produces a single-line simplified log for console and SIMPLE_CAPTURE_FILE.

    Output format (single line):
        [Timestamp]: [Method] detected from [src_ip:src_port] to [dst_ip:dst_port]: [information package]

    'Method' is the human readable protocol_label detected (HTTP Request/Response or TCP/UDP)
    'information package' is produced by get_information_package(...)

    The function also writes a fuller payload record to FULL_PAYLOAD_FILE for reference.
    """
    # Extract IP addresses; fallback for loopback captures without IP
    if packet.haslayer(IP):
        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst
    else:
        src_ip = "127.0.0.1"
        dst_ip = "127.0.0.1"

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    decoded_payload: Optional[str] = None
    protocol_label: str = "Unknown"

    # --- TCP branch ---
    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

        # If monitored_ports is set, ignore packets not involving monitored ports
        if monitored_ports is not None and (src_port not in monitored_ports and dst_port not in monitored_ports):
            return

        if packet.haslayer(Raw):
            raw_bytes = bytes(packet[Raw].load)
            try:
                decoded_payload = raw_bytes.decode(errors="ignore")
            except Exception:
                decoded_payload = raw_bytes.hex()

        # Prioritize HTTP detection if payload present
        http_label = detect_http_label(decoded_payload or "")
        if http_label:
            protocol_label = http_label
        elif src_port == 5000 or dst_port == 5000:
            protocol_label = "TCP"
        else:
            # Generic TCP for other ports/payloads we allowed through lfilter
            protocol_label = "TCP"

    # --- UDP branch ---
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

        if monitored_ports is not None and (src_port not in monitored_ports and dst_port not in monitored_ports):
            return

        protocol_label = "UDP"
        if packet.haslayer(Raw):
            raw_bytes = bytes(packet[Raw].load)
            try:
                decoded_payload = raw_bytes.decode(errors="ignore")
            except Exception:
                decoded_payload = raw_bytes.hex()

    # Only log when we have ports and a known protocol_label
    if protocol_label == "Unknown" or src_port is None or dst_port is None:
        return

    # Build the concise information package for the single-line summary
    info_pkg: str = get_information_package(protocol_label, decoded_payload)
    timestamp = now_timestamp()
    source = f"{src_ip}:{src_port}"
    dest = f"{dst_ip}:{dst_port}"
    simple_line = f"[{timestamp}]: [{protocol_label}] detected from [{source}] to [{dest}]: {info_pkg}"

    # Print and optional external log (single-line only)
    console_and_optional_log_line(simple_line, external_log_file)

    # Also store to the simple capture file (single-line)
    try:
        write_simple_record(simple_line)
    except Exception as e:
        print(f"Warning: failed to write simple capture file: {e}")

    # For debugging/forensics also write a more detailed payload file
    full_header = f"[{timestamp}] {protocol_label} {source} -> {dest}"
    try:
        write_full_payload_record(full_header, decoded_payload)
    except Exception as e:
        # Don't crash sniffing; warn and continue
        print(f"Warning: failed to write full payload file: {e}")

    # Optional debug preview
    if DEBUG:
        preview_text = decoded_payload or "None"
        if len(preview_text) > 1000:
            preview_text = preview_text[:1000] + " ... (truncated)"
        debug_line = f"DEBUG preview: {preview_text}"
        console_and_optional_log_line(debug_line, external_log_file)


# Small utility used inside process_packet for label detection (keeps logic single-responsibility)
def detect_http_label(decoded_payload: str) -> Optional[str]:
    """
    Detect HTTP Request/Response and return a clear label or None.

    Returns examples:
      - "HTTP Request (GET /path HTTP/1.1)"
      - "HTTP Response (HTTP/1.1 200 OK)"
      - None if not HTTP-like
    """
    if not decoded_payload:
        return None

    # Remove leading CRLF if present to handle mid-stream fragments
    stripped = decoded_payload.lstrip("\r\n")

    req = re.search(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)", stripped, flags=re.IGNORECASE)
    if req:
        method, path, version = req.groups()
        return f"HTTP Request ({method} {path} HTTP/{version})"

    resp = re.search(r"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", stripped, flags=re.IGNORECASE)
    if resp:
        version, status, reason = resp.groups()
        return f"HTTP Response (HTTP/{version} {status} {reason.strip()})"

    # Looser heuristics
    if "HTTP/" in decoded_payload or re.search(r"(?mi)^(Host|User-Agent|Content-Type):", decoded_payload):
        return "HTTP (partial)"

    return None


# -------------------------
# CLI & main
# -------------------------
def parse_ports_argument(ports_arg: str) -> Tuple[Optional[List[int]], str]:
    """
    Parse --ports argument into a tuple (monitored_ports_or_none, description).

    - 'all' -> None (monitor all TCP/UDP payload-bearing packets)
    - 'common' -> common HTTP ports list
    - 'targeted' -> default [5000, 8080]
    - comma-separated ints -> parsed list
    """
    if ports_arg == "all":
        return None, "all TCP/UDP payload-bearing packets"
    if ports_arg == "common":
        ports = [80, 443, 8000, 8080, 8888]
        return ports, "common HTTP ports: " + ", ".join(map(str, ports))
    if ports_arg == "targeted":
        ports = [5000, 8080]
        return ports, "targeted (5000 and 8080)"
    try:
        ports = [int(p.strip()) for p in ports_arg.split(",") if p.strip()]
        return ports, "custom ports: " + ", ".join(map(str, ports))
    except Exception:
        raise ValueError("Invalid --ports argument. Use 'all','common','targeted', or comma-separated ints.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet sniffer with simplified one-line logging.")
    parser.add_argument("--ports", type=str, default="targeted", help="Ports: 'targeted' (default), 'common', 'all', or comma list.")
    parser.add_argument("--iface", type=str, default=None, help="Interface to sniff on (default: loopback).")
    parser.add_argument("--log", type=str, default=None, help="Optional file to append compact console lines to.")
    parser.add_argument("--timeout", type=int, default=0, help="Sniff timeout seconds (0 means run until Ctrl+C).")
    args = parser.parse_args()

    try:
        monitored_ports, ports_description = parse_ports_argument(args.ports)
    except ValueError as e:
        print(f"Error parsing --ports: {e}")
        sys.exit(2)

    # Select default interface when not provided
    if args.iface:
        interface_name: str = args.iface
    else:
        if sys.platform == "win32":
            try:
                interface_name = conf.loopback_name  # type: ignore
            except Exception:
                iface_list = get_if_list()
                interface_name = next((i for i in iface_list if "Loop" in i or "loop" in i or "lo" in i), iface_list[0])
        else:
            interface_name = "lo"

    # External compact console log file (optional)
    external_log_file = None
    if args.log:
        try:
            external_log_file = open(args.log, "a", encoding="utf-8")
        except Exception as e:
            print(f"Warning: cannot open {args.log} for appending: {e}")
            external_log_file = None

    console_and_optional_log_line(f"Sniffing on '{interface_name}' for {ports_description} ...", external_log_file)
    if DEBUG:
        console_and_optional_log_line("DEBUG mode enabled: payload previews will be printed to console.", external_log_file)
        console_and_optional_log_line("Format: [Timestamp]: [Method] detected from [src] to [dst]: [information package]", external_log_file)

    # Build lfilter to reduce noise
    def lfilter_fn(p: Packet) -> bool:
        try:
            if monitored_ports is None:
                return (p.haslayer(TCP) or p.haslayer(UDP)) and p.haslayer(Raw)
            if p.haslayer(TCP) and p.haslayer(Raw):
                return int(p[TCP].sport) in monitored_ports or int(p[TCP].dport) in monitored_ports
            if p.haslayer(UDP) and p.haslayer(Raw):
                return int(p[UDP].sport) in monitored_ports or int(p[UDP].dport) in monitored_ports
            return False
        except Exception:
            return False

    try:
        prn_callable: Callable[[Packet], None] = lambda pkt: process_packet(pkt, monitored_ports, external_log_file)
        sniff(iface=interface_name, prn=prn_callable, store=False, lfilter=lfilter_fn, timeout=(args.timeout or None))
    except KeyboardInterrupt:
        console_and_optional_log_line("Stopped sniffing (Ctrl+C).", external_log_file)
    except PermissionError:
        console_and_optional_log_line("Permission error: run as administrator/root and ensure Npcap/libpcap installed.", external_log_file)
    except Exception as exc:
        console_and_optional_log_line(f"Unexpected error: {exc}", external_log_file)
    finally:
        if external_log_file:
            try:
                external_log_file.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
