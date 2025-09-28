# PortListener / Packet Sniffer

Lightweight Python packet sniffer focused on producing human‑readable one‑line summaries of TCP/UDP payload traffic (with basic HTTP request/response recognition). Designed for quick local debugging on Windows loopback or selected interfaces.

---
## Features
- One‑line log format: `[YYYY-MM-DD HH:MM:SS]: [Label] detected from [src_ip:src_port] to [dst_ip:dst_port]: <information package>`
- Detects & labels HTTP requests, HTTP responses, partial HTTP fragments, generic TCP, UDP
- Appends concise records to `captured_packets_simple.txt`
- Optionally records full (raw decoded) payloads in `captured_packets_full.txt`
- Optional extra simultaneous log file via `--log your_log.txt`
- Port filtering modes: targeted / common / all / custom list (e.g. `80,443,8080`)
- Timeout support (auto stop after N seconds)

---
## Quick Start (Windows)
1. Install **Python 3.9+** (3.11/3.12 recommended).
2. Install **Npcap** (required for packet capture on Windows):
   - Download: https://npcap.com/
   - During install leave default options ("Install Npcap in WinPcap API-compatible Mode" is usually fine).
3. (Recommended) Create & activate a virtual environment:
```
python -m venv .venv
.venv\Scripts\activate
```
4. Install dependencies:
   - The repo contains a `requirements` file (no extension). Either:
     - Rename it to `requirements.txt` then run:
```
pip install -r requirements.txt
```
     - OR install directly:
```
pip install scapy==2.6.1
```
5. Run the sniffer **from an elevated (Administrator) terminal**:
```
python main.py --ports targeted
```

If you see permission errors, re‑open your Command Prompt / PowerShell as Administrator.

---
## Command Line Usage
```
python main.py [--ports MODE|LIST] [--iface NAME] [--log FILE] [--timeout SECONDS]
```
Arguments:
- `--ports`:
  - `targeted` (default) → ports 5000, 8080
  - `common` → 80, 443, 8000, 8080, 8888
  - `all` → any TCP/UDP packet with a Raw payload
  - Comma list → e.g. `--ports 80,443,8080`
- `--iface` Interface name (omit to auto‑select loopback). On Windows the code attempts to pick the loopback automatically.
- `--log` Path to an extra file that will receive the same concise console lines.
- `--timeout` Number of seconds to sniff (0 = run until Ctrl+C).

Examples:
```
# Monitor default targeted ports on loopback
python main.py

# Monitor common web ports and stop after 120s
python main.py --ports common --timeout 120

# Custom ports, write an external session log
python main.py --ports 80,443 --log session.log

# All TCP/UDP payload packets on a specific interface name
python main.py --ports all --iface "Ethernet"
```
To list interfaces quickly (interactive Python):
```
from scapy.all import get_if_list
print(get_if_list())
```
(Or run a short script; Scapy must be installed.)

---
## Output Files
| File | Description |
|------|-------------|
| `captured_packets_simple.txt` | One‑line summaries (append‑only) |
| `captured_packets_full.txt` | Multi-line: header + full decoded payload + separator |
| (optional) `your_log.txt` | If `--log` specified: duplicate of console lines |

Log line anatomy example:
```
[2025-09-28 14:33:50]: [HTTP Request (GET /api/v1/items HTTP/1.1)] detected from [127.0.0.1:50104] to [127.0.0.1:8080]: GET /api/v1/items HTTP/1.1 Host:localhost:8080
```
- First bracket: timestamp
- Second bracket: detected protocol label (may include parsed request/response line)
- `from` / `to`: IP:port endpoints
- Tail: concise information package (request line + Host, response status, first text line, or hex preview)

Full payload record example (`captured_packets_full.txt`):
```
[2025-09-28 14:33:50] HTTP Request (GET /api/v1/items HTTP/1.1) 127.0.0.1:50104 -> 127.0.0.1:8080
GET /api/v1/items HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.1.2\r\nAccept: */*\r\n\r\n
--------------------------------------------------------------------------------
```

---
## How HTTP Detection Works
The script looks for:
- Request line: `METHOD <path> HTTP/x.y`
- Response line: `HTTP/x.y <status> <reason>`
- Otherwise checks for headers or fragments (`Host:`, `User-Agent:`) → may label as `HTTP (partial)`
If none match, falls back to generic `TCP` / `UDP` and uses the first non-empty text line or a hex snippet.

---
## Limitations / Scope
- No TCP stream reassembly: multi‑packet HTTP bodies might appear fragmented.
- Only inspects packets with a `Raw` layer (payload). Pure ACKs / handshakes filtered out by design when port filtering active.
- Not an intrusion detection system—intended for local debugging / educational use.
- Payload decoding uses `errors="ignore"`; binary data becomes truncated/hex‑preview.

---
## Security & Privacy Notes
- Capturing packets may expose sensitive data in plaintext protocols. Safeguard log files.
- Run only on networks you are authorized to monitor.
- Consider encryption (HTTPS) limitations: TLS payloads will not be readable.

---
## Troubleshooting
| Symptom | Possible Cause / Fix |
|---------|----------------------|
| `Permission error` | Run terminal as Administrator; ensure Npcap installed. |
| Empty output | Wrong interface, wrong port filter, no traffic yet. Try `--ports all` or generate traffic. |
| Interface name not found | Use `get_if_list()` to confirm exact name (case sensitive sometimes). |
| Garbled characters | Binary payloads decoded with ignore errors—expected. Check full file for hex preview. |
| No HTTP labels | Traffic might be TLS (HTTPS) or fragmented mid‑stream. |

---
## Development Tips
- Enable quick manual testing: `curl http://localhost:8080/` or start a simple server.
- You can extend `detect_http_label` or `get_information_package` to support more protocols (e.g., DNS, MQTT) by inspecting payload signatures.
- Set `DEBUG = True` in `main.py` for additional payload previews (truncated).

---
## Possible Improvements (Future Work)
- Add DNS / TLS ClientHello / SNI recognition
- Optional PCAP output
- Stream reassembly for HTTP (using `scapy.sessions` or `dpkt`/`pyshark` integration)
- Colored console output
- Configurable max line length & truncation marker

---
## License
Add a license of your choice (e.g., MIT) here if you plan to share publicly.

---
## Attribution
Built with [Scapy](https://scapy.net/).

---
## One-Liner Recap
Install Npcap, install Scapy, run as Administrator:
```
pip install scapy==2.6.1
python main.py --ports common --timeout 60
```

