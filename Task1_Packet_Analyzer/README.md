# Task 1 - Network Packet Analyzer

CodSoft Cyber Security Internship

A Python tool that captures live network packets with **Scapy**, extracts the important
fields, and shows them in an organized table.

## What it extracts
- Source IP and destination IP (IPv4, IPv6, ARP)
- Protocol type (TCP, UDP, ICMP, ARP, ...)
- Source / destination ports
- Packet length
- Preview of the packet data (payload)

## Setup
```bash
pip install scapy
```
- **Windows:** install [Npcap](https://npcap.com) and run the terminal as Administrator.
- **Linux / macOS:** run with `sudo`.

## Usage
```bash
sudo python3 packet_analyzer.py -c 20                      # capture 20 packets
sudo python3 packet_analyzer.py -c 50 -f "tcp port 80"     # only HTTP traffic
sudo python3 packet_analyzer.py -c 100 --payload           # show data preview
sudo python3 packet_analyzer.py -c 100 --csv out.csv --pcap out.pcap
```

| Option | Meaning |
|---|---|
| `-i` | network interface (e.g. `eth0`, `wlan0`) |
| `-c` | number of packets (0 = run until Ctrl+C) |
| `-f` | BPF filter such as `tcp port 443` or `icmp` |
| `--payload` | show a printable preview of packet data |
| `--csv` | export parsed packets to CSV |
| `--pcap` | export raw packets to open in Wireshark |

## Sample output
Replace this with a screenshot or paste from your own run.

## Ethical use
Only capture traffic on networks you own or have explicit permission to monitor.
