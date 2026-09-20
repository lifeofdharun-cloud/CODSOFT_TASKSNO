#!/usr/bin/env python3
"""
Network Packet Analyzer
CodSoft Cyber Security Internship - Task 1

Captures packets on a network interface, extracts key details
(source IP, destination IP, protocol, ports, length, payload preview)
and presents them in a clean table, with an optional CSV / PCAP export.

Only capture traffic on networks you own or have permission to monitor.

Usage examples (run with admin/root rights):
    sudo python3 packet_analyzer.py -c 20
    sudo python3 packet_analyzer.py -c 50 -f "tcp port 80" --payload
    sudo python3 packet_analyzer.py -i wlan0 -c 100 --csv out.csv --pcap out.pcap
"""

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import ARP, ICMP, IP, TCP, UDP, IPv6, Raw, sniff, wrpcap
except ImportError:
    sys.exit("Scapy is not installed. Run:  pip install scapy")

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

HEADER = f"{'No.':<5} {'Time':<12} {'Source':<40} {'Destination':<40} {'Proto':<8} {'Ports':<15} {'Len':<6}"

rows = []             # every parsed packet, used for CSV export
raw_packets = []      # kept only if --pcap is requested
protocol_count = Counter()


def payload_preview(packet, max_bytes=40):
    """Return a printable preview of the packet's application data."""
    if Raw in packet:
        data = bytes(packet[Raw].load)[:max_bytes]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def analyze(packet):
    """Pull the important fields out of one packet. Returns a dict or None."""
    src = dst = proto = None
    sport = dport = ""

    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
        proto = PROTO_NAMES.get(packet[IP].proto, f"IP-{packet[IP].proto}")
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
        proto = PROTO_NAMES.get(packet[IPv6].nh, f"IPv6-{packet[IPv6].nh}")
    elif ARP in packet:
        src, dst, proto = packet[ARP].psrc, packet[ARP].pdst, "ARP"
    else:
        return None  # ignore non-IP / non-ARP frames

    if TCP in packet:
        sport, dport = packet[TCP].sport, packet[TCP].dport
    elif UDP in packet:
        sport, dport = packet[UDP].sport, packet[UDP].dport

    return {
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "source": src,
        "destination": dst,
        "protocol": proto,
        "src_port": sport,
        "dst_port": dport,
        "length": len(packet),
        "payload": payload_preview(packet),
    }


def make_handler(show_payload, keep_raw):
    def handle(packet):
        info = analyze(packet)
        if info is None:
            return

        info["no"] = len(rows) + 1
        rows.append(info)
        protocol_count[info["protocol"]] += 1
        if keep_raw:
            raw_packets.append(packet)

        ports = f"{info['src_port']}->{info['dst_port']}" if info["src_port"] != "" else "-"
        print(f"{info['no']:<5} {info['time']:<12} {info['source']:<40} "
              f"{info['destination']:<40} {info['protocol']:<8} {ports:<15} {info['length']:<6}")
        if show_payload and info["payload"]:
            print(f"      payload: {info['payload']}")
    return handle


def save_csv(path):
    fields = ["no", "time", "source", "destination", "protocol",
              "src_port", "dst_port", "length", "payload"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] CSV saved to {path}")


def print_summary():
    print("\n" + "=" * 30 + " SUMMARY " + "=" * 30)
    print(f"Total packets analysed: {len(rows)}")
    for proto, n in protocol_count.most_common():
        print(f"  {proto:<8} {n}")


def main():
    parser = argparse.ArgumentParser(description="Simple network packet analyzer (Scapy)")
    parser.add_argument("-i", "--interface", help="interface to sniff on (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="number of packets (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default=None, help='BPF filter, e.g. "tcp port 443"')
    parser.add_argument("--payload", action="store_true", help="show a preview of packet data")
    parser.add_argument("--csv", metavar="FILE", help="save results to a CSV file")
    parser.add_argument("--pcap", metavar="FILE", help="save raw packets to a PCAP file (open in Wireshark)")
    args = parser.parse_args()

    print(f"[*] Capturing... press Ctrl+C to stop\n{HEADER}\n{'-' * len(HEADER)}")

    try:
        sniff(iface=args.interface, filter=args.filter, count=args.count,
              prn=make_handler(args.payload, bool(args.pcap)), store=False)
    except PermissionError:
        sys.exit("[!] Permission denied. Run as root/administrator (sudo on Linux/macOS).")
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit(f"[!] Capture error: {e}\n    On Windows, install Npcap first (https://npcap.com).")

    print_summary()
    if args.csv:
        save_csv(args.csv)
    if args.pcap and raw_packets:
        wrpcap(args.pcap, raw_packets)
        print(f"[+] PCAP saved to {args.pcap}")


if __name__ == "__main__":
    main()
