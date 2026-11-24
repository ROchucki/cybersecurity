#!/usr/bin/env python3
"""Rootless IPv4 mDNS/DNS-SD observation tool for Termux.

Examples:
  python mdns-scan.py --duration 20
  python mdns-scan.py --duration 20 --json report.json
  python mdns-scan.py --interface 192.168.1.23 --forever

Queries are sent once. Records are historical observations, not a live cache.
Use only on networks you own or have permission to examine.
"""

import argparse
import ipaddress
import json
import socket
import struct
import time
from collections import defaultdict
from datetime import datetime

GROUP = "224.0.0.251"
PORT = 5353
TYPES = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC"}
HINTS = {
    "_googlecast": "Google Cast / Android TV",
    "_androidtvremote2": "Android TV remote control",
    "_adb-tls-connect": "Wireless ADB",
    "_adb-tls-pairing": "Wireless ADB pairing",
    "_airplay": "AirPlay", "_raop": "AirPlay audio",
    "_ipp": "IPP printing", "_ipps": "IPPS printing",
    "_printer": "Printing", "_pdl-datastream": "Printing",
    "_http": "HTTP", "_https": "HTTPS",
    "_spotify-connect": "Spotify Connect", "_hue": "Philips Hue",
    "_homekit": "HomeKit", "_hap": "HomeKit accessory",
    "_sftp-ssh": "SSH/SFTP", "_ssh": "SSH",
    "_workstation": "Workstation", "_smb": "SMB file sharing",
    "_esphomelib": "ESPHome", "_matter": "Matter",
    "_matterc": "Matter commissioning", "_device-info": "Device information",
    "_sleep-proxy": "Sleep Proxy",
}
SERVICES = ["_services._dns-sd._udp.local"] + [
    name + "._tcp.local" for name in (
        "_googlecast", "_androidtvremote2", "_adb-tls-connect",
        "_adb-tls-pairing", "_airplay", "_raop", "_ipp", "_ipps",
        "_printer", "_http", "_https", "_spotify-connect", "_hap",
        "_homekit", "_ssh", "_smb", "_device-info",
    )
]


def read_name(packet, offset):
    labels, visited = [], set()
    pos, end_offset, expanded = offset, None, 1
    while True:
        if pos >= len(packet) or pos in visited:
            raise ValueError("Invalid DNS name or compression loop")
        visited.add(pos)
        length = packet[pos]
        if length == 0:
            if end_offset is None:
                end_offset = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(packet):
                raise ValueError("Truncated pointer")
            pointer = ((length & 0x3F) << 8) | packet[pos + 1]
            if pointer >= len(packet):
                raise ValueError("Pointer outside packet")
            if end_offset is None:
                end_offset = pos + 2
            pos = pointer
            continue
        if length & 0xC0:
            raise ValueError("Unsupported label type")
        stop = pos + 1 + length
        expanded += 1 + length
        if stop > len(packet) or expanded > 255:
            raise ValueError("Truncated or oversized name")
        labels.append(packet[pos + 1:stop].decode("utf-8", "replace"))
        pos = stop
    return ".".join(labels), end_offset


def encode_name(name):
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    result = bytearray()
    for label in name.split("."):
        raw = label.encode("utf-8")
        if not 1 <= len(raw) <= 63:
            raise ValueError("Invalid label length")
        result.append(len(raw))
        result.extend(raw)
    result.append(0)
    if len(result) > 255:
        raise ValueError("Name too long")
    return bytes(result)


def make_query(name, qtype=12):
    return (struct.pack(">6H", 0, 0, 1, 0, 0, 0)
            + encode_name(name) + struct.pack(">HH", qtype, 1))


def parse_packet(packet):
    records = []
    if len(packet) < 12:
        return records
    try:
        _, flags, qd, an, ns, ar = struct.unpack(">6H", packet[:12])
        if not flags & 0x8000 or flags & 0x780F:
            return records
        offset = 12
        for _ in range(qd):
            _, offset = read_name(packet, offset)
            if offset + 4 > len(packet):
                raise ValueError("Truncated question")
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = read_name(packet, offset)
            if offset + 10 > len(packet):
                raise ValueError("Truncated record")
            kind, cls, ttl, size = struct.unpack(">HHIH", packet[offset:offset + 10])
            offset += 10
            end = offset + size
            if end > len(packet):
                raise ValueError("Truncated RDATA")
            data = packet[offset:end]
            if cls & 0x7FFF != 1:
                offset = end
                continue
            if kind in (1, 28):
                required = 4 if kind == 1 else 16
                if size != required:
                    raise ValueError("Invalid address length")
                family = socket.AF_INET if kind == 1 else socket.AF_INET6
                value = socket.inet_ntop(family, data)
            elif kind == 12:
                value, stop = read_name(packet, offset)
                if stop != end:
                    raise ValueError("Invalid PTR length")
            elif kind == 33:
                if size < 7:
                    raise ValueError("Truncated SRV")
                priority, weight, port = struct.unpack(">3H", data[:6])
                target, stop = read_name(packet, offset + 6)
                if stop != end:
                    raise ValueError("Invalid SRV length")
                value = dict(priority=priority, weight=weight, port=port, target=target)
            elif kind == 16:
                value, pos = [], 0
                while pos < size:
                    length = data[pos]
                    pos += 1
                    if pos + length > size:
                        raise ValueError("Truncated TXT")
                    value.append(data[pos:pos + length].decode("utf-8", "replace"))
                    pos += length
            else:
                value = data.hex()
            records.append(dict(name=name, type=TYPES.get(kind, str(kind)),
                                ttl=ttl, cache_flush=bool(cls & 0x8000), value=value))
            offset = end
    except (ValueError, struct.error, IndexError, OSError):
        pass
    return records


def service_types(name):
    parts = name.lower().rstrip(".").split(".")
    return {parts[i] for i in range(len(parts) - 2)
            if parts[i].startswith("_") and parts[i] != "_dns-sd"
            and parts[i + 1] in ("_tcp", "_udp") and parts[i + 2] == "local"}


def collect_services(records):
    result = set()
    for rec in records:
        result.update(service_types(rec["name"]))
        if rec["type"] == "PTR":
            result.update(service_types(rec["value"]))
    return result


def create_socket(interface):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", PORT))
        membership = socket.inet_aton(GROUP) + socket.inet_aton(interface)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(interface))
    except OSError:
        sock.close()
        raise
    return sock


def print_summary(records):
    groups = defaultdict(list)
    for rec in records:
        groups[rec["source_ip"]].append(rec)
    print("\n========== OBSERVATION SUMMARY ==========")
    print("Historical observations, not a live DNS cache.")
    if not groups:
        print("No mDNS responses received. This does not prove no devices exist.")
        return
    for ip in sorted(groups, key=ipaddress.ip_address):
        group = groups[ip]
        services = sorted(collect_services(group))
        labels = sorted({HINTS[s] for s in services if s in HINTS})
        addresses = sorted({r["value"] for r in group if r["type"] in ("A", "AAAA")})
        names = {r["name"] for r in group}
        names.update(r["value"] for r in group if r["type"] == "PTR")
        print(f"\nSource IP: {ip}")
        print("  Functions: " + (", ".join(labels) or "Unknown"))
        if services:
            print("  Services: " + ", ".join(services))
        if addresses:
            print("  Advertised addresses: " + ", ".join(addresses))
        print("  Names:")
        for name in sorted(names)[:12]:
            print("    - " + name)
        if len(names) > 12:
            print(f"    ... and {len(names) - 12} more")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=60,
                        help="scan duration in seconds (default: 60)")
    parser.add_argument("--forever", action="store_true",
                        help="listen until Ctrl+C; queries are sent once")
    parser.add_argument("--interface", default="0.0.0.0",
                        help="local Wi-Fi IPv4 address")
    parser.add_argument("--json", dest="json_path", help="JSON report destination")
    args = parser.parse_args()
    if args.duration < 1:
        parser.error("--duration must be >= 1")
    try:
        ipaddress.IPv4Address(args.interface)
    except ValueError:
        parser.error("--interface must be an IPv4 address")
    try:
        sock = create_socket(args.interface)
    except OSError as exc:
        raise SystemExit(f"Cannot start mDNS: {exc}\nCheck Wi-Fi, interface, VPN and UDP port 5353.")

    seen, send_errors, receive_errors = {}, [], []
    started = time.monotonic()
    deadline = started + args.duration
    print(f"mDNS scanner | {datetime.now().isoformat(timespec='seconds')}")
    print(f"Group: {GROUP}:{PORT} | interface: {args.interface}")
    print("Sending queries once, then listening. Ctrl+C stops.\n")
    try:
        for service in SERVICES:
            try:
                sock.sendto(make_query(service), (GROUP, PORT))
            except OSError as exc:
                send_errors.append(f"{service}: {exc}")
        for error in send_errors:
            print("Send error: " + error)
        while True:
            remaining = deadline - time.monotonic()
            if not args.forever and remaining <= 0:
                break
            sock.settimeout(1.0 if args.forever else min(1.0, remaining))
            try:
                packet, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                receive_errors.append(str(exc))
                print(f"Receive error: {exc}")
                break
            if addr[1] != PORT:
                continue
            timestamp = datetime.now().isoformat(timespec="seconds")
            for rec in parse_packet(packet):
                key = (addr[0], rec["name"], rec["type"],
                       json.dumps(rec["value"], sort_keys=True, ensure_ascii=False))
                previous = seen.get(key)
                seen[key] = dict(source_ip=addr[0], **rec,
                                 first_seen=previous["first_seen"] if previous else timestamp,
                                 last_seen=timestamp)
                if previous and ((previous["ttl"] == 0) == (rec["ttl"] == 0)):
                    continue
                value = rec["value"]
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                status = " [withdrawn]" if rec["ttl"] == 0 else ""
                print(f"[{timestamp[11:]}] {addr[0]:>15} | {rec['type']:<4} | "
                      f"{rec['name'][:65]} | {str(value)[:100]}{status}")
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        sock.close()

    elapsed = round(time.monotonic() - started, 1)
    records = list(seen.values())
    print_summary(records)
    if args.json_path:
        report = dict(generated_at=datetime.now().isoformat(timespec="seconds"),
                      interface=args.interface, duration_seconds=elapsed,
                      report_mode="observed_records_not_live_cache", records=records,
                      send_errors=send_errors, receive_errors=receive_errors)
        try:
            with open(args.json_path, "w", encoding="utf-8") as output:
                json.dump(report, output, ensure_ascii=False, indent=2)
            print(f"\nJSON report saved: {args.json_path}")
        except OSError as exc:
            print(f"\nCannot save JSON report: {exc}")
    print(f"\nElapsed: {elapsed} s")
    print("IPv4 multicast only; AAAA records in received responses are decoded.")
    print("Source IP groups are not guaranteed device identities.")
    print("This is not a full IP inventory or a complete mDNS implementation.")


if __name__ == "__main__":
    main()
