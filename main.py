#!/usr/bin/env python3
# ============================================================
# Project: Network Traffic Analyzer
# Author: 0xander
# Watermark: created and maintained by 0xander
# Description: Lightweight PCAP traffic analyzer for network inspection.
# Notes: Comments in Portuguese + English for traceability and style.
# ============================================================
"""Network Traffic Analyzer.

Analisador leve de tráfego de rede que extrai fluxos, portas, protocolos,
consultas DNS, requisições HTTP, conexões suspeitas e indicadores de C2.

Lightweight pcap reader that extracts flows, ports, protocols, DNS queries,
HTTP requests, suspicious connections and potential C2-style indicators.
"""

import argparse
import os
import socket
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field


RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"

SUSPICIOUS_PORTS = {4444, 8080, 1337}
WATERMARK = "0xander // cyber-security pcap intelligence"


@dataclass
class AnalyzerData:
    packets_analyzed: int
    ips_involved: list[str]
    ports: list[int]
    protocols: list[str]
    dns_queries: list[str]
    http_requests: list[str]
    suspicious_connections: list[str]
    potential_c2: list[str]
    top_source: str = "unknown"
    top_destination: str = "unknown"
    suspicious_port_set: list[int] = field(default_factory=list)


class Analyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def analyze(self) -> AnalyzerData:
        # Processa o arquivo PCAP e monta estatísticas de fluxo.
        # Processes the PCAP file and builds traffic flow statistics.
        ip_counter = Counter()
        src_counter = Counter()
        dst_counter = Counter()
        port_counter = Counter()
        protocol_counter = Counter()
        dns_queries = []
        http_requests = []
        suspicious_connections = []
        potential_c2 = []
        suspicious_ports = []

        with open(self.filepath, "rb") as handle:
            raw = handle.read()
        if len(raw) < 24:
            return AnalyzerData(0, [], [], [], [], [], [], [], "unknown", "unknown", [])

        endian = self._detect_endian(raw[:4])
        offset = 24
        packets_analyzed = 0

        while offset + 16 <= len(raw):
            record_header = raw[offset:offset + 16]
            if len(record_header) != 16:
                break
            _, _, incl_len, _ = struct.unpack(f"{endian}IIII", record_header)
            pkt = raw[offset + 16:offset + 16 + incl_len]
            offset += 16 + incl_len

            if len(pkt) < 14:
                continue

            eth_type = struct.unpack("!H", pkt[12:14])[0]
            if eth_type != 0x0800:
                continue

            ip_packet = pkt[14:]
            if len(ip_packet) < 20:
                continue

            version = ip_packet[0] >> 4
            ihl = (ip_packet[0] & 0x0F) * 4
            if version != 4 or ihl < 20 or len(ip_packet) < ihl:
                continue

            proto = ip_packet[9]
            src_ip = socket.inet_ntoa(ip_packet[12:16])
            dst_ip = socket.inet_ntoa(ip_packet[16:20])
            src_counter[src_ip] += 1
            dst_counter[dst_ip] += 1
            ip_counter[src_ip] += 1
            ip_counter[dst_ip] += 1

            protocol_name = self._protocol_name(proto)
            protocol_counter[protocol_name] += 1

            src_port = None
            dst_port = None
            payload = b""

            if proto == 6:
                tcp_offset = 14 + ihl
                if len(pkt) >= tcp_offset + 20:
                    tcp = pkt[tcp_offset:]
                    src_port, dst_port = struct.unpack("!HH", tcp[:4])
                    payload = tcp[20:]
                    port_counter[src_port] += 1
                    port_counter[dst_port] += 1
                    protocol_name = "TCP"
                else:
                    continue

            elif proto == 17:
                udp_offset = 14 + ihl
                if len(pkt) >= udp_offset + 8:
                    udp = pkt[udp_offset:]
                    src_port, dst_port = struct.unpack("!HH", udp[:4])
                    payload = udp[8:]
                    port_counter[src_port] += 1
                    port_counter[dst_port] += 1
                    protocol_name = "UDP"
                else:
                    continue

            if src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS:
                suspicious_ports.append(src_port or dst_port)
                suspicious_connections.append(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | suspicious port activity")
                potential_c2.append(f"{src_ip} -> {dst_ip} suspicious:{src_port or dst_port} protocol:{protocol_name}")

            # DNS queries.
            # Consultas DNS.
            if src_port == 53 or dst_port == 53:
                dns_name = self._decode_dns_query(payload)
                if dns_name:
                    dns_queries.append(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} query={dns_name}")

            # HTTP requests.
            # Requisições HTTP.
            try:
                text = payload.decode("latin1", errors="ignore")
            except Exception:
                text = ""
            if (src_port in {80, 8080, 8000, 443} or dst_port in {80, 8080, 8000, 443}) and text:
                first_line = text.splitlines()[0].strip() if text.splitlines() else ""
                if first_line.startswith(("GET ", "POST ", "PUT ", "HEAD ")) or "HTTP/" in text:
                    http_requests.append(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} :: {first_line}")

            packets_analyzed += 1

        ips_involved = sorted(set(ip_counter.keys()))
        ports = sorted(port_counter.keys())
        protocols = sorted(protocol_counter.keys())
        top_source = src_counter.most_common(1)[0][0] if src_counter else "unknown"
        top_destination = dst_counter.most_common(1)[0][0] if dst_counter else "unknown"
        suspicious_port_set = sorted(set(suspicious_ports))

        return AnalyzerData(
            packets_analyzed=packets_analyzed,
            ips_involved=ips_involved,
            ports=ports,
            protocols=protocols,
            dns_queries=dns_queries,
            http_requests=http_requests,
            suspicious_connections=suspicious_connections,
            potential_c2=potential_c2,
            top_source=top_source,
            top_destination=top_destination,
            suspicious_port_set=suspicious_port_set,
        )

    @staticmethod
    def _detect_endian(magic: bytes) -> str:
        # Detecta a ordem de bytes do cabeçalho PCAP.
        # Detects the byte ordering used by the PCAP header.
        if magic == b"\xd4\xc3\xb2\xa1":
            return "<"
        if magic == b"\xa1\xb2\xc3\xd4":
            return ">"
        if magic == b"\x4d\x18\x4d\x18":
            return "<"
        if magic == b"\x18\x4d\x18\x4d":
            return ">"
        return "<"

    @staticmethod
    def _protocol_name(proto: int) -> str:
        # Mapeia o número do protocolo para uma label legível.
        # Maps protocol numbers to readable labels.
        return {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6"}.get(proto, f"PROTO_{proto}")

    @staticmethod
    def _decode_dns_query(payload: bytes) -> str | None:
        # Extrai nomes de domínio contidos em payloads DNS.
        # Extracts domain names from DNS payloads.
        if len(payload) < 12:
            return None
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            offset += 1
            if offset + length > len(payload):
                break
            labels.append(payload[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        return ".".join(labels) if labels else None


def analyze_pcap(path: str) -> AnalyzerData:
    return Analyzer(path).analyze()


def build_report_text(data: AnalyzerData) -> str:
    # Gera um texto legível para relatórios em terminal ou arquivos.
    # Builds a readable text report for terminal or file output.
    lines = []
    lines.append("========== NETWORK REPORT ==========")
    lines.append("")
    lines.append("[+] Packets analyzed:")
    lines.append(f"    {data.packets_analyzed:,}")
    lines.append("")
    lines.append("[+] Top source:")
    lines.append(f"    {data.top_source}")
    lines.append("")
    lines.append("[+] Top destination:")
    lines.append(f"    {data.top_destination}")
    lines.append("")
    lines.append("[+] Suspicious ports:")
    if data.suspicious_port_set:
        lines.append("    " + ", ".join(str(p) for p in data.suspicious_port_set))
    else:
        lines.append("    " + ", ".join(str(p) for p in sorted(SUSPICIOUS_PORTS)))
    lines.append("")
    lines.append("[+] Potential C2:")
    if data.potential_c2:
        lines.extend(f"    {item}" for item in data.potential_c2[:3])
    else:
        lines.append("    No clear C2 pattern detected")
    lines.append("")
    lines.append("[+] IPs involved:")
    lines.extend(f"    {ip}" for ip in data.ips_involved or ["No IPs captured"])
    lines.append("")
    lines.append("[+] Ports:")
    lines.extend(f"    {port}" for port in data.ports)
    lines.append("")
    lines.append("[+] Protocols:")
    lines.extend(f"    {protocol}" for protocol in data.protocols or ["No protocols captured"])
    lines.append("")
    lines.append("[+] DNS queries:")
    lines.extend(f"    {query}" for query in data.dns_queries or ["No DNS traffic detected"])
    lines.append("")
    lines.append("[+] HTTP requests:")
    lines.extend(f"    {req}" for req in data.http_requests or ["No HTTP traffic detected"])
    lines.append("")
    lines.append("[+] Connections suspeitas:")
    lines.extend(f"    {conn}" for conn in data.suspicious_connections or ["No suspicious connections detected"])
    return "\n".join(lines)


def print_banner() -> None:
    # Exibe o banner visual do projeto no início da execução.
    # Displays the visual project banner at execution startup.
    logo_path = os.path.join(os.path.dirname(__file__), "logo.txt")
    if os.path.exists(logo_path):
        with open(logo_path, "r", encoding="utf-8") as fp:
            banner = fp.read()
    else:
        banner = r"""
        __  __             _       _   _     ____      _       _       _
       |  \/  | __ _ _ __ | |__   | | | |   / ___| ___| |_ ___| |_ ___| |_
       | |\/| |/ _` | '_ \| '_ \  | | | |  | |  _ / _ \ __/ __| __/ _ \ __|
       | |  | | (_| | | | |_) | |_| | |  | |_| |  __/ |_|__ \ |_  __/ |_ 
       |_|  |_|\__,_|_| |_|_.__/  \___/   \____|\___|\__|___/___|\__\___|\__|

                    Network Traffic Analyzer
                    cyber-security pcap intelligence
                    by 0xander
        """
    print(f"{CYAN}{banner}\n{WATERMARK}{RESET}")


def main(argv: list[str] | None = None) -> int:
    # Ponto de entrada principal do analisador.
    # Main entry point for the analyzer.
    print_banner()

    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("pcap", help="Path to your .pcap file")
    args = parser.parse_args(argv)

    pcap_path = args.pcap
    if not os.path.exists(pcap_path):
        print(f"{RED}File not found: {pcap_path}{RESET}")
        print(f"{YELLOW}Use: python3 main.py your_capture.pcap{RESET}")
        return 2

    print(f"{GREEN}[+] Loading pcap: {pcap_path}{RESET}")
    data = analyze_pcap(pcap_path)
    report = build_report_text(data)
    print(f"{BOLD}{CYAN}{report}{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
