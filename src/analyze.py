from pathlib import Path
from scapy.all import rdpcap, IP, TCP, UDP
from argparse import ArgumentParser
from scapy.error import Scapy_Exception
import json
from collections import defaultdict


def analyze_protocols(packets):
    tcp_count = 0
    udp_count = 0
    packet_types = []

    for packet in packets:

        if TCP in packet:
            packet_types.append("TCP")
            tcp_count += 1

        elif UDP in packet:
            packet_types.append("UDP")
            udp_count += 1

        else:
            packet_types.append("Other")

    return packet_types, tcp_count, udp_count



# Accept a PCAP filename from the terminal
parser = ArgumentParser(
    description="NetLens Network Traffic Analyzer"
)

parser.add_argument(
    "pcap",
    type=Path,
    help="Path to the PCAP file to analyze"
)

args = parser.parse_args()

pcap_path = args.pcap.expanduser().resolve()

# Ensure the file exists
if not pcap_path.is_file():
    parser.error(f"File not found: {pcap_path}")


# Read packets from the capture
try:
    packets = rdpcap(str(pcap_path))

except (Scapy_Exception, OSError) as error:
    parser.error(
        f"Unable to read capture '{pcap_path}': {error}"
    )


# Display our first analysis results
print("Welcome to NetLens!")
print("Total packets:", len(packets))
print("First packet:", packets[0].summary())


print("\nIP Address Analysis")
print("-------------------")

for index, packet in enumerate(packets, start=1):

    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst

        print(f"Packet {index}: {source} -> {destination}")




# Analyze network protocols
packet_types, tcp_count, udp_count = analyze_protocols(packets)

other_count = len(packets) - tcp_count - udp_count


print("\nProtocol Analysis")
print("-----------------")

for index, protocol in enumerate(packet_types, start=1):
    print(f"Packet {index}: {protocol}")

print("\nProtocol Summary")
print("----------------")
print(f"TCP packets: {tcp_count}")
print(f"UDP packets: {udp_count}")
print(f"Other packets: {other_count}")



print("\nPort Analysis")
print("-------------")

for index, packet in enumerate(packets, start=1):

    if TCP in packet:
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        protocol = "TCP"

    elif UDP in packet:
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        protocol = "UDP"

    else:
        continue

    print(
        f"Packet {index} ({protocol}): "
        f"{source_port} -> {destination_port}"
    )


print("\nSource IP Summary")
print("-----------------")

source_counts = {}

for packet in packets:

    if IP in packet:
        source = packet[IP].src

        source_counts[source] = source_counts.get(source, 0) + 1

for ip, count in source_counts.items():
    print(f"{ip}: {count} packets")


print("\nMost Active Source IP")
print("---------------------")

if source_counts:
    most_active_ip = max(
        source_counts,
        key=source_counts.get
    )

    packet_count = source_counts[most_active_ip]

    print(f"IP Address: {most_active_ip}")
    print(f"Packets Sent: {packet_count}")
else:
    print("No IPv4 source addresses found.")


print("\nDestination IP Summary")
print("----------------------")

destination_counts = {}

for packet in packets:

    if IP in packet:
        destination = packet[IP].dst

        destination_counts[destination] = (
            destination_counts.get(destination, 0) + 1
        )

for ip, count in destination_counts.items():
    print(f"{ip}: {count} packets")


print("\nMost Contacted Destination IP")
print("-----------------------------")

if destination_counts:

    highest_count = max(destination_counts.values())

    for ip, count in destination_counts.items():
        if count == highest_count:
            print(f"IP Address: {ip}")
            print(f"Packets Received: {count}")
else:
    print("No IPv4 destination addresses found.")


# Time-window-based TCP SYN scan detection
print("\nPotential Port Scan Detection")
print("-----------------------------")

threshold = 5
window_seconds = 60

scan_attempts = defaultdict(set)

for packet in packets:
    if IP not in packet or TCP not in packet:
        continue

    flags = int(packet[TCP].flags)

    is_syn = bool(flags & 0x02)
    is_ack = bool(flags & 0x10)

    if is_syn and not is_ack:
        source = packet[IP].src
        destination = packet[IP].dst
        port = int(packet[TCP].dport)

        # Group timestamps into fixed 60-second windows
        window_id = int(float(packet.time) // window_seconds)

        key = (source, destination, window_id)
        scan_attempts[key].add(port)

scan_findings = []

for (source, destination, window_id), ports in sorted(
    scan_attempts.items()
):
    if len(ports) >= threshold:
        finding = {
            "source": source,
            "destination": destination,
            "unique_ports": len(ports),
            "ports": sorted(ports),
            "window_seconds": window_seconds,
            "window_start_unix": window_id * window_seconds
        }

        scan_findings.append(finding)

        print("Potential TCP SYN port scan detected!")
        print(f"Source: {source}")
        print(f"Destination: {destination}")
        print(f"Unique destination ports: {len(ports)}")
        print(f"Ports: {sorted(ports)}")

if not scan_findings:
    print("No potential TCP SYN port scans detected.")



# Generate a network traffic report
print("\nGenerating NetLens Report...")

# Create the reports folder if necessary
report_dir = (
    Path(__file__).resolve().parent.parent / "reports"
)

report_dir.mkdir(exist_ok=True)


# Generate a report filename based on the PCAP
report_filename = f"{pcap_path.stem}_summary.txt"

report_path = report_dir / report_filename


# Build the report
report_lines = [
    "NETLENS — NETWORK TRAFFIC REPORT",
    "================================",
    "",
    f"Capture: {pcap_path.name}",
    "",
    "TRAFFIC OVERVIEW",
    "----------------",
    f"Total Packets: {len(packets)}",
    f"TCP Packets: {tcp_count}",
    f"UDP Packets: {udp_count}",
    f"Other Packets: {other_count}",
    "",
    "SOURCE IP SUMMARY",
    "-----------------"
]

for ip, count in source_counts.items():
    report_lines.append(f"{ip}: {count} packets")

report_lines.extend([
    "",
    "DESTINATION IP SUMMARY",
    "----------------------"
])

for ip, count in destination_counts.items():
    report_lines.append(f"{ip}: {count} packets")

report_lines.extend([
    "",
    "Note: Packet counts alone do not establish malicious activity."
])


# Add detection findings to the text report
report_lines.extend([
    "",
    "POTENTIAL PORT SCAN FINDINGS",
    "----------------------------"
])

if scan_findings:
    for finding in scan_findings:
        report_lines.append(
            f"Source: {finding['source']} | "
            f"Destination: {finding['destination']} | "
            f"Unique ports: {finding['unique_ports']} | "
            f"Window: {finding['window_seconds']} seconds | "
            f"Ports: {finding['ports']}"
        )
else:
    report_lines.append(
        "No potential TCP SYN port scans detected."
    )



# Save the report
report_path.write_text(
    "\n".join(report_lines) + "\n",
    encoding="utf-8"
)

print(f"Report saved to: {report_path}")



# Generate JSON report
print("\nGenerating JSON Report...")

json_report = {
    "capture": pcap_path.name,
    "total_packets": len(packets),
    "protocol_counts": {
        "TCP": tcp_count,
        "UDP": udp_count,
        "Other": len(packets) - tcp_count - udp_count
    },
    "source_ip_counts": source_counts,
    "destination_ip_counts": destination_counts,
    "scan_findings": scan_findings
}

json_filename = f"{pcap_path.stem}_summary.json"
json_path = report_dir / json_filename

json_path.write_text(
    json.dumps(json_report, indent=2) + "\n",
    encoding="utf-8"
)

print(f"JSON report saved to: {json_path}")



