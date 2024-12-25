import csv
import json
from scapy.all import rdpcap, wrpcap
import os


def export_to_csv(filtered_data, filename="filtered_data.csv"):
    if not filtered_data:
        print("No data available for CSV export.")
        return

    fieldnames = filtered_data[0].keys()

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for packet in filtered_data:
                if packet.get("Timestamp") and hasattr(packet["Timestamp"], "isoformat"):
                    packet["Timestamp"] = packet["Timestamp"].isoformat()
                writer.writerow(packet)
        print(f"Data successfully exported to CSV: {filename}")
    except Exception as e:
        print(f"Error exporting to CSV: {e}")


def export_to_json(filtered_data, filename="filtered_data.json"):
    if not filtered_data:
        print("No data available for JSON export.")
        return

    export_data = []
    for packet in filtered_data:
        packet_copy = packet.copy()
        if packet_copy.get("Timestamp") and hasattr(packet_copy["Timestamp"], "isoformat"):
            packet_copy["Timestamp"] = packet_copy["Timestamp"].isoformat()
        export_data.append(packet_copy)

    try:
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(export_data, jsonfile, ensure_ascii=False, indent=4)
        print(f"Data successfully exported to JSON: {filename}")
    except Exception as e:
        print(f"Error exporting to JSON: {e}")


def export_to_pcap(filtered_data, original_pcap_path, filename="filtered_data.pcap"):
    if not filtered_data:
        print("No data available for PCAP export.")
        return

    if not os.path.exists(original_pcap_path):
        print(f"Original PCAP file not found: {original_pcap_path}")
        return

    try:
        all_packets = rdpcap(original_pcap_path)
    except Exception as e:
        print(f"Error reading original PCAP file: {e}")
        return

    filtered_indices = set(packet["Index"] for packet in filtered_data)

    result_packets = []
    for idx, pkt in enumerate(all_packets, start=1):
        if idx in filtered_indices:
            result_packets.append(pkt)

    if not result_packets:
        print("No packets available for PCAP export.")
        return

    try:
        wrpcap(filename, result_packets)
        print(f"Packets successfully exported to PCAP: {filename}")
    except Exception as e:
        print(f"Error exporting to PCAP: {e}")
