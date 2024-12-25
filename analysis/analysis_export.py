import pyshark
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from collections import Counter
import plotly.express as px
from dash import Dash, html, dcc, Input, Output, State, dash_table
import webbrowser
from threading import Timer
from datetime import datetime

import csv
import json

from scapy.all import rdpcap, wrpcap

try:
    import geoip2.database
    geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except ImportError:
    geoip_reader = None
    print("GeoIP library not installed. Location filtering is unavailable.")

original_pcap_path = None

def parse_pcap(file_path):
    try:
        capture = pyshark.FileCapture(file_path, keep_packets=False)
        packet_count = 0
        protocols = Counter()
        packets_data = []
        unique_ips = set()

        print("Processing packets...")
        for packet in capture:
            try:
                protocol = packet.highest_layer
                protocols[protocol] += 1
                packet_count += 1

                src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'

                if src_ip != 'N/A':
                    unique_ips.add(src_ip)
                if dst_ip != 'N/A':
                    unique_ips.add(dst_ip)

                timestamp = getattr(packet, 'sniff_time', None)
                src_port = (getattr(packet[packet.transport_layer], 'srcport', 'N/A')
                            if hasattr(packet, 'transport_layer') else 'N/A')
                dst_port = (getattr(packet[packet.transport_layer], 'dstport', 'N/A')
                            if hasattr(packet, 'transport_layer') else 'N/A')

                length = getattr(packet, 'length', 'N/A')
                full_info = str(packet)

                country = "N/A"
                if geoip_reader and src_ip != 'N/A':
                    try:
                        response = geoip_reader.city(src_ip)
                        country = response.country.name
                    except Exception:
                        pass

                http_method = "N/A"
                if protocol == "HTTP" and hasattr(packet, "http"):
                    http_method = getattr(packet.http, 'request_method', 'N/A')

                is_anomalous = "No"
                if protocol in ["TCP", "UDP"] and length != "N/A" and int(length) > 1500:
                    is_anomalous = "Yes"

                packets_data.append({
                    "Index": packet_count,
                    "Timestamp": timestamp,
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Protocol": protocol,
                    "Source Port": src_port,
                    "Destination Port": dst_port,
                    "Packet Size": length,
                    "Country": country,
                    "HTTP Method": http_method,
                    "Anomalous": is_anomalous,
                    "Full Info": full_info
                })

            except Exception:
                continue

            if packet_count >= 1000:
                break

        capture.close()
        print(f"\nProcessing completed. Packets processed: {packet_count}.")
        return protocols, packets_data, list(unique_ips)

    except Exception as e:
        print(f"Error processing file: {e}")
        return {}, [], []

def export_to_csv(filtered_data, filename="filtered_data.csv"):
    if not filtered_data:
        print("No data available for CSV export.")
        return

    fieldnames = filtered_data[0].keys()
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in filtered_data:
            if row["Timestamp"] and hasattr(row["Timestamp"], "isoformat"):
                row["Timestamp"] = row["Timestamp"].isoformat()
            writer.writerow(row)

    print(f"Data successfully exported to CSV: {filename}")

def export_to_json(filtered_data, filename="filtered_data.json"):
    if not filtered_data:
        print("No data available for JSON export.")
        return

    export_data = []
    for row in filtered_data:
        item = row.copy()
        if item["Timestamp"] and hasattr(item["Timestamp"], "isoformat"):
            item["Timestamp"] = item["Timestamp"].isoformat()
        export_data.append(item)

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, ensure_ascii=False, indent=2)
    print(f"Data successfully exported to JSON: {filename}")

def export_to_pcap(filtered_data, filename="filtered_data.pcap"):
    if not filtered_data:
        print("No data available for PCAP export.")
        return

    if not original_pcap_path:
        print("Original PCAP path is unknown. Export is not possible.")
        return

    filtered_indices = set([p["Index"] for p in filtered_data])
    all_packets = rdpcap(original_pcap_path)

    result_packets = []
    for idx, scapy_pkt in enumerate(all_packets, start=1):
        if idx in filtered_indices:
            result_packets.append(scapy_pkt)

    if not result_packets:
        print("No packets selected for the new PCAP. The PCAP is empty.")
        return

    wrpcap(filename, result_packets)
    print(f"New PCAP successfully saved: {filename}")

def visualize_data(protocols, packets_data, unique_ips):
    app = Dash(__name__)

    fig_protocols = px.pie(values=list(protocols.values()), names=list(protocols.keys()),
                           title="Protocol Distribution")
    fig_unique_ips = px.bar(x=unique_ips, y=[1] * len(unique_ips),
                            title="Unique IP Addresses", labels={"x": "IP", "y": "Count"})
    fig_unique_ips.update_traces(hovertemplate='IP: %{x}')

    app.layout = html.Div(children=[
        html.H1("PCAP File Analysis"),
        html.Div("Filters for the table:", style={'fontSize': '20px', 'marginBottom': '10px'}),
        html.Div([
            dcc.Input(id="filter-src-ip", type="text", placeholder="Source IP",
                      style={'marginRight': '10px', 'width': '15%'}),
            dcc.Input(id="filter-dst-ip", type="text", placeholder="Destination IP",
                      style={'marginRight': '10px', 'width': '15%'}),
            dcc.Input(id="filter-protocol", type="text", placeholder="Protocol",
                      style={'marginRight': '10px', 'width': '15%'}),
            dcc.Input(id="filter-keyword", type="text", placeholder="Keyword (password, login)",
                      style={'marginRight': '10px', 'width': '20%'}),
            dcc.Input(id="filter-size", type="number", placeholder="Packet size > (bytes)",
                      style={'marginRight': '10px', 'width': '15%'}),
            dcc.Input(id="filter-time", type="text", placeholder="Time (e.g., 10:00-11:00)",
                      style={'marginRight': '10px', 'width': '20%'}),
            dcc.Input(id="filter-country", type="text", placeholder="Country",
                      style={'marginRight': '10px', 'width': '15%'}),
            dcc.Input(id="filter-http-method", type="text", placeholder="HTTP Method (GET, POST)",
                      style={'marginRight': '10px', 'width': '20%'}),
            html.Button("Apply Filters", id="apply-filters", n_clicks=0,
                        style={
                            'backgroundColor': '#4CAF50', 'color': 'white', 'border': 'none',
                            'padding': '10px 20px', 'cursor': 'pointer', 'borderRadius': '5px'
                        })
        ], style={'marginBottom': '20px'}),

        html.Div([
            html.Button("Export to CSV", id="export-csv", n_clicks=0,
                        style={'marginRight': '10px', 'backgroundColor': '#008CBA', 'color': 'white'}),
            html.Button("Export to JSON", id="export-json", n_clicks=0,
                        style={'marginRight': '10px', 'backgroundColor': '#f44336', 'color': 'white'}),
            html.Button("Export to PCAP", id="export-pcap", n_clicks=0,
                        style={'backgroundColor': '#FF9800', 'color': 'white'})
        ], style={'marginBottom': '20px'}),

        dcc.Graph(id='protocols-graph', figure=fig_protocols),
        dcc.Graph(id='unique-ips-graph', figure=fig_unique_ips),
        dash_table.DataTable(
            id='packet-table',
            columns=[
                {"name": col, "id": col} for col in [
                    "Index", "Timestamp", "Source IP", "Destination IP", "Protocol",
                    "Source Port", "Destination Port", "Packet Size", "Country",
                    "HTTP Method", "Anomalous"
                ]
            ],
            data=packets_data,
            style_table={'overflowX': 'auto', 'maxHeight': '400px', 'overflowY': 'scroll'},
            style_cell={'textAlign': 'left', 'whiteSpace': 'normal', 'height': 'auto'},
            row_selectable='single'
        ),
        html.Div(id='packet-details', style={
            'whiteSpace': 'pre-wrap',
            'marginTop': '20px',
            'border': '1px solid #ccc',
            'padding': '10px'
        })
    ])

    @app.callback(
        Output('packet-table', 'data'),
        [Input('apply-filters', 'n_clicks'),
         Input('unique-ips-graph', 'clickData')],
        [State('filter-src-ip', 'value'),
         State('filter-dst-ip', 'value'),
         State('filter-protocol', 'value'),
         State('filter-keyword', 'value'),
         State('filter-size', 'value'),
         State('filter-time', 'value'),
         State('filter-country', 'value'),
         State('filter-http-method', 'value')]
    )
    def filter_table(n_clicks, clickData, src_ip, dst_ip, protocol, keyword, size, time_range, country, http_method):
        filtered_data = packets_data

        if clickData is not None:
            clicked_ip = clickData['points'][0]['x']
            filtered_data = [p for p in filtered_data if (
                clicked_ip == p["Source IP"] or clicked_ip == p["Destination IP"]
            )]
            return filtered_data

        if src_ip:
            filtered_data = [p for p in filtered_data if src_ip in p["Source IP"]]

        if dst_ip:
            filtered_data = [p for p in filtered_data if dst_ip in p["Destination IP"]]

        if protocol:
            filtered_data = [p for p in filtered_data if protocol.upper() in p["Protocol"].upper()]

        if keyword:
            filtered_data = [p for p in filtered_data if keyword.lower() in p["Full Info"].lower()]

        if size:
            filtered_data = [p for p in filtered_data if p["Packet Size"] != 'N/A' and int(p["Packet Size"]) > size]

        if time_range:
            try:
                start_time, end_time = time_range.split('-')
                start_time = datetime.strptime(start_time.strip(), "%H:%M").time()
                end_time = datetime.strptime(end_time.strip(), "%H:%M").time()
                filtered_data = [p for p in filtered_data if p["Timestamp"] and start_time <= p["Timestamp"].time() <= end_time]
            except ValueError:
                pass

        if country:
            filtered_data = [p for p in filtered_data if p["Country"] == country]

        if http_method:
            filtered_data = [p for p in filtered_data if p["HTTP Method"] == http_method.upper()]

        return filtered_data

    @app.callback(
        Output('packet-details', 'children'),
        [Input('packet-table', 'selected_rows')],
        [State('packet-table', 'data')]
    )
    def display_packet_details(selected_rows, table_data):
        if selected_rows:
            row_index = selected_rows[0]
            packet = table_data[row_index]

            details_table = html.Table(
                [
                    html.Tr([html.Th("Parameter"), html.Th("Value")]),
                    html.Tr([html.Td("Timestamp"), html.Td(packet.get("Timestamp", "N/A"))]),
                    html.Tr([html.Td("Source IP"), html.Td(packet.get("Source IP", "N/A"))]),
                    html.Tr([html.Td("Destination IP"), html.Td(packet.get("Destination IP", "N/A"))]),
                    html.Tr([html.Td("Protocol"), html.Td(packet.get("Protocol", "N/A"))]),
                    html.Tr([html.Td("Source Port"), html.Td(packet.get("Source Port", "N/A"))]),
                    html.Tr([html.Td("Destination Port"), html.Td(packet.get("Destination Port", "N/A"))]),
                    html.Tr([html.Td("Packet Size"), html.Td(packet.get("Packet Size", "N/A"))]),
                    html.Tr([html.Td("Country"), html.Td(packet.get("Country", "N/A"))]),
                    html.Tr([html.Td("HTTP Method"), html.Td(packet.get("HTTP Method", "N/A"))]),
                    html.Tr([html.Td("Anomalous"), html.Td(packet.get("Anomalous", "N/A"))]),
                ],
                style={
                    'borderCollapse': 'collapse',
                    'width': '100%',
                    'border': '1px solid #ccc',
                    'fontFamily': 'Arial, sans-serif',
                    'lineHeight': '1.5',
                },
            )

            full_info_section = html.Div(
                [
                    html.H4("Full Information"),
                    html.Pre(
                        packet.get("Full Info", "N/A"),
                        style={
                            'backgroundColor': '#f9f9f9',
                            'padding': '10px',
                            'border': '1px solid #ccc',
                            'overflowX': 'auto',
                        },
                    ),
                ]
            )

            return html.Div([details_table, full_info_section])

        return "Select a row to display details."

    @app.callback(
        Output('packet-details', 'children', allow_duplicate=True),
        [Input('export-csv', 'n_clicks'),
         Input('export-json', 'n_clicks'),
         Input('export-pcap', 'n_clicks')],
        [State('packet-table', 'data')],
        prevent_initial_call=True
    )
    def export_data_to_files(csv_clicks, json_clicks, pcap_clicks, table_data):
        ctx = dash.callback_context
        if not ctx.triggered:
            return ""

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]
        filtered_data = table_data

        if button_id == 'export-csv':
            export_to_csv(filtered_data, filename="filtered_data.csv")
            return "Export to CSV completed!"

        elif button_id == 'export-json':
            export_to_json(filtered_data, filename="filtered_data.json")
            return "Export to JSON completed!"

        elif button_id == 'export-pcap':
            export_to_pcap(filtered_data, filename="filtered_data.pcap")
            return "Export to PCAP completed!"

        return ""

    def open_browser():
        webbrowser.open_new("http://127.0.0.1:8050/")

    Timer(1, open_browser).start()
    app.run_server(debug=False)

if __name__ == "__main__":
    root = Tk()
    root.withdraw()
    print("Select a PCAP file...")
    file_path = askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])

    if file_path:
        global original_pcap_path
        original_pcap_path = file_path
        print(f"Selected file: {file_path}")
        protocols, packets_data, unique_ips = parse_pcap(file_path)
        visualize_data(protocols, packets_data, unique_ips)
    else:
        print("No file selected.")
