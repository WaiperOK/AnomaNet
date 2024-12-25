import pyshark
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from collections import Counter
import plotly.express as px
import plotly.graph_objs as go
from dash import Dash, html, dcc, Input, Output, State, dash_table
import dash
import dash_bootstrap_components as dbc
import webbrowser
from threading import Timer
from datetime import datetime
import pandas as pd
import io
import logging
import numpy as np
import joblib

from analysis.export_results import export_to_csv, export_to_json, export_to_pcap
from training.constants import WELL_KNOWN_PORTS, PROTOCOL_MAPPING

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_pcap(file_path):
    try:
        capture = pyshark.FileCapture(file_path, keep_packets=False)

        packet_count = 0
        protocols = Counter()
        packets_data = []
        unique_ips = set()

        logging.info("Packet processing...")
        for packet in capture:
            try:
                packet_count += 1
                logging.debug(f"Packet processing {packet_count}")

                protocol = packet.highest_layer
                protocols[protocol] += 1
                logging.debug(f"Protocol: {protocol}")

                src_ip = getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                dst_ip = getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A'
                logging.debug(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

                if src_ip != 'N/A':
                    unique_ips.add(src_ip)
                if dst_ip != 'N/A':
                    unique_ips.add(dst_ip)

                timestamp = getattr(packet, 'sniff_time', None)
                logging.debug(f"Timestamp: {timestamp}")

                if hasattr(packet, 'transport_layer') and packet.transport_layer:
                    transport_layer = packet.transport_layer
                    transport_layer_obj = getattr(packet, transport_layer, None)
                    if transport_layer_obj:
                        src_port = getattr(transport_layer_obj, 'srcport', 'N/A')
                        dst_port = getattr(transport_layer_obj, 'dstport', 'N/A')
                        logging.debug(f"Source Port: {src_port}, Destination Port: {dst_port}")
                    else:
                        src_port = 'N/A'
                        dst_port = 'N/A'
                        logging.debug("Transport layer object is None")
                else:
                    src_port = 'N/A'
                    dst_port = 'N/A'
                    logging.debug("No transport layer")

                length = getattr(packet, 'length', None)
                try:
                    length = int(length)
                except (ValueError, TypeError):
                    length = None
                    logging.debug("Length is None or invalid")
                logging.debug(f"Packet Size: {length}")

                try:
                    full_info = str(packet) if packet else "N/A"
                except Exception as e:
                    logging.error(f"Error converting packet to string: {e}")
                    full_info = "N/A"

                country = "N/A"

                http_method = "N/A"
                if protocol == "HTTP" and hasattr(packet, "http"):
                    http_method = getattr(packet.http, 'request_method', 'N/A')
                    if http_method is None:
                        http_method = "N/A"
                logging.debug(f"HTTP Method: {http_method}")

                service_name = "N/A"
                try:
                    s_p = int(src_port) if src_port != 'N/A' else None
                    d_p = int(dst_port) if dst_port != 'N/A' else None
                    if s_p in WELL_KNOWN_PORTS:
                        service_name = WELL_KNOWN_PORTS[s_p]
                    elif d_p in WELL_KNOWN_PORTS:
                        service_name = WELL_KNOWN_PORTS[d_p]
                except ValueError:
                    pass
                logging.debug(f"Service: {service_name}")

                is_anomalous = "No"
                if protocol in ["TCP", "UDP"] and length is not None and length > 1500:
                    is_anomalous = "Yes"
                logging.debug(f"Anomalous: {is_anomalous}")

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
                    "Service": service_name,
                    "Anomalous": is_anomalous,
                    "Attack Prediction": "N/A",
                    "Full Info": full_info
                })

            except Exception as e:
                logging.error(f"Error processing package {packet_count}: {e}")
                continue

            if packet_count >= 1000000:
                logging.info("The limit of 1,000,000 packages has been reached.")
                break

        capture.close()
        logging.info(f"Processing completed. Packets processed: {packet_count}.")
        return protocols, packets_data, list(unique_ips)
    except Exception as e:
        logging.error(f"Error opening file {file_path}: {e}")
        return Counter(), [], []

def load_random_forest_model(model_path='random_forest_model.pkl'):
    try:
        model = joblib.load(model_path)
        logging.info(f"Random Forest model loaded from {model_path}.")
        return model
    except Exception as e:
        logging.error(f"Error loading model: {e}")
        return None

def preprocess_data(packets_data):
    df = pd.DataFrame(packets_data)
    feature_columns = ['Protocol', 'Source Port', 'Destination Port', 'Packet Size']
    df_features = df[feature_columns].copy()
    df_features['Packet Size'] = df_features['Packet Size'].fillna(0)
    df_features['Source Port'] = pd.to_numeric(df_features['Source Port'], errors='coerce').fillna(0).astype(int)
    df_features['Destination Port'] = pd.to_numeric(df_features['Destination Port'], errors='coerce').fillna(0).astype(int)
    df_features['Protocol'] = df_features['Protocol'].astype(str).map(PROTOCOL_MAPPING).fillna(PROTOCOL_MAPPING['Other']).astype(int)
    X = df_features.values
    return X

def visualize_data(protocols, packets_data, unique_ips, original_pcap_path, alerts, model):
    app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
    df_packets = pd.DataFrame(packets_data)

    X = preprocess_data(packets_data)

    if model:
        try:
            predictions = model.predict(X)
            df_packets['Attack Prediction'] = predictions
            df_packets['Attack Prediction'] = df_packets['Attack Prediction'].map({0: 'BENIGN', 1: 'ATTACK'})
            logging.info("Model predictions completed successfully.")
        except Exception:
            df_packets['Attack Prediction'] = 'N/A'
    else:
        logging.error("Model not loaded. Predictions will not be made.")
        df_packets['Attack Prediction'] = 'N/A'

    packets_data = df_packets.to_dict('records')

    fig_protocols = px.pie(
        values=list(protocols.values()),
        names=list(protocols.keys()),
        title="Protocol Distribution"
    )
    fig_unique_ips = px.bar(
        x=unique_ips,
        y=[1] * len(unique_ips),
        title="Unique IP Addresses",
        labels={"x": "IP", "y": "Count"}
    )
    fig_unique_ips.update_traces(hovertemplate='IP: %{x}')

    df_packets['Protocol_Code'] = df_packets['Protocol'].astype('category').cat.codes

    fig_3d_scatter = px.scatter_3d(
        df_packets,
        x='Index',
        y='Packet Size',
        z='Protocol_Code',
        color='Protocol',
        title='3D Scatter Plot: Packet Index vs. Size vs. Protocol',
        labels={'Protocol_Code': 'Protocol'}
    )

    pivot_table = df_packets.pivot_table(
        values='Packet Size',
        index='Index',
        columns='Protocol_Code',
        aggfunc='mean'
    ).fillna(0)
    x_surf, y_surf = np.meshgrid(pivot_table.index.values, pivot_table.columns.values)
    z_surf = pivot_table.values

    fig_3d_surface = go.Figure(
        data=[go.Surface(x=x_surf, y=y_surf, z=z_surf, colorscale='Viridis')]
    )
    fig_3d_surface.update_layout(
        title='3D Surface Plot: Packet Size by Index and Protocol',
        scene=dict(
            xaxis_title='Index',
            yaxis_title='Protocol Code',
            zaxis_title='Packet Size'
        )
    )

    packet_table = dash_table.DataTable(
        id='packet-table',
        columns=[
            {"name": "Index", "id": "Index"},
            {"name": "Timestamp", "id": "Timestamp"},
            {"name": "Source IP", "id": "Source IP"},
            {"name": "Destination IP", "id": "Destination IP"},
            {"name": "Protocol", "id": "Protocol"},
            {"name": "Source Port", "id": "Source Port"},
            {"name": "Destination Port", "id": "Destination Port"},
            {"name": "Packet Size", "id": "Packet Size"},
            {"name": "Country", "id": "Country"},
            {"name": "HTTP Method", "id": "HTTP Method"},
            {"name": "Service", "id": "Service"},
            {"name": "Anomalous", "id": "Anomalous"},
            {"name": "Attack Prediction", "id": "Attack Prediction"},
        ],
        data=packets_data,
        style_table={'overflowX': 'auto', 'maxHeight': '400px', 'overflowY': 'scroll'},
        style_cell={'textAlign': 'left', 'whiteSpace': 'normal', 'height': 'auto'},
        row_selectable='single',
        style_data_conditional=[
            {
                'if': {
                    'filter_query': '{Anomalous} = "Yes"',
                    'column_id': 'Anomalous'
                },
                'backgroundColor': '#FFCDD2',
                'color': 'red',
                'fontWeight': 'bold'
            },
            {
                'if': {
                    'filter_query': '{Attack Prediction} = "ATTACK"',
                    'column_id': 'Attack Prediction'
                },
                'backgroundColor': '#D1C4E9',
                'color': 'purple',
                'fontWeight': 'bold'
            },
        ],
        style_header={
            'backgroundColor': 'rgb(230, 230, 230)',
            'fontWeight': 'bold'
        },
    )

    anomalies_data = [
        packet
        for packet in packets_data
        if packet.get("Anomalous") == "Yes" or packet.get("Attack Prediction") == "ATTACK"
    ]
    anomalies_table = dash_table.DataTable(
        id='anomalies-table',
        columns=[
            {"name": "Index", "id": "Index"},
            {"name": "Timestamp", "id": "Timestamp"},
            {"name": "Source IP", "id": "Source IP"},
            {"name": "Destination IP", "id": "Destination IP"},
            {"name": "Protocol", "id": "Protocol"},
            {"name": "Source Port", "id": "Source Port"},
            {"name": "Destination Port", "id": "Destination Port"},
            {"name": "Packet Size", "id": "Packet Size"},
            {"name": "Country", "id": "Country"},
            {"name": "HTTP Method", "id": "HTTP Method"},
            {"name": "Service", "id": "Service"},
            {"name": "Anomalous", "id": "Anomalous"},
            {"name": "Attack Prediction", "id": "Attack Prediction"},
        ],
        data=anomalies_data,
        style_table={'overflowX': 'auto', 'maxHeight': '400px', 'overflowY': 'scroll'},
        style_cell={'textAlign': 'left', 'whiteSpace': 'normal', 'height': 'auto'},
        row_selectable='single',
        style_data_conditional=[
            {
                'if': {
                    'filter_query': '{Anomalous} = "Yes"',
                    'column_id': 'Anomalous'
                },
                'backgroundColor': '#FFCDD2',
                'color': 'red',
                'fontWeight': 'bold'
            },
            {
                'if': {
                    'filter_query': '{Attack Prediction} = "ATTACK"',
                    'column_id': 'Attack Prediction'
                },
                'backgroundColor': '#D1C4E9',
                'color': 'purple',
                'fontWeight': 'bold'
            },
        ],
        style_header={
            'backgroundColor': 'rgb(230, 230, 230)',
            'fontWeight': 'bold'
        },
    )

    packet_details = html.Div(
        id='packet-details',
        style={
            'whiteSpace': 'pre-wrap',
            'marginTop': '10px',
            'border': '1px solid #ccc',
            'padding': '10px'
        }
    )

    anomaly_details = html.Div(
        id='anomaly-details',
        style={
            'whiteSpace': 'pre-wrap',
            'marginTop': '10px',
            'border': '1px solid #ccc',
            'padding': '10px'
        }
    )

    download_buttons = html.Div([
        dbc.Button(
            "Download CSV",
            id="download-csv-btn",
            n_clicks=0,
            color="warning",
            size="lg",
            style={
                'marginTop': '20px',
                'marginRight': '10px',
                'cursor': 'pointer',
                'borderRadius': '5px'
            }
        ),
        dbc.Button(
            "Download JSON",
            id="download-json-btn",
            n_clicks=0,
            color="primary",
            size="lg",
            style={
                'marginTop': '20px',
                'marginRight': '10px',
                'cursor': 'pointer',
                'borderRadius': '5px'
            }
        ),
        dbc.Button(
            "Download PCAP",
            id="download-pcap-btn",
            n_clicks=0,
            color="purple",
            size="lg",
            style={
                'marginTop': '20px',
                'marginRight': '10px',
                'cursor': 'pointer',
                'borderRadius': '5px'
            }
        ),
    ])

    app.layout = html.Div(children=[
        html.H1("PCAP/PCAPNG File Analysis"),
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
            dbc.Button(
                "Apply Filters",
                id="apply-filters",
                n_clicks=0,
                color="success",
                size="lg",
                style={
                    'marginRight': '10px',
                    'cursor': 'pointer',
                    'borderRadius': '5px'
                }
            )
        ], style={'marginBottom': '20px'}),
        dcc.Graph(id='protocols-graph', figure=fig_protocols),
        dcc.Graph(id='unique-ips-graph', figure=fig_unique_ips),

        html.Div([
            dcc.Graph(id='3d-scatter-plot', figure=fig_3d_scatter),
            dcc.Graph(id='3d-surface-plot', figure=fig_3d_surface)
        ], style={'display': 'flex', 'flexDirection': 'row', 'justifyContent': 'space-around'}),

        packet_table,

        packet_details,

        html.H2("Anomaly Alerts", style={'marginTop': '40px', 'marginBottom': '10px'}),
        anomalies_table,
        anomaly_details,

        download_buttons,
        dcc.Download(id="download-csv"),
        dcc.Download(id="download-json"),
        dcc.Download(id="download-pcap"),
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
            filtered_data = [
                p
                for p in filtered_data
                if (clicked_ip == p["Source IP"] or clicked_ip == p["Destination IP"])
            ]
            return filtered_data

        if src_ip:
            filtered_data = [p for p in filtered_data if src_ip in p["Source IP"]]
        if dst_ip:
            filtered_data = [p for p in filtered_data if dst_ip in p["Destination IP"]]
        if protocol:
            filtered_data = [p for p in filtered_data if protocol.upper() in p["Protocol"].upper()]
        if keyword:
            keyword_lower = keyword.lower()
            filtered_data = [
                p
                for p in filtered_data
                if p["Full Info"] and keyword_lower in p["Full Info"].lower()
            ]
        if size:
            filtered_data = [
                p
                for p in filtered_data
                if p["Packet Size"] is not None and p["Packet Size"] > size
            ]
        if time_range:
            try:
                start_time, end_time = time_range.split('-')
                start_time = datetime.strptime(start_time.strip(), "%H:%M").time()
                end_time = datetime.strptime(end_time.strip(), "%H:%M").time()
                filtered_data = [
                    p
                    for p in filtered_data
                    if p["Timestamp"] and start_time <= p["Timestamp"].time() <= end_time
                ]
            except ValueError:
                pass
        if country:
            filtered_data = [p for p in filtered_data if p["Country"] == country]
        if http_method:
            filtered_data = [
                p
                for p in filtered_data
                if p["HTTP Method"] == http_method.upper()
            ]

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
                    html.Tr([html.Td("Time"), html.Td(packet.get("Timestamp", "N/A"))]),
                    html.Tr([html.Td("Source IP"), html.Td(packet.get("Source IP", "N/A"))]),
                    html.Tr([html.Td("Destination IP"), html.Td(packet.get("Destination IP", "N/A"))]),
                    html.Tr([html.Td("Protocol"), html.Td(packet.get("Protocol", "N/A"))]),
                    html.Tr([html.Td("Source Port"), html.Td(packet.get("Source Port", "N/A"))]),
                    html.Tr([html.Td("Destination Port"), html.Td(packet.get("Destination Port", "N/A"))]),
                    html.Tr([html.Td("Packet Size"), html.Td(packet.get("Packet Size", "N/A"))]),
                    html.Tr([html.Td("Country"), html.Td(packet.get("Country", "N/A"))]),
                    html.Tr([html.Td("HTTP Method"), html.Td(packet.get("HTTP Method", "N/A"))]),
                    html.Tr([html.Td("Service"), html.Td(packet.get("Service", "N/A"))]),
                    html.Tr([html.Td("Anomaly"), html.Td(packet.get("Anomalous", "N/A"))]),
                    html.Tr([html.Td("Attack Prediction"), html.Td(packet.get("Attack Prediction", "N/A"))]),
                ],
                style={
                    'borderCollapse': 'collapse',
                    'width': '100%',
                    'border': '1px solid #ccc',
                    'fontFamily': 'Arial, sans-serif',
                    'lineHeight': '1.5',
                },
            )

            full_info_section = html.Div([
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
            ])

            return html.Div([details_table, full_info_section])

        return "Select a row to display packet details."

    @app.callback(
        Output('anomaly-details', 'children'),
        [Input('anomalies-table', 'selected_rows')],
        [State('anomalies-table', 'data')]
    )
    def display_anomaly_details(selected_rows, table_data):
        if selected_rows:
            row_index = selected_rows[0]
            anomaly = table_data[row_index]

            details_table = html.Table(
                [
                    html.Tr([html.Th("Parameter"), html.Th("Value")]),
                    html.Tr([html.Td("Time"), html.Td(anomaly.get("Timestamp", "N/A"))]),
                    html.Tr([html.Td("Source IP"), html.Td(anomaly.get("Source IP", "N/A"))]),
                    html.Tr([html.Td("Destination IP"), html.Td(anomaly.get("Destination IP", "N/A"))]),
                    html.Tr([html.Td("Protocol"), html.Td(anomaly.get("Protocol", "N/A"))]),
                    html.Tr([html.Td("Source Port"), html.Td(anomaly.get("Source Port", "N/A"))]),
                    html.Tr([html.Td("Destination Port"), html.Td(anomaly.get("Destination Port", "N/A"))]),
                    html.Tr([html.Td("Packet Size"), html.Td(anomaly.get("Packet Size", "N/A"))]),
                    html.Tr([html.Td("Country"), html.Td(anomaly.get("Country", "N/A"))]),
                    html.Tr([html.Td("HTTP Method"), html.Td(anomaly.get("HTTP Method", "N/A"))]),
                    html.Tr([html.Td("Service"), html.Td(anomaly.get("Service", "N/A"))]),
                    html.Tr([html.Td("Anomaly"), html.Td(anomaly.get("Anomalous", "N/A"))]),
                    html.Tr([html.Td("Attack Prediction"), html.Td(anomaly.get("Attack Prediction", "N/A"))]),
                ],
                style={
                    'borderCollapse': 'collapse',
                    'width': '100%',
                    'border': '1px solid #ccc',
                    'fontFamily': 'Arial, sans-serif',
                    'lineHeight': '1.5',
                },
            )

            full_info_section = html.Div([
                html.H4("Full Information"),
                html.Pre(
                    anomaly.get("Full Info", "N/A"),
                    style={
                        'backgroundColor': '#f9f9f9',
                        'padding': '10px',
                        'border': '1px solid #ccc',
                        'overflowX': 'auto',
                    },
                ),
            ])

            return html.Div([details_table, full_info_section])

        return "Select a row to display anomaly details."

    @app.callback(
        Output("download-csv", "data"),
        [Input("download-csv-btn", "n_clicks")],
        [State('packet-table', 'data')],
        prevent_initial_call=True
    )
    def download_csv(n_clicks, current_data):
        if not current_data:
            return dash.no_update
        return dcc.send_data_frame(pd.DataFrame(current_data).to_csv, "filtered_data.csv", index=False)

    @app.callback(
        Output("download-json", "data"),
        [Input("download-json-btn", "n_clicks")],
        [State('packet-table', 'data')],
        prevent_initial_call=True
    )
    def download_json(n_clicks, current_data):
        if not current_data:
            return dash.no_update
        return dcc.send_data_frame(pd.DataFrame(current_data).to_json, "filtered_data.json", orient='records', lines=False)

    @app.callback(
        Output("download-pcap", "data"),
        [Input("download-pcap-btn", "n_clicks")],
        [State('packet-table', 'data')],
        prevent_initial_call=True
    )
    def download_pcap(n_clicks, current_data):
        if not current_data or not original_pcap_path:
            return dash.no_update

        try:
            export_to_pcap(current_data, original_pcap_path, "filtered_data.pcap")

            with open("filtered_data.pcap", "rb") as f:
                pcap_bytes = f.read()

            buffer = io.BytesIO(pcap_bytes)
            buffer.seek(0)

            return dcc.send_bytes(buffer.read, "filtered_data.pcap")
        except Exception as e:
            logging.error(f"Error downloading PCAP: {e}")
            return dash.no_update

    def open_browser():
        webbrowser.open_new("http://127.0.0.1:8050/")

    Timer(1, open_browser).start()
    logging.info("Starting Dash server at http://127.0.0.1:8050/")
    app.run_server(debug=False)

if __name__ == "__main__":
    root = Tk()
    root.withdraw()
    logging.info("Select a PCAP/PCAPNG file...")
    file_path = askopenfilename(filetypes=[("PCAP/PCAPNG Files", "*.pcap *.pcapng"), ("All Files", "*.*")])

    if file_path:
        logging.info(f"Selected file: {file_path}")
        original_pcap_path = file_path
        protocols, packets_data, unique_ips = parse_pcap(file_path)

        model = load_random_forest_model('random_forest_model.pkl')

        if model:
            logging.info("Performing predictions using Random Forest model...")
            X = preprocess_data(packets_data)

            try:
                predictions = model.predict(X)
                df_packets = pd.DataFrame(packets_data)
                df_packets['Attack Prediction'] = predictions
                df_packets['Attack Prediction'] = df_packets['Attack Prediction'].map({0: 'BENIGN', 1: 'ATTACK'})
                packets_data = df_packets.to_dict('records')
                logging.info("Model predictions completed successfully.")
            except Exception:
                for packet in packets_data:
                    packet['Attack Prediction'] = 'N/A'
        else:
            logging.error("Model not loaded. Continuing without predictions.")

        alerts = []
        for packet in packets_data:
            if packet.get("Anomalous") == "Yes" or packet.get("Attack Prediction") == "ATTACK":
                alert = {
                    "Index": packet.get("Index"),
                    "Type": "Anomaly" if packet.get("Anomalous") == "Yes" else "Attack",
                    "Details": f"Anomaly: {packet.get('Anomalous')} | Attack: {packet.get('Attack Prediction')}",
                    "Attack Type": packet.get("Attack Prediction") if packet.get("Attack Prediction") == "ATTACK" else "N/A"
                }
                alerts.append(alert)

        visualize_data(protocols, packets_data, unique_ips, original_pcap_path, alerts, model)
    else:
        logging.info("No file selected.")
