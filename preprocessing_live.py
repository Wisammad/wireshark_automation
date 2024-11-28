import pyshark
import pandas as pd
import numpy as np

# Function to load and extract features from .pcap files
def extract_features_from_pcap(file_path):
    """
    Parses a .pcap file using Pyshark and extracts key features for anomaly detection.
    """
    capture = pyshark.FileCapture(file_path)
    data = []

    for packet in capture:
        try:
            packet_info = {
                'time': pd.to_datetime(packet.sniff_time),
                'protocol': packet.highest_layer,
                'length': int(packet.length),
                'src_ip': packet.ip.src if 'IP' in packet else None,
                'dst_ip': packet.ip.dst if 'IP' in packet else None,
                'src_port': int(packet[packet.transport_layer].srcport) if hasattr(packet, 'transport_layer') else None,
                'dst_port': int(packet[packet.transport_layer].dstport) if hasattr(packet, 'transport_layer') else None,
            }

            # Extract TCP flags if the packet is TCP
            if 'TCP' in packet:
                def safe_int(flag_value):
                    if isinstance(flag_value, str) and flag_value.lower() in ['true', 'false']:
                        return int(flag_value.lower() == 'true')
                    return int(flag_value) if flag_value else 0

                packet_info.update({
                    'syn_flag': safe_int(packet.tcp.flags_syn) if hasattr(packet.tcp, 'flags_syn') else 0,
                    'ack_flag': safe_int(packet.tcp.flags_ack) if hasattr(packet.tcp, 'flags_ack') else 0,
                    'rst_flag': safe_int(packet.tcp.flags_reset) if hasattr(packet.tcp, 'flags_reset') else 0,
                    'fin_flag': safe_int(packet.tcp.flags_fin) if hasattr(packet.tcp, 'flags_fin') else 0,
                })
            else:
                packet_info.update({'syn_flag': 0, 'ack_flag': 0, 'rst_flag': 0, 'fin_flag': 0})

            data.append(packet_info)

        except AttributeError:
            continue

    capture.close()
    return pd.DataFrame(data)

# Feature Engineering with Anomaly Detection
def feature_engineering_with_labels(df):
    """
    Feature engineering with anomaly detection logic to label anomalies.
    """
    df['bytes_in_out_ratio'] = df['length'] / (df['length'] + 1e-9)
    high_bandwidth_threshold = df['length'].quantile(0.99)
    df['anomaly_bandwidth'] = df['length'] > high_bandwidth_threshold
    df['anomaly_unsuccessful'] = (df['syn_flag'] == 1) & (df['ack_flag'] == 0)
    df['unique_ports'] = df.groupby('src_ip')['dst_port'].transform('nunique')
    df['anomaly_port_scan'] = df['unique_ports'] > 20
    df['anomaly'] = (df['anomaly_bandwidth'] | df['anomaly_unsuccessful'] | df['anomaly_port_scan']).astype(int)
    return df.drop(columns=['anomaly_bandwidth', 'anomaly_unsuccessful', 'anomaly_port_scan', 'unique_ports'], errors='ignore')

def capture_live_packets(interface, output_file, duration=20):
    """
    Captures live packets from the specified interface for a given duration and saves them to a .pcap file.
    """
    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
    capture.sniff(timeout=duration)
    capture.close()
