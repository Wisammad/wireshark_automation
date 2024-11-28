# preprocessing_live.py

import pandas as pd

# Feature Engineering with Anomaly Detection
def feature_engineering_with_labels(df):
    """
    Feature engineering with anomaly detection logic to label anomalies.
    """
    # Avoid division by zero
    df['bytes_in_out_ratio'] = df['length'] / (df['length'] + 1e-9)
    
    # High bandwidth anomaly
    high_bandwidth_threshold = df['length'].quantile(0.99)
    df['anomaly_bandwidth'] = df['length'] > high_bandwidth_threshold
    
    # Unsuccessful connection attempts
    df['anomaly_unsuccessful'] = (df['syn_flag'] == 1) & (df['ack_flag'] == 0)
    
    # Port scan detection
    df['unique_ports'] = df.groupby('src_ip')['dst_port'].transform('nunique')
    df['anomaly_port_scan'] = df['unique_ports'] > 20
    
    # Aggregate anomaly flags
    df['anomaly'] = (df['anomaly_bandwidth'] | df['anomaly_unsuccessful'] | df['anomaly_port_scan']).astype(int)
    
    # Drop intermediate columns
    return df.drop(columns=['anomaly_bandwidth', 'anomaly_unsuccessful', 'anomaly_port_scan', 'unique_ports'], errors='ignore')
