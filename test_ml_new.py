import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

def predict_anomalies(processed_data, model_path='anomaly_detection_model_nmap10.pkl'):
    """
    Predicts anomalies using the pre-trained ML model.
    """
    model = joblib.load(model_path)
    features = ['length', 'src_port', 'dst_port', 'syn_flag', 'ack_flag', 'rst_flag', 'fin_flag', 'bytes_in_out_ratio', 'protocol']
    X = processed_data[features]
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)
    processed_data['predicted_anomaly'] = model.predict(X)
    return processed_data

def log_predictions(predicted_data, output_file='live_predictions.csv'):
    """
    Logs predictions to a file and prints anomalies.
    """
    predicted_data.to_csv(output_file, index=False)
    anomalies = predicted_data[predicted_data['predicted_anomaly'] == 1]
    if not anomalies.empty:
        print("Anomalies detected:")
        print(anomalies[['time', 'src_ip', 'dst_ip', 'protocol', 'length', 'predicted_anomaly']])
    else:
        print("No anomalies detected.")
