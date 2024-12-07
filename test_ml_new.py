# test_ml_new.py

import pandas as pd
import joblib

def predict_anomalies(processed_data, model_path='anomaly_detection_model_enhanced_synthetic.pkl'):
    """
    Predicts anomalies using the pre-trained ML model.
    """
    # Load the pre-trained model
    model = joblib.load(model_path)
    
    # Define the features expected by the model
    features = ['length', 'src_port', 'dst_port', 'syn_flag', 'ack_flag',
                'rst_flag', 'fin_flag', 'bytes_in_out_ratio', 'protocol']
    
    # Ensure numeric features are numeric
    numeric_cols = ['length', 'src_port', 'dst_port', 'syn_flag',
                    'ack_flag', 'rst_flag', 'fin_flag', 'bytes_in_out_ratio', 'protocol']
    processed_data[numeric_cols] = processed_data[numeric_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Select features
    X = processed_data[features]
    
    # Proceed with prediction
    processed_data['predicted_anomaly'] = model.predict(X)
    return processed_data

def log_predictions(predicted_data, output_file='predictions.csv'):
    """
    Logs predictions to a file and prints anomalies.
    """
    # Save predictions to CSV
    predicted_data.to_csv(output_file, index=False)
    
    # Filter anomalies
    anomalies = predicted_data[predicted_data['predicted_anomaly'] == 1]
    
    # Print anomalies
    if not anomalies.empty:
        print("Anomalies detected:")
        print(anomalies[['time', 'src_ip', 'dst_ip', 'protocol', 'length', 'predicted_anomaly']])
    else:
        print("No anomalies detected.")
