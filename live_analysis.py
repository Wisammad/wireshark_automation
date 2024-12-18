# live_analysis.py

import time
import subprocess
import pandas as pd
from test_ml_new import predict_anomalies, log_predictions
from preprocessing_live import feature_engineering_with_labels


def live_analysis_workflow(interface, model_path, interval=20):
    while True:
        try:
            output_pcap = 'live_capture.pcap'
            output_csv = 'live_features.csv'
            predictions_csv = 'predictions.csv'

            # Capture live packets using tcpdump
            print("Capturing live packets...")
            capture_command = ['sudo', 'tcpdump', '-i', interface, '-w', output_pcap, '-G', str(interval), '-W', '1']
            subprocess.run(capture_command, check=True)

            # Process pcap file using C program
            print("Processing pcap file using C program...")
            subprocess.run(['./preprocessing_parallel', output_pcap], check=True)

            # Read CSV file generated by C program
            print("Reading processed data...")
            processed_data = pd.read_csv(output_csv)

            # Perform feature engineering
            print("Performing feature engineering...")
            processed_data = feature_engineering_with_labels(processed_data)

            # Predict anomalies
            print("Predicting anomalies...")
            predictions = predict_anomalies(processed_data, model_path)

            # Log predictions and print anomalies
            print("Logging predictions...")
            log_predictions(predictions, output_file=predictions_csv)

        except KeyboardInterrupt:
            print("Live analysis stopped.")
            break
        except subprocess.CalledProcessError as e:
            print(f"Subprocess error: {e}")
        except Exception as e:
            print(f"Error during live analysis: {e}")
        
        print(f"Waiting for {interval} seconds before next capture...\n")
        time.sleep(interval)

if __name__ == "__main__":
    live_analysis_workflow(interface='en0', model_path='anomaly_detection_model_enhanced_synthetic.pkl', interval=20)
