from preprocessing_live import capture_live_packets, extract_features_from_pcap, feature_engineering_with_labels
from test_ml_new import predict_anomalies, log_predictions
import time

def live_analysis_workflow(interface, model_path, interval=20):
    while True:
        try:
            output_pcap = 'live_capture.pcap'
            capture_live_packets(interface, output_pcap, duration=interval)
            processed_data = extract_features_from_pcap(output_pcap)
            processed_data = feature_engineering_with_labels(processed_data)
            predictions = predict_anomalies(processed_data, model_path)
            log_predictions(predictions, output_file='live_predictions.csv')
        except KeyboardInterrupt:
            print("Live analysis stopped.")
            break
        except Exception as e:
            print(f"Error during live analysis: {e}")
        time.sleep(interval)


live_analysis_workflow(interface='en0', model_path='anomaly_detection_model_enhanced_synthetic.pkl', interval=20)
