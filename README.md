# **Network Traffic Anomaly Detection Using Machine Learning**

This project implements a network traffic anomaly detection system leveraging machine learning. It processes `.pcap` files captured using Wireshark, extracts meaningful features, and classifies traffic as normal or anomalous.

## **Features**
- 📄 **Feature Extraction**: Parses `.pcap` files to extract attributes like protocol, flags, packet length, and more.
- 🛠️ **Synthetic Data Generation**: Augments the dataset with realistic attack simulations (e.g., SYN floods, Nmap scans) and natural network noise.
- 🤖 **Machine Learning Model**: A Random Forest classifier trained on a mix of synthetic and real-world data to detect anomalies.
- 🔄 **Real-Time Detection**: Processes live network traffic in specified intervals for real-time anomaly identification.

## **Technologies Used**
- **PyShark**: For packet capture and feature extraction.
- **Pandas**: For data preprocessing and analysis.
- **Scikit-learn**: For machine learning modeling.
- **Wireshark**: For network traffic capture.

## **Installation**
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git](https://github.com/Wisammad/wireshark_automation.git
   cd wireshark_automation
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## **How to Use**
### **1. Feature Extraction**
- Capture network traffic using Wireshark.
- Use the `get_info.py` script to extract features:
   ```bash
   python get_info.py
   ```

### **2. Train the Model**
- Use the `ml.py` script to train the machine learning model on extracted features:
   ```bash
   python ml.py
   ```

### **3. Test the Model**
- Test the trained model on new traffic data using `test_ml.py`:
   ```bash
   python test_ml.py
   ```

### **4. Real-Time Monitoring**
- Enable live traffic analysis by processing network packets at regular intervals using the live capture workflow.

## **Use Cases**
- Detecting SYN flood attacks, Nmap scans, and bandwidth anomalies.
- Training and testing machine learning models on realistic datasets.
- Real-time network monitoring and anomaly detection.

## **Future Enhancements**
- Add support for additional machine learning algorithms.
- Advanced visualization of anomalies for better insights.
- Integrate with other network monitoring tools and systems.

