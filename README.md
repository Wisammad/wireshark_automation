# Live Network Traffic Anomaly Detection

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Compilation](#compilation)
- [Usage](#usage)
  - [Running the Live Analysis](#running-the-live-analysis)
- [Project Structure](#project-structure)
  - [Python Scripts](#python-scripts)
    - [`live_analysis.py`](#live_analysispy)
    - [`preprocessing_live.py`](#preprocessing_livepy)
    - [`test_ml_new.py`](#test_ml_newpy)
    - [`creating_ml.py`](#creating_mlpy)
  - [C Program](#c-program)
    - [`preprocessing_parallel.c`](#preprocessing_parallelc)
- [Machine Learning Model](#machine-learning-model)
- [Dataset](#dataset)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Overview

The **Live Network Traffic Anomaly Detection** project is a high-performance computing (HPC) application designed to monitor and analyze live network traffic in real-time. By leveraging parallel processing techniques with **MPI** and **OpenMP**, the system efficiently captures, processes, and analyzes network packets to detect anomalies indicative of potential cyber threats.

## Features

- **Real-Time Packet Capture:** Utilizes `tcpdump` to capture live network traffic.
- **Parallel Packet Processing:** Implements a C program with MPI and OpenMP for efficient packet feature extraction.
- **Feature Engineering:** Enhances raw packet data with engineered features for improved anomaly detection.
- **Machine Learning Integration:** Employs a pre-trained Random Forest classifier to identify anomalous traffic patterns.
- **Automated Workflow:** Orchestrates the entire pipeline through a Python script, ensuring seamless operation.

## Architecture

The project consists of the following components:

1. **Packet Capture:** Uses `tcpdump` to capture network packets and save them to a `.pcap` file.
2. **Packet Processing:** A C program (`preprocessing_parallel`) processes the `.pcap` file, extracting relevant features and exporting them to a CSV file.
3. **Feature Engineering:** Enhances the extracted features to better represent network behavior.
4. **Anomaly Detection:** Applies a trained Random Forest model to predict anomalies in the network traffic.
5. **Logging:** Records predictions and highlights detected anomalies for further analysis.

## Getting Started

### Prerequisites

Ensure the following software is installed on your system:

- **Operating System:** macOS (tested) or Linux.
- **Python:** Version 3.6 or higher.
- **C Compiler:** GCC with OpenMP support.
- **MPI Implementation:** Open MPI.
- **Libraries and Tools:**
  - `tcpdump`
  - `libpcap`
  - Python packages: `pandas`, `joblib`, `scikit-learn`

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/live-network-anomaly-detection.git
   cd live-network-anomaly-detection
   ```

2. **Install Python Dependencies:**

   It's recommended to use a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install pandas joblib scikit-learn
   ```

3. **Install Open MPI and GCC (with OpenMP) via Homebrew (macOS):**

   ```bash
   brew update
   brew install open-mpi gcc libpcap
   ```

   **Note:** Ensure that `mpirun` and `gcc` are accessible in your `PATH`.

### Compilation

1. **Compile the C Program with MPI and OpenMP Support:**

   Navigate to the directory containing `preprocessing_parallel.c` and compile:

   ```bash
   mpicc -fopenmp -o preprocessing_parallel preprocessing_parallel.c -lpcap
   ```

   **Explanation:**

   - `mpicc`: MPI C compiler wrapper.
   - `-fopenmp`: Enables OpenMP support for multi-threading.
   - `-o preprocessing_parallel`: Specifies the output executable name.
   - `preprocessing_parallel.c`: C source file.
   - `-lpcap`: Links the `libpcap` library for packet processing.

2. **Verify Compilation:**

   Ensure the executable `preprocessing_parallel` is created:

   ```bash
   ls -l preprocessing_parallel
   ```

## Usage

### Running the Live Analysis

The primary workflow is managed by the `live_analysis.py` script, which orchestrates packet capture, processing, feature engineering, anomaly detection, and logging.

1. **Ensure Permissions for `tcpdump`:**

   `tcpdump` requires elevated privileges. You can run the Python script with `sudo` or configure `tcpdump` for passwordless execution.

   **Running with `sudo`:**

   ```bash
   sudo python live_analysis.py
   ```

   **Note:** Be cautious when running scripts with `sudo` due to security implications.

2. **Execute the Python Script:**

   ```bash
   python live_analysis.py
   ```

   **Parameters:**

   - **Interface:** Network interface to monitor (e.g., `en0`, `eth0`).
   - **Model Path:** Path to the pre-trained ML model (`anomaly_detection_model_enhanced_synthetic.pkl`).
   - **Interval:** Time interval (in seconds) between captures (default: 20 seconds).

   **Example:**

   ```bash
   python live_analysis.py
   ```

3. **Monitor Outputs:**

   - **Captured Packets:** Saved as `live_capture.pcap`.
   - **Processed Features:** Saved as `live_features.csv`.
   - **Anomaly Predictions:** Saved as `predictions.csv`.

   **Console Output:**

   The script prints the progress of each step and reports any detected anomalies.

4. **Stopping the Workflow:**

   Press `Ctrl + C` to gracefully terminate the live analysis.

## Project Structure

### Python Scripts

#### `live_analysis.py`

Manages the end-to-end workflow of capturing, processing, feature engineering, anomaly detection, and logging.

**Key Steps:**

1. **Packet Capture:** Uses `tcpdump` to capture network packets.
2. **Packet Processing:** Invokes the MPI-enabled C program to extract features from captured packets.
3. **Feature Engineering:** Enhances extracted features for better anomaly detection.
4. **Anomaly Prediction:** Applies the pre-trained Random Forest model to predict anomalies.
5. **Logging:** Saves predictions and highlights detected anomalies.

**Usage:**

```bash
python live_analysis.py
```

#### `preprocessing_live.py`

Contains the `feature_engineering_with_labels` function, which enriches raw packet features with engineered features to aid anomaly detection.

**Features Engineered:**

- **Bytes In/Out Ratio:** Ratio of packet length to total bytes.
- **High Bandwidth Anomaly:** Flags packets exceeding the 99th percentile in length.
- **Unsuccessful Connection Attempts:** Identifies SYN packets without corresponding ACKs.
- **Port Scan Detection:** Detects sources accessing more than 20 unique destination ports.

**Example:**

```python
import pandas as pd
from preprocessing_live import feature_engineering_with_labels

df = pd.read_csv('live_features.csv')
df = feature_engineering_with_labels(df)
```

#### `test_ml_new.py`

Handles loading the pre-trained ML model, performing anomaly predictions, and logging the results.

**Functions:**

- `predict_anomalies`: Loads the model and predicts anomalies based on processed features.
- `log_predictions`: Saves predictions to a CSV file and prints detected anomalies.

**Usage:**

```python
from test_ml_new import predict_anomalies, log_predictions

processed_data = pd.read_csv('live_features.csv')
predictions = predict_anomalies(processed_data, model_path='anomaly_detection_model_enhanced_synthetic.pkl')
log_predictions(predictions, output_file='predictions.csv')
```

#### `creating_ml.py`

Script for training the Random Forest classifier on a synthetic dataset and saving the trained model.

**Workflow:**

1. **Load Dataset:** Reads `enhanced_synthetic_dataset.csv`.
2. **Preprocessing:** Encodes categorical features and handles missing values.
3. **Model Training:** Trains a Random Forest classifier.
4. **Evaluation:** Outputs classification reports and confusion matrices.
5. **Model Saving:** Saves the trained model as `anomaly_detection_model_enhanced_synthetic.pkl`.

**Usage:**

```bash
python creating_ml.py
```

### C Program

#### `preprocessing_parallel.c`

A high-performance C program that processes `.pcap` files to extract relevant packet features. Utilizes **MPI** for distributed processing across multiple processes and **OpenMP** for multi-threading within each process.

**Key Components:**

1. **Packet Feature Extraction:**
   - Timestamp, protocol, length, source/destination IPs and ports, TCP flags.
2. **Parallel Processing:**
   - **MPI:** Distributes packet processing across multiple processes.
   - **OpenMP:** Further parallelizes processing within each MPI process.
3. **CSV Output:**
   - Aggregates processed features into CSV files (`live_features_rank_<rank>.csv`).

**Compilation:**

```bash
mpicc -fopenmp -o preprocessing_parallel preprocessing_parallel.c -lpcap
```

**Execution:**

Invoked by the Python script using `mpirun` with a specified number of processes (e.g., 4).

```bash
mpirun -np 4 ./preprocessing_parallel live_capture.pcap
```

**Output:**

- **Rank 0:** Aggregates and writes all processed packet features to `live_features_rank_0.csv`.
- **Other Ranks:** Send their processed data to Rank 0.

## Machine Learning Model

A **Random Forest** classifier trained to detect anomalies in network traffic. The model leverages engineered features to identify patterns indicative of potential cyber threats.

- **Model File:** `anomaly_detection_model_enhanced_synthetic.pkl`
- **Training Script:** `creating_ml.py`
- **Dataset:** `enhanced_synthetic_dataset.csv`

**Features Used:**

- `length`
- `src_port`
- `dst_port`
- `syn_flag`
- `ack_flag`
- `rst_flag`
- `fin_flag`
- `bytes_in_out_ratio`
- `protocol`

**Model Training:**

The model is trained on a synthetic dataset that simulates various network attacks and incorporates realistic noise to enhance robustness.

## Dataset

- **File:** `enhanced_synthetic_dataset.csv`
- **Description:** A synthetic dataset combining real-world network traffic with simulated attack patterns and noise, designed to train the anomaly detection model.

**Features:**

- **Raw Features:** Extracted from network packets.
- **Engineered Features:** Additional metrics to aid in anomaly detection.
- **Target Variable:** `anomaly` flag indicating normal or anomalous traffic.

**Usage:**

Used by `creating_ml.py` to train and evaluate the Random Forest classifier.
