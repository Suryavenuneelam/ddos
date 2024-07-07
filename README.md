# Network Traffic Simulation and Detection

This project simulates network traffic and applies various processing steps such as rate limiting, filtering, anomaly detection, whitelist checking, machine learning-based prediction, and malicious traffic detection.

## Features

- **Traffic Generation**: Generates random network traffic with attributes like source IP, destination IP, and packet size.
- **Traffic Filtering**: Filters out traffic based on certain rules (e.g., packet size and source IP).
- **Rate Limiting**: Limits the rate of traffic to a maximum number of packets per second.
- **Anomaly Detection**: Uses statistical methods (z-scores) to detect anomalies in packet sizes.
- **Whitelist**: Checks if the source IP is in a whitelist.
- **Machine Learning Model**: Uses a RandomForestClassifier to predict if traffic is legitimate or malicious.
- **Malicious Traffic Detection**: Detects and drops malicious traffic based on predefined rules.
- **Traffic Processing Loop**: Simulates traffic generation and applies the various processing steps in a loop. It also keeps track of the generated and dropped traffic over time for plotting.
- **Plotting**: Plots the number of generated and dropped packets over time.
- **Accuracy Calculation**: Calculates and prints the accuracy of generated and dropped traffic.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-traffic-simulation.git
   cd network-traffic-simulation
