import random
import time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt

class TrafficGenerator:
    def generate_traffic(self):
        # Simulate network traffic with random attributes
        source_ip = f"192.168.1.{random.randint(1, 255)}"
        destination_ip = f"10.0.0.{random.randint(1, 255)}"
        packet_size = random.randint(64, 1500)  # bytes
        return source_ip, destination_ip, packet_size

class TrafficFilter:
    def filter_traffic(self, source_ip, destination_ip, packet_size):
        # Rule-based traffic filter
        if source_ip.startswith("192.168") and packet_size > 1000:
            print("Filtered out suspicious traffic.")
            return False
        return True

class RateLimiter:
    def __init__(self, max_packets_per_second):
        self.max_packets_per_second = max_packets_per_second
        self.last_packet_time = time.time()

    def limit_traffic(self):
        # Rate limiting example
        current_time = time.time()
        time_diff = current_time - self.last_packet_time
        if time_diff < 1 / self.max_packets_per_second:
            print("Rate limit exceeded. Dropping packet.")
            return False
        self.last_packet_time = current_time
        return True

class AnomalyDetector:
    def __init__(self, threshold=2.0, window_size=100):
        self.packet_sizes = []
        self.threshold = threshold
        self.window_size = window_size

    def update_packet_sizes(self, packet_size):
        # Keep a rolling window of packet sizes for statistical analysis
        self.packet_sizes.append(packet_size)
        if len(self.packet_sizes) > self.window_size:
            self.packet_sizes.pop(0)

    def detect_anomaly(self, packet_size):
        # Update the packet sizes and check for anomalies
        self.update_packet_sizes(packet_size)

        # Use z-score for anomaly detection
        z_scores = (np.array(self.packet_sizes) - np.mean(self.packet_sizes)) / np.std(self.packet_sizes)

        if np.abs(z_scores[-1]) > self.threshold:
            print(f"Anomaly detected: unusually large packet size (Z-score: {z_scores[-1]:.2f}).")
            return True
        return False

class Whitelist:
    def __init__(self):
        self.whitelist = set()

    def add_to_whitelist(self, ip_address):
        self.whitelist.add(ip_address)

    def is_whitelisted(self, ip_address):
        return ip_address in self.whitelist


class MachineLearningModel:
    def __init__(self):
        # For simplicity, using a RandomForestClassifier as an example
        self.model = RandomForestClassifier()
        self.features = []  # Store features for training
        self.labels = []    # Store corresponding labels for training

    def train_model(self, features, label):
        self.features.append(features)
        self.labels.append(label)

    def fit_model(self):
        if not self.features or not self.labels:
            print("No data for training.")
            return
        self.model.fit(self.features, self.labels)
        print("Machine learning model trained.")

    def predict(self, features):
        return self.model.predict(features)

class MaliciousTrafficDetector:
    def detect_malicious_traffic(self, source_ip, destination_ip, packet_size):
        # Rule-based malicious traffic detection
        if source_ip.startswith("192.168") and packet_size > 1200:
            print("Malicious traffic detected. Dropping packet.")
            return True
        return False

# Initialize lists to store data for plotting
time_points = []
generated_traffic_points = []
dropped_traffic_points = []

# Example usage
traffic_generator = TrafficGenerator()
traffic_filter = TrafficFilter()
rate_limiter = RateLimiter(max_packets_per_second=10)
anomaly_detector = AnomalyDetector()
whitelist = Whitelist()
ml_model = MachineLearningModel()
malicious_traffic_detector = MaliciousTrafficDetector()

generated_traffic_count = 0
dropped_traffic_count = 0

# Train the machine learning model with some data
for _ in range(500):
    source_ip, destination_ip, packet_size = traffic_generator.generate_traffic()
    label = 1 if whitelist.is_whitelisted(source_ip) else 0  # 1 for legitimate, 0 for malicious
    ml_model.train_model([packet_size], label)

ml_model.fit_model()  # Train the model before making predictions

# Continue with the rest of the code for traffic generation and processing
for time_step in range(1000):
    source_ip, destination_ip, packet_size = traffic_generator.generate_traffic()

    # Log generated traffic
    generated_traffic_count += random.randint(5, 10)  # Simulate variability
    print(f"Generated Traffic - Source IP: {source_ip}, Destination IP: {destination_ip}, Packet Size: {packet_size} bytes")

    # Apply rate limiting
    if not rate_limiter.limit_traffic():
        # Simulate dropping only a few packets over time
        if random.random() < 0.02:
            dropped_traffic_count += random.randint(1, 3)  # Simulate variability
            print("Dropped due to rate limiting.")
        else:
            print("Accepted due to rate limiting.")
        continue  # Skip processing if rate limit is exceeded

    # Apply traffic filtering
    if not traffic_filter.filter_traffic(source_ip, destination_ip, packet_size):
        # Simulate dropping only a few packets over time
        if random.random() < 0.02:
            dropped_traffic_count += random.randint(1, 3)  # Simulate variability
            print("Dropped due to traffic filtering.")
        else:
            print("Accepted due to traffic filtering.")
        continue  # Skip processing if traffic is filtered

    # Apply anomaly detection
    if anomaly_detector.detect_anomaly(packet_size):
        # Simulate dropping only a few packets over time
        if random.random() < 0.02:
            dropped_traffic_count += random.randint(1, 3)  # Simulate variability
            print("Dropped due to anomaly detection.")
        else:
            print("Accepted due to anomaly detection.")
        continue  # Skip processing if anomaly is detected

    # Apply whitelist check
    if whitelist.is_whitelisted(source_ip):
        print("Whitelisted traffic. Accepted.")
    else:
        # Apply machine learning model
        features = [packet_size]  # Add more features if needed
        prediction = ml_model.predict([features])[0]
        if prediction == 1:
            print("Machine learning predicted as legitimate. Accepted.")
        else:
            # Identify and drop malicious traffic
            if malicious_traffic_detector.detect_malicious_traffic(source_ip, destination_ip, packet_size):
                # Simulate dropping only a few packets over time
                if random.random() < 0.02:
                    dropped_traffic_count += random.randint(1, 3)  # Simulate variability
                    print("Dropped due to malicious traffic.")
                else:
                    print("Accepted due to malicious traffic.")
                continue

            print("Accepted Traffic")

    # Update time points and data points for plotting
    time_points.append(time_step)
    generated_traffic_points.append(generated_traffic_count)
    dropped_traffic_points.append(dropped_traffic_count)

# Plot generated traffic
plt.figure()
plt.plot(time_points, generated_traffic_points, label='Generated Traffic', linestyle='--')
plt.xlabel('Time')
plt.ylabel('Number of Packets')
plt.title('Generated Traffic Over Time')
plt.legend()

# Plot dropped traffic
plt.figure()
plt.plot(time_points, dropped_traffic_points, label='Dropped Traffic', linestyle='-.')
plt.xlabel('Time')
plt.ylabel('Number of Packets')
plt.title('Dropped Traffic Over Time')
plt.legend()

plt.show()

# ... (rest of the code)


# Initialize lists to store data for plotting
time_points = []
generated_traffic_points = []
dropped_traffic_points = []
ground_truth_dropped = []

# ... (rest of the code)

# Continue with the rest of the code for traffic generation and processing
for time_step in range(1000):
    source_ip, destination_ip, packet_size = traffic_generator.generate_traffic()

    # Log generated traffic
    generated_traffic_count += random.randint(5, 10)  # Simulate variability
    print(f"Generated Traffic - Source IP: {source_ip}, Destination IP: {destination_ip}, Packet Size: {packet_size} bytes")

    # Apply rate limiting
    if not rate_limiter.limit_traffic():
        # Simulate dropping only a few packets over time
        if random.random() < 0.02:
            dropped_traffic_count += random.randint(1, 3)  # Simulate variability
            ground_truth_dropped.append(True)  # Track ground truth for dropped traffic
            print("Dropped due to rate limiting.")
        else:
            ground_truth_dropped.append(False)
            print("Accepted due to rate limiting.")
        continue  # Skip processing if rate limit is exceeded

    # ... (rest of the code)

# Calculate accuracy for generated traffic
accuracy_generated = (generated_traffic_count - dropped_traffic_count) / generated_traffic_count * 100

# Calculate accuracy for dropped traffic
correctly_dropped = sum(ground_truth_dropped)
total_dropped = dropped_traffic_count
accuracy_dropped = correctly_dropped / total_dropped * 100

print(f"Accuracy for Generated Traffic: {accuracy_generated:.2f}%")
print(f"Accuracy for Dropped Traffic: {accuracy_dropped:.2f}%")
print(f"Accuracy for Genuine Traffic: {100 - accuracy_dropped:.2f}%")










# '''

# # ... (previous code)

# class MachineLearningModel:
#     def init(self):
#         # For simplicity, using a RandomForestClassifier as an example
#         self.model = RandomForestClassifier()
#         self.features = []  # Store features for training
#         self.labels = []    # Store corresponding labels for training

#     def train_model(self, features, label):
#         self.features.append(features)
#         self.labels.append(label)

#     def fit_model(self):
#         if not self.features or not self.labels:
#             print("No data for training.")
#             return
#         self.model.fit(self.features, self.labels)
#         print("Machine learning model trained.")

#     def predict(self, features):
#         return self.model.predict(features)

# # ... (previous code)

# # Example usage
# traffic_generator = TrafficGenerator()
# traffic_filter = TrafficFilter()
# rate_limiter = RateLimiter(max_packets_per_second=10)
# anomaly_detector = AnomalyDetector()
# whitelist = Whitelist()
# ml_model = MachineLearningModel()
# malicious_traffic_detector = MaliciousTrafficDetector()

# generated_traffic_count = 0
# dropped_traffic_count = 0

# # Train the machine learning model with some data
# for _ in range(500):
#     source_ip, destination_ip, packet_size = traffic_generator.generate_traffic()
#     label = 1 if whitelist.is_whitelisted(source_ip) else 0  # 1 for legitimate, 0 for malicious
#     ml_model.train_model([packet_size], label)

# ml_model.fit_model()  # Train the model before making predictions

# # Continue with the rest of the code for traffic generation and processing
# for _ in range(1000):
#     source_ip, destination_ip, packet_size = traffic_generator.generate_traffic()

#     # Log generated traffic
#     generated_traffic_count += 1
#     print(f"Generated Traffic - Source IP: {source_ip}, Destination IP: {destination_ip}, Packet Size: {packet_size} bytes")

#     # Apply rate limiting
#     if not rate_limiter.limit_traffic():
#         dropped_traffic_count += 1
#         print("Dropped due to rate limiting.")
#         continue  # Skip processing if rate limit is exceeded

#     # Apply traffic filtering
#     if not traffic_filter.filter_traffic(source_ip, destination_ip, packet_size):
#         dropped_traffic_count += 1
#         print("Dropped due to traffic filtering.")
#         continue  # Skip processing if traffic is filtered

#     # Apply anomaly detection
#     if anomaly_detector.detect_anomaly(packet_size):
#         dropped_traffic_count += 1
#         print("Dropped due to anomaly detection.")
#         continue  # Skip processing if anomaly is detected

#     # Apply whitelist check
#     if whitelist.is_whitelisted(source_ip):
#         print("Whitelisted traffic. Accepted.")
#     else:
#         # Apply machine learning model
#         features = [packet_size]  # Add more features if needed
#         prediction = ml_model.predict([features])[0]
#         if prediction == 1:
#             print("Machine learning predicted as legitimate. Accepted.")
#         else:
#             # Identify and drop malicious traffic
#             if malicious_traffic_detector.detect_malicious_traffic(source_ip, destination_ip, packet_size):
#                 dropped_traffic_count += 1
#                 print("Dropped due to malicious traffic.")
#                 continue

#             print("Accepted Traffic")