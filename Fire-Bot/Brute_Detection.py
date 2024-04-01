import json
from collections import deque
from datetime import datetime, timedelta

class FailedLoginDetector:
    def __init__(self, window_size, threshold, time_interval):
        self.window = deque(maxlen=window_size)
        self.threshold = threshold
        self.time_interval = time_interval

    def detect_brute_force(self, timestamp, ip_address):
        current_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")

        # Remove expired entries from the window
        while self.window and current_time - self.window[0][0] > self.time_interval:
            self.window.popleft()

        # Add current login attempt to the window
        self.window.append((current_time, ip_address))

        # Check if failed login attempts exceed the threshold within the time interval
        ip_count = sum(1 for _, ip in self.window if ip == ip_address)
        if ip_count >= self.threshold:
            return True
        return False

# Read data from JSON file

def detect_brute_force_attacks(log_entries_file):
    # Read data from JSON file
    with open(r'E:\Fire-bot\Fire-Bot\Login._Log.json', 'r') as file:
        data = json.load(file)

    login_attempts = data["log_entries"]

    # Parameters for detector
    window_size = 5  # Number of recent login attempts to consider
    threshold = 5    # Threshold for failed login attempts within the time interval
    time_interval = timedelta(minutes=5)  # Time interval for analysis

    # Initialize detector
    detector = FailedLoginDetector(window_size, threshold, time_interval)

    brute_force_attacks = []
    for attempt in login_attempts:
        if attempt["event_type"] == "login_attempt" and attempt["status"] == "failed":
            timestamp = attempt["timestamp"]
            ip_address = attempt["ip_address"]
            if detector.detect_brute_force(timestamp, ip_address):
                brute_force_attacks.append((timestamp, ip_address))

    return brute_force_attacks