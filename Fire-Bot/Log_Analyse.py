
def analyze_log_file(log_file_path):
    malicious_ip = "198.18.0.20"
    threat_detected = False

    with open(log_file_path, 'r') as file:
        for line in file:
            if line.startswith("Time"):
                time_str = line.split(": ")[1].strip()
                hour = int(time_str.split(":")[0])
                if hour >= 20:  # Check if time is after 8 pm
                    threat_detected = True
            elif line.startswith("Destination IP"):
                destination_ip = line.split(": ")[1].strip()
                if destination_ip == malicious_ip:
                    threat_detected = True

    return threat_detected


log_file_path = "E:\\Fire-bot\\Fire-Bot\\Net_Log.txt"
threat_detected = analyze_log_file(log_file_path)

if threat_detected:
    print("Threat detected! Take necessary action.Login after 8 pm and malicious IP detected")
else:
     print("No threat detected.")
