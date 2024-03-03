# defender_scan.py
import subprocess

def scan_file_with_defender(file_path):
    try:
        # Run Windows Defender scan using MpCmdRun.exe
        command = ['C:\\Program Files\\Windows Defender\\MpCmdRun.exe', '-Scan', '-ScanType', '3', '-File', file_path]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)

        # Check the scan result
        if result.returncode == 0:
            if "No threats detected" in result.stdout:
                return f"File {file_path} is clean."
            else:
                return f"File {file_path} is infected:\n{result.stdout}"
        else:
            return f"Scan failed with error code {result.returncode}:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        return "Scan timed out."
    except Exception as e:
        return f"An error occurred: {e}"
