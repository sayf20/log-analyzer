from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import os

def analyze_log(log_path):
    # Read the log file
    with open(log_path, "r") as file:
        logs = file.readlines()

    # Part 1: Failed login attempts
    failed_attempts = defaultdict(int)
    failed_usernames = defaultdict(int)
    suspicious_ips = defaultdict(int)

    for line in logs:
        if "Failed password" in line:
            parts = line.split()
            ip_index = parts.index("from") + 1
            ip = parts[ip_index]

            user_index = parts.index("for") + 1
            username = parts[user_index]

            failed_attempts[ip] += 1
            failed_usernames[username] += 1

            # Add suspicious IPs with more than 5 failed attempts
            if failed_attempts[ip] > 5:
                suspicious_ips[ip] += 1

    # Part 2: Successful logins
    successful_logins = defaultdict(int)
    successful_usernames = defaultdict(int)

    for line in logs:
        if "Accepted password" in line:
            parts = line.split()
            ip_index = parts.index("from") + 1
            ip = parts[ip_index]

            user_index = parts.index("for") + 1
            username = parts[user_index]

            successful_logins[ip] += 1
            successful_usernames[username] += 1

    # Part 3: Plotting chart for failed attempts
    # Filter IPs with more than 3 failed attempts
    filtered_failed_attempts = {ip: count for ip, count in failed_attempts.items() if count > 3}
    sorted_ips = dict(sorted(filtered_failed_attempts.items(), key=lambda x: x[1], reverse=True))

    plt.figure(figsize=(10, 6))
    plt.bar(sorted_ips.keys(), sorted_ips.values(), color="red")
    plt.xlabel("IP Addresses")
    plt.ylabel("Failed Login Attempts")
    plt.title("🔐 SSH Brute-force Detection")
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the chart as a PNG image
    chart_filename = os.path.join("static", "failed_attempts_chart.png")
    plt.savefig(chart_filename)

    # Return results as a dictionary
    return {
        "failed_attempts": failed_attempts,
        "failed_usernames": failed_usernames,
        "suspicious_ips": suspicious_ips,
        "successful_logins": successful_logins,
        "successful_usernames": successful_usernames,
        "chart_filename": chart_filename,
    }
