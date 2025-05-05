from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt


# Step 1: Read log file
with open("logs/auth.log", "r") as file:
    logs = file.readlines()

# Step 2: Count failed attempts
failed_attempts = defaultdict(int)

for line in logs:
    if "Failed password" in line:
        parts = line.split()
        ip_index = parts.index("from") + 1
        ip = parts[ip_index]
        failed_attempts[ip] += 1

# Step 3: Prepare report content
report_lines = []
report_lines.append("🧾 SECURITY REPORT — SSH Failed Login Analysis")
report_lines.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
report_lines.append("🔍 Suspicious IPs (5+ failed attempts):\n")

for ip, count in failed_attempts.items():
    if count > 5:
        report_lines.append(f"🚨 {ip} — {count} failed attempts")

if len(report_lines) == 3:
    report_lines.append("✅ No brute-force attempts detected.\n")

# Step 4: Save report
with open("report.txt", "w") as report_file:
    report_file.write("\n".join(report_lines))

print("✅ Report saved as report.txt")



# Step 5: Filter only IPs with more than 3 failed attempts (to clean up noise)
filtered_attempts = {ip: count for ip, count in failed_attempts.items() if count > 3}

# Step 6: Sort IPs by number of attempts (descending)
sorted_ips = dict(sorted(filtered_attempts.items(), key=lambda x: x[1], reverse=True))

# Step 7: Plot bar chart
plt.figure(figsize=(10, 6))
plt.bar(sorted_ips.keys(), sorted_ips.values(), color="red")
plt.xlabel("IP Addresses")
plt.ylabel("Failed Login Attempts")
plt.title("🔐 SSH Brute-force Detection")
plt.xticks(rotation=45)
plt.tight_layout()

# Step 8: Save the chart as a PNG image
plt.savefig("failed_attempts_chart.png")

print("📊 Chart saved as failed_attempts_chart.png")