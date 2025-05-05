from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
from colorama import Fore, Style, init
init(autoreset=True)


# Step 1: Read log file
with open("logs/auth.log", "r") as file:
    logs = file.readlines()

# 🟢 Part 1: Filter logs for SSH failed login attempts
    
# Step 2: Count failed attempts
failed_attempts = defaultdict(int)
failed_usernames = defaultdict(int)

for line in logs:
    if "Failed password" in line:
        parts = line.split()
        ip_index = parts.index("from") + 1
        ip = parts[ip_index]

        user_index = parts.index("for") + 1
        username = parts[user_index]

        failed_attempts[ip] += 1
        failed_usernames[username] += 1

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


# 🟢 Part 2: Count successful logins

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

# Save report
with open("report.txt", "w") as report_file:
    report_file.write("\n".join(report_lines))


# 🟢 Part 3: Track timestamps of successful logins

successful_login_times = defaultdict(list)

for line in logs:
    if "Accepted password" in line:
        parts = line.split()
        date_str = " ".join(parts[0:3])  # Example: "May  5 12:34:56"
        try:
            timestamp = datetime.strptime(date_str, "%b %d %H:%M:%S")
        except ValueError:
            continue  # Skip malformed lines

        ip_index = parts.index("from") + 1
        ip = parts[ip_index]
        successful_login_times[ip].append(timestamp)


# Prepare report content

report_lines.append("\n👥 Failed Login Usernames:")
for user, count in failed_usernames.items():
    report_lines.append(f"🚫 {user}: {count} failed attempt(s)")

report_lines.append("\n✅ Successful Login Usernames:")
for user, count in successful_usernames.items():
    report_lines.append(f"🔓 {user}: {count} successful login(s)")


report_lines.append("\n✅ Successful SSH Logins:")

for ip, count in successful_logins.items():
    report_lines.append(f"🔓 {ip} — {count} successful login(s)")


report_lines.append("\n🕒 Login Times per IP:")
for ip, times in successful_login_times.items():
    report_lines.append(f"\n🔓 {ip}")
    for t in times:
        report_lines.append(f"   📅 {t.strftime('%b %d %H:%M:%S')}")

# Save report
with open("report.txt", "w") as report_file:
    report_file.write("\n".join(report_lines))


## 🚨  Add CLI Summary Function : You can delete it if you want:

print("\n" + "="*40)
print(Fore.YELLOW + "🔍 CLI SUMMARY VIEW")
print("="*40)

# 🔴 Failed Attempts
print(Fore.RED + "\n❌ Failed Login Attempts by IP:")
for ip, count in failed_attempts.items():
    if count > 3:
        print(Fore.RED + f" {ip} — {count} attempts")
    else:
        print(Fore.LIGHTRED_EX + f"⚠️ {ip} — {count} attempts")

# 🟢 Successful Logins
print(Fore.GREEN + "\n✅ Successful Logins by IP:")
for ip, count in successful_logins.items():
    print(Fore.GREEN + f" {ip} — {count} successful login(s)")

# 👤 Successful Users
print(Fore.CYAN + "\n👤 Successful Users:")
for user, count in successful_usernames.items():
    print(Fore.CYAN + f" {user} — {count} login(s)")

# 🧑‍💻 Failed Users
print(Fore.MAGENTA + "\n🚫 Failed Users:")
for user, count in failed_usernames.items():
    print(Fore.MAGENTA + f" {user} — {count} failed attempt(s)")

print("="*40)
