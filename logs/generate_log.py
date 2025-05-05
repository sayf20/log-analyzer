import random
from datetime import datetime, timedelta
import os

# Ensure the logs directory exists
os.makedirs("logs", exist_ok=True)

ips = ["192.168.1.10", "192.168.1.25", "172.16.0.5", "10.0.0.2", "203.0.113.45", "198.51.100.23"]
users = ["admin", "root", "user", "john", "test", "unknown"]

start_time = datetime.now() - timedelta(days=3)
lines = []

# Generate 200 mixed login attempts
for _ in range(200):
    timestamp = (start_time + timedelta(minutes=random.randint(1, 4320))).strftime("%b %d %H:%M:%S")
    ip = random.choice(ips)
    user = random.choice(users)
    if random.random() < 0.7:
        line = f"{timestamp} myserver sshd[12345]: Failed password for {user} from {ip} port 22 ssh2"
    else:
        line = f"{timestamp} myserver sshd[12345]: Accepted password for {user} from {ip} port 22 ssh2"
    lines.append(line)

# Add brute-force attack attempts
brute_ip = "203.0.113.200"
for _ in range(15):
    timestamp = (start_time + timedelta(minutes=random.randint(3000, 4320))).strftime("%b %d %H:%M:%S")
    lines.append(f"{timestamp} myserver sshd[12345]: Failed password for invalid user hacker from {brute_ip} port 22 ssh2")

# Shuffle and save
random.shuffle(lines)
with open("logs/auth.log", "w") as f:
    f.write("\n".join(lines))