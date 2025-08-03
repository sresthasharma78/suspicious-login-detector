from datetime import datetime
import csv

user_last_location = {}
user_last_time = {}
suspicious_entries = []

with open("logins.txt", "r") as file:
    lines = file.readlines()

print("🔍 Analyzing login history...\n")

for line in lines:
    parts = line.strip().split(", ")
    if len(parts) != 3:
        print(f"❌ Skipping malformed line: {line.strip()}")
        continue

    username, timestamp_str, location = parts
    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"❌ Invalid date format: {timestamp_str}")
        continue

    is_suspicious = False
    reason = []

    # First login
    if username not in user_last_location:
        print(f"🆕 First login detected for {username}")
    else:
        # Location changed
        if user_last_location[username] != location:
            print(f"⚠️ Suspicious login for {username} from new location: {location}")
            is_suspicious = True
            reason.append("New location")

        # Rapid login
        time_diff = (timestamp - user_last_time[username]).total_seconds()
        if time_diff < 60:
            print(f"🚨 Rapid login: {username} logged in again within {int(time_diff)} seconds!")
            is_suspicious = True
            reason.append("Rapid login")

    # Time-based check
    suspicious_hours_start = 1
    suspicious_hours_end = 5
    if suspicious_hours_start <= timestamp.hour <= suspicious_hours_end:
        print(f"⏰ Suspicious login time for {username} at {timestamp.strftime('%H:%M')}")
        is_suspicious = True
        reason.append("Odd login time")

    if is_suspicious:
        suspicious_entries.append([username, timestamp_str, location, "; ".join(reason)])

    # Update tracking
    user_last_location[username] = location
    user_last_time[username] = timestamp

# Save to CSV
if suspicious_entries:
    with open("suspicious_logins.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Timestamp", "Location", "Reason"])
        writer.writerows(suspicious_entries)
    print("\n✅ Suspicious logins saved to suspicious_logins.csv")
else:
    print("\n✅ No suspicious logins found.")
