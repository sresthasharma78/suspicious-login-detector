import csv
from datetime import datetime
from geolocation import get_geolocation

# 🚨 Settings
LATE_NIGHT_START = 1  # 1 AM
LATE_NIGHT_END = 5    # 5 AM
RAPID_LOGIN_THRESHOLD = 600  # seconds (10 minutes)

# 📁 Data structures
suspicious_logins = []
login_history = {}
location_history = {}

# 🕵️ Function to check if time is late night
def is_late_night(timestamp_str):
    try:
        login_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        return LATE_NIGHT_START <= login_time.hour <= LATE_NIGHT_END
    except ValueError:
        return False

# 📂 Parse logins.txt
parsed_logins = []

with open("logins.txt", "r") as file:
    for line in file:
        parts = [p.strip() for p in line.strip().split(",")]
        if len(parts) >= 3:
            username = parts[0]
            timestamp_str = parts[1]
            location_or_ip = parts[2]
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                # Get location from IP if needed
                if location_or_ip.count(".") == 3:
                    location = get_geolocation(location_or_ip)
                else:
                    location = location_or_ip
                parsed_logins.append((username, timestamp, location))
            except ValueError:
                print(f"❌ Skipping malformed line: {line.strip()}")
        else:
            print(f"❌ Skipping malformed line: {line.strip()}")

# 🔀 Sort by time
parsed_logins.sort(key=lambda x: x[1])

# 🔍 Analyze
for username, timestamp, current_location in parsed_logins:
    # First time seeing this user
    if username not in login_history:
        print(f"🆕 First login detected for {username}")
        login_history[username] = []
        location_history[username] = current_location

    # ⏰ Late night login
    if LATE_NIGHT_START <= timestamp.hour <= LATE_NIGHT_END:
        print(f"⏰ Suspicious login time for {username} at {timestamp.strftime('%H:%M')}")
        suspicious_logins.append({
            "username": username,
            "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "location": current_location,
            "reason": "Late-night login"
        })

    # 🔁 Rapid login
    for prev_login in login_history[username]:
        delta = (timestamp - prev_login).total_seconds()
        if 0 < delta <= RAPID_LOGIN_THRESHOLD:
            print(f"🔁 Multiple logins: {username} logged in again within {int(delta)} seconds!")
            suspicious_logins.append({
                "username": username,
                "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "location": current_location,
                "reason": f"Rapid login within {int(delta)} seconds"
            })

    # 📍 Location mismatch
    if current_location != location_history[username]:
        print(f"⚠️ Suspicious login for {username} from new location: {current_location}")
        suspicious_logins.append({
            "username": username,
            "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "location": current_location,
            "reason": "New location detected"
        })

    # ➕ Add current login to history
    login_history[username].append(timestamp)
    login_history[username].sort()  # ✅ Fix for negative seconds issue
    location_history[username] = current_location

# 💾 Save to CSV
with open("suspicious_logins.csv", "w", newline="") as csvfile:
    fieldnames = ["username", "time", "location", "reason"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for entry in suspicious_logins:
        writer.writerow(entry)

print("✅ Analysis complete. Suspicious logins saved to suspicious_logins.csv.")
