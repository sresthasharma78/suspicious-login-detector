import csv
from datetime import datetime
import smtplib
from email.message import EmailMessage
import geocoder
import os

# --- EMAIL SETTINGS ---
SENDER_EMAIL = "sharmasrestha78@gmail.com"
SENDER_PASSWORD = "rdtylxctpyxazxun"
RECEIVER_EMAIL = "sharmasrestha78@gmail.com"

def send_email_alert(username, ip_or_location, location, time_str, reason):
    msg = EmailMessage()
    msg['Subject'] = f"Suspicious Login Alert: {reason}"
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    body = (
        f"Suspicious login detected!\n\n"
        f"User: {username}\n"
        f"Time: {time_str}\n"
        f"Location: {location}\n"
        f"Reason: {reason}\n\n"
        f"Please verify if this was you."
    )
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
        print("✅ Email alert sent.")
    except Exception as e:
        print("❌ Failed to send email:", e)

def get_location_from_ip(ip):
    try:
        g = geocoder.ip(ip)
        return f"{g.city or 'Unknown'}, {g.country or 'Unknown'}"
    except:
        return "Unknown, Unknown"

# --- Main Analyzer Logic ---
print("\n📊 Analyzing login history...\n")

login_log = 'logins.txt'
suspicious_log = 'suspicious_logins.csv'
last_login = {}

# ✅ Create suspicious_logins.csv with header ONLY if it doesn't exist
if not os.path.exists(suspicious_log):
    with open(suspicious_log, mode='w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Username', 'Time', 'Location', 'Reason'])

with open(login_log, 'r') as file:
    for line in file:
        if not line.strip():
            continue
        try:
            parts = line.strip().split(',')
            if len(parts) < 3:
                print(f"⚠️ Skipping invalid entry: {line.strip()} -> too few values")
                continue

            username = parts[0].strip()
            timestamp_str = parts[1].strip()
            ip_or_location = ",".join(parts[2:]).strip()

            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            hour = timestamp.hour

            # --- Determine location ---
            if any(c.isalpha() for c in ip_or_location) and not ip_or_location.replace('.', '').isdigit():
                location = ip_or_location  # e.g., Bangalore, India
            else:
                location = get_location_from_ip(ip_or_location)

            # --- Late Night Detection ---
            is_late_night = 1 <= hour < 5
            is_rapid_login = False
            reason = ""

            if is_late_night:
                print(f"🌙 Late night login: {username} at {timestamp_str} ({location})")
                reason = "Late night login"
                send_email_alert(username, ip_or_location, location, timestamp_str, reason)

                with open(suspicious_log, mode='a', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([username, timestamp_str, location, reason])

            # --- Rapid Login Detection ---
            if username in last_login:
                delta = (timestamp - last_login[username]).total_seconds()
                if 0 < delta <= 300:  # 5 minutes
                    print(f"🚨 Rapid login: {username} logged in again within {int(delta)} seconds!")
                    reason = f"Rapid login (within {int(delta)} seconds)"
                    is_rapid_login = True
                    send_email_alert(username, ip_or_location, location, timestamp_str, reason)

                    with open(suspicious_log, mode='a', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow([username, timestamp_str, location, reason])

            last_login[username] = timestamp

        except Exception as e:
            print(f"⚠️ Skipping invalid entry: {line.strip()} -> {e}")

print(f"\n✅ Suspicious logins saved to: {os.path.abspath(suspicious_log)}")
