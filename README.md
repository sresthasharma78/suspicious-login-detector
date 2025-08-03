# Suspicious Login Detector 🔐

A Python-based tool to detect suspicious login activities using time, location, and frequency patterns. Ideal for beginner-to-intermediate cybersecurity projects.

## 🔧 Features

- Late night login detection
- Geolocation tracking (auto IP-to-location + direct city/country)
- Rapid login alert (e.g., login from different regions in short span)
- Email alerts
- Gender and location handling from logins
- Automatically skips invalid log entries

## 🗂 Files

- `main.py`: The core script that processes login data and triggers alerts.
- `logins.txt`: Input file with login entries.
- `email_alert.py`: Sends email alerts.
- `geolocation.py`: Converts IPs to city/country using geocoder.
- `suspicious_logins.csv`: Output log of suspicious entries.

## 💡 Example Log Format

Supports both formats:
name, 2025-07-30 01:15:00, 49.47.134.255
name, 2025-07-30 01:15:00, Bangalore, India


## 📌 Project Status

- Working  
- Public and open-source.

---

Created by - Srestha Sharma


