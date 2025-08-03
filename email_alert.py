import smtplib
from email.message import EmailMessage

def send_email_alert(username, ip, location, time):
    sender_email = "sharmasrestha78@gmail.com"
    sender_password = "rdtylxctpyxazxun"  # App Password
    receiver_email = "sharmasrestha78@gmail.com"

    msg = EmailMessage()
    msg['Subject'] = f"🚨 Suspicious Login Alert for {username}"
    msg['From'] = sender_email
    msg['To'] = receiver_email

    msg.set_content(f"""
    Suspicious login detected!

    👤 User: {username}
    🕒 Time: {time}
    🌐 IP Address: {ip}
    📍 Location: {location}

    Please verify if this was you.
    """)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
        print("✅ Email sent successfully!")
    except Exception as e:
        print("❌ Failed to send email:", e)

