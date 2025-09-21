from flask import Flask, render_template, request
import smtplib, imaplib, email
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime, parseaddr


app = Flask(__name__)

GMAIL_USER = "kencedrickg@gmail.com"
GMAIL_PASS = "cdwyzyhsdrwntvco"  # 16-char app password

# Home page (send form)
@app.route("/")
def index():
    return render_template("index.html")

# Send email
@app.route("/send", methods=["POST"])
def send():
    to_email = request.form["to"]
    subject = request.form["subject"]
    message = request.form["message"]

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = GMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(GMAIL_USER, GMAIL_PASS)
                server.send_message(msg)
        return render_template("success.html", to_email=to_email)
    except Exception as e:
        return f"Error: {e}"
        

@app.route("/inbox")
def inbox():
    emails = []
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(GMAIL_USER, GMAIL_PASS)
        mail.select("inbox")

        result, data = mail.search(None, "ALL")
        mail_ids = data[0].split()
        latest_ids = mail_ids[-5:]

        for i in reversed(latest_ids):
            result, msg_data = mail.fetch(i, "(BODY.PEEK[HEADER.FIELDS (FROM DATE)])")
            raw_msg = msg_data[0][1]
            msg = email.message_from_bytes(raw_msg)

            # Extract clean name + email
            name, addr = parseaddr(msg["from"])
            sender_name = name if name else addr
            sender_email = f"<{addr}>" if addr else ""

            # Parse date
            date_header = msg["date"]
            try:
                date_obj = parsedate_to_datetime(date_header)
                date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                date_str = date_header

            emails.append({
                "name": sender_name,
                "email": sender_email,
                "date": date_str
            })

        mail.logout()
    except Exception as e:
        emails.append({"name": "System", "email": "", "date": str(e)})

    return render_template("inbox.html", emails=emails)



if __name__ == "__main__":
    app.run(debug=True)
