from flask import Flask, render_template, request, redirect, url_for, session, flash
import smtplib, imaplib, email
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime, parseaddr


app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

GMAIL_USER = "kencedrickg@gmail.com"
GMAIL_PASS = "cdwyzyhsdrwntvco"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        if email == GMAIL_USER and password == GMAIL_PASS:
            session['logged_in'] = True
            session['user_email'] = email
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        else:
            error_msg = "Invalid email or password. Please try again."
            return render_template("login.html", error=error_msg)
    
    return render_template("login.html")

@app.route("/")
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route("/send", methods=["POST"])
def send():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
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
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
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

            name, addr = parseaddr(msg["from"])
            sender_name = name if name else addr
            sender_email = f"<{addr}>" if addr else ""

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

@app.route("/debug")
def debug():
    debug_info = {
        "session_data": dict(session),
        "is_logged_in": session.get('logged_in', False),
        "user_email": session.get('user_email', 'None'),
        "gmail_user": GMAIL_USER,
        "routes": [rule.rule for rule in app.url_map.iter_rules()]
    }
    return f"<pre>{debug_info}</pre>"

if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)
