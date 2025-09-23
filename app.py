from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import base64
import json
from datetime import datetime
from email.mime.text import MIMEText

# Google API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Local imports
from config import SCOPES, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SECRET_KEY, DEBUG

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Gmail API helper functions
def get_gmail_service():
    """Get Gmail service using stored credentials from session"""
    if 'credentials' not in session:
        return None
    
    credentials_dict = session['credentials']
    credentials = Credentials(
        token=credentials_dict['token'],
        refresh_token=credentials_dict.get('refresh_token'),
        token_uri=credentials_dict.get('token_uri'),
        client_id=credentials_dict.get('client_id'),
        client_secret=credentials_dict.get('client_secret'),
        scopes=credentials_dict.get('scopes')
    )
    
    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        # Update session with refreshed credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    
    return build('gmail', 'v1', credentials=credentials)

def create_message(to, subject, message_text):
    """Create a message for an email"""
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    message['from'] = session.get('user_email', '')
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

@app.route("/login")
def login():
    """Initiate Gmail OAuth2 login"""
    if 'credentials' in session:
        return redirect(url_for('index'))
    
    # Create OAuth2 flow
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES
    )
    flow.redirect_uri = REDIRECT_URI
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth2 callback from Google"""
    if 'state' not in session or request.args.get('state') != session['state']:
        flash('Invalid state parameter', 'error')
        return redirect(url_for('show_login'))
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI]
            }
        },
        scopes=SCOPES,
        state=session['state']
    )
    flow.redirect_uri = REDIRECT_URI
    
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # Store credentials in session
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Get user info
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        session['logged_in'] = True
        session['user_email'] = user_info.get('email')
        session['user_name'] = user_info.get('name')
        
        flash(f"Login successful! Welcome {user_info.get('name', 'User')}", "success")
        return redirect(url_for('index'))
        
    except Exception as e:
        flash(f"Authentication failed: {str(e)}", "error")
        return redirect(url_for('show_login'))

@app.route("/show_login")
def show_login():
    """Show the login page"""
    return render_template("login.html")

@app.route("/")
def index():
    if not session.get('logged_in'):
        return redirect(url_for('show_login'))
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('show_login'))

@app.route("/send", methods=["POST"])
def send():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    to_email = request.form["to"]
    subject = request.form["subject"]
    message_text = request.form["message"]

    try:
        service = get_gmail_service()
        if not service:
            flash("Gmail service not available. Please log in again.", "error")
            return redirect(url_for('login'))
        
        message = create_message(to_email, subject, message_text)
        result = service.users().messages().send(userId='me', body=message).execute()
        
        flash(f"Email sent successfully to {to_email}", "success")
        return render_template("success.html", to_email=to_email)
        
    except HttpError as error:
        flash(f"Gmail API error: {error}", "error")
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error sending email: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route("/inbox")
def inbox():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    emails = []
    try:
        service = get_gmail_service()
        if not service:
            flash("Gmail service not available. Please log in again.", "error")
            return redirect(url_for('login'))
        
        # Get list of messages
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        
        for msg in messages:
            # Get message details
            message = service.users().messages().get(userId='me', id=msg['id']).execute()
            
            # Extract headers
            payload = message['payload']
            headers = payload.get('headers', [])
            
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            date_header = next((h['value'] for h in headers if h['name'] == 'Date'), '')
            
            # Parse sender
            if '<' in sender and '>' in sender:
                name_part = sender.split('<')[0].strip().strip('"')
                email_part = sender.split('<')[1].split('>')[0]
                sender_name = name_part if name_part else email_part
                sender_email = f"<{email_part}>"
            else:
                sender_name = sender
                sender_email = ""
            
            # Parse date
            try:
                # Simple date parsing - you might want to use dateutil.parser for better parsing
                if date_header:
                    date_str = date_header[:25] if len(date_header) > 25 else date_header
                else:
                    date_str = "Unknown"
            except Exception:
                date_str = date_header
            
            emails.append({
                "name": sender_name,
                "email": sender_email,
                "date": date_str,
                "subject": subject
            })
            
    except HttpError as error:
        emails.append({"name": "System", "email": "", "date": f"Gmail API error: {error}"})
    except Exception as e:
        emails.append({"name": "System", "email": "", "date": f"Error: {str(e)}"})

    return render_template("inbox.html", emails=emails)

@app.route("/debug")
def debug():
    debug_info = {
        "session_data": dict(session),
        "is_logged_in": session.get('logged_in', False),
        "user_email": session.get('user_email', 'None'),
        "user_name": session.get('user_name', 'None'),
        "has_credentials": 'credentials' in session,
        "routes": [rule.rule for rule in app.url_map.iter_rules()]
    }
    return f"<pre>{debug_info}</pre>"

if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5000)
