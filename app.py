from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import base64
import json
from datetime import datetime
from email.mime.text import MIMEText
import re
import html as html_lib

# google API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# local imports
from config import SCOPES, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, SECRET_KEY, DEBUG

app = Flask(__name__)
app.secret_key = SECRET_KEY

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' #disable insecure transport for local development

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
        
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    
    return build('gmail', 'v1', credentials=credentials)

def _decode_base64url(data: str) -> str:
    """Decode base64url data to utf-8 text safely."""
    if not data:
        return ""
    # Gmail uses URL-safe base64 without padding
    missing = (-len(data)) % 4
    if missing:
        data = data + ("=" * missing)
    try:
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
    except Exception:
        # As a fallback, try standard b64decode
        return base64.b64decode(data + ("=" * missing)).decode('utf-8', errors='replace')

def _strip_html_to_text(html: str) -> str:
    """Convert HTML to readable plain text (basic, safe)."""
    if not html:
        return ""
    # Remove script/style blocks
    text = re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', '', html)
    # Replace <br> and </p> with line breaks
    text = re.sub(r'(?i)<br\s*/?>', '\n', text)
    text = re.sub(r'(?i)</p\s*>', '\n\n', text)
    # Remove all other tags
    text = re.sub(r'<[^>]+>', '', text)
    # Unescape HTML entities
    text = html_lib.unescape(text)
    # Normalize whitespace
    return text.strip()

def extract_message_plain_text(payload: dict) -> str:
    """Extract the best-effort plain text body from a Gmail message payload.

    Preference order:
    1) text/plain
    2) text/html converted to plain text
    3) payload.body.data (if present)
    """
    if not payload:
        return ""

    # If the payload has a direct body data
    body = payload.get('body', {})
    data = body.get('data')
    if data:
        mime = payload.get('mimeType', '')
        decoded = _decode_base64url(data)
        if mime.lower() == 'text/html':
            return _strip_html_to_text(decoded)
        # Treat everything else as text
        return decoded

    parts = payload.get('parts', [])
    if not parts:
        return ""

    # Helper to collect parts
    plain_candidates = []
    html_candidates = []

    def walk(parts_list):
        for p in parts_list:
            mime = (p.get('mimeType') or '').lower()
            pbody = p.get('body', {})
            pdata = pbody.get('data')
            pparts = p.get('parts')
            if pparts:
                walk(pparts)
            if pdata:
                decoded = _decode_base64url(pdata)
                if mime == 'text/plain':
                    plain_candidates.append(decoded)
                elif mime == 'text/html':
                    html_candidates.append(decoded)

    walk(parts)

    if plain_candidates:
        return plain_candidates[0]
    if html_candidates:
        return _strip_html_to_text(html_candidates[0])
    return ""

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
    
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    
    session.pop('state', None)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Force consent screen to get refresh token
    )
    
    session['state'] = state
    session.permanent = True  # Make session permanent to persist state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth2 callback from Google"""
    # Get state from request
    request_state = request.args.get('state')
    
    # More lenient state validation
    if not request_state:
        flash('Missing state parameter', 'error')
        return redirect(url_for('show_login'))
    
    
    if 'state' in session and request_state != session.get('state'): # Check if we have state in session, if not, proceed anyway (some browsers clear session)
        flash('State parameter mismatch', 'error')
        return redirect(url_for('show_login'))
    
    flow = Flow.from_client_secrets_file(
        'client_secret.json',
        scopes=SCOPES,
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    
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
        session['user_picture'] = user_info.get('picture')
        
        # Clear state from session
        session.pop('state', None)
        
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
    # flash("You have been logged out successfully.", "info")
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
        
        # Get list of messages in inbox
        results = service.users().messages().list(userId='me', maxResults=10, labelIds=['INBOX']).execute()
        messages = results.get('messages', [])
        
        for msg in messages:
            # Get message details
            message = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            
            # Extract headers
            payload = message['payload']
            headers = payload.get('headers', [])
            
            # For inbox, we want to show who sent the email TO us (From header)
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            date_header = next((h['value'] for h in headers if h['name'] == 'Date'), '')
            
            # Parse sender information more reliably
            sender_name = "Unknown Sender"
            sender_email = ""
            
            if sender and sender != 'Unknown Sender':
                # Handle different sender formats:
                # "John Doe <john@example.com>"
                # "john@example.com"
                # "<john@example.com>"
                if '<' in sender and '>' in sender:
                    # Format: "Name <email@domain.com>"
                    email_match = re.search(r'<([^>]+)>', sender)
                    if email_match:
                        email_part = email_match.group(1)
                        name_part = sender.split('<')[0].strip().strip('"').strip()
                        
                        if name_part:
                            sender_name = name_part
                        else:
                            # If no name part, use the part before @ in email
                            sender_name = email_part.split('@')[0] if '@' in email_part else email_part
                        
                        sender_email = f"<{email_part}>"
                else:
                    # Format: just email or just name
                    if '@' in sender:
                        # It's an email address
                        sender_name = sender.split('@')[0]  # Use part before @ as name
                        sender_email = f"<{sender}>"
                    else:
                        # It's just a name
                        sender_name = sender
                        sender_email = ""
            
            # Parse date more reliably
            try:
                if date_header:
                    # Try to parse the date and format it nicely
                    from email.utils import parsedate_to_datetime
                    parsed_date = parsedate_to_datetime(date_header)
                    date_str = parsed_date.strftime('%b %d, %Y %I:%M %p')
                else:
                    date_str = "Unknown Date"
            except Exception:
                # Fallback to truncated original date
                date_str = date_header[:25] if len(date_header) > 25 else date_header or "Unknown Date"
            
            # Extract plain text body
            body_text = extract_message_plain_text(payload)
            if not body_text:
                body_text = message.get('snippet', 'No preview available')
            
            # Limit body text length for display
            if len(body_text) > 200:
                body_text = body_text[:200] + "..."
            
            emails.append({
                "name": sender_name,
                "email": sender_email,
                "date": date_str,
                "subject": subject,
                "body_text": body_text
            })
            
    except HttpError as error:
        flash(f"Gmail API error: {error}", "error")
        emails.append({
            "name": "System Error", 
            "email": "", 
            "date": "Now", 
            "subject": "Gmail API Error",
            "body_text": f"Error fetching emails: {error}"
        })
    except Exception as e:
        flash(f"Error fetching emails: {str(e)}", "error")
        emails.append({
            "name": "System Error", 
            "email": "", 
            "date": "Now", 
            "subject": "Application Error",
            "body_text": f"Error: {str(e)}"
        })

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
