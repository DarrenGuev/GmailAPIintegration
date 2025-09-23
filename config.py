import os

# Gmail API OAuth2 Configuration
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

# OAuth2 credentials from Google Cloud Console
CLIENT_ID = '923464732254-ut8s3jcbtu04o5hb6qh36q0u0gpl5bco.apps.googleusercontent.com'
CLIENT_SECRET = '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'
REDIRECT_URI = 'http://localhost:5000/oauth2callback'

# Path to the OAuth2 credentials JSON file
CREDENTIALS_FILE = 'client_secret.json'

# Flask app configuration
SECRET_KEY = 'your-secret-key-change-this-in-production'
DEBUG = True