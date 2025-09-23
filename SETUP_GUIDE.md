# Gmail API OAuth2 Setup Guide

This guide will help you set up Google OAuth2 credentials for your Gmail API Flask application.

## Prerequisites

1. A Google account
2. Access to the Google Cloud Console

## Step-by-Step Setup

### 1. Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" and then "New Project"
3. Enter a project name (e.g., "Gmail API Flask App")
4. Click "Create"

### 2. Enable Gmail API

1. In the Google Cloud Console, navigate to "APIs & Services" > "Library"
2. Search for "Gmail API"
3. Click on "Gmail API" and then "Enable"

### 3. Configure OAuth Consent Screen

1. Go to "APIs & Services" > "OAuth consent screen"
2. Choose "External" user type (unless you have a Google Workspace account)
3. Fill in the required fields:
   - App name: Your app name (e.g., "EZ Mail")
   - User support email: Your email
   - Developer contact information: Your email
4. Click "Save and Continue"
5. On the "Scopes" page, click "Save and Continue" (we'll add scopes later)
6. Add test users if needed (for development)
7. Click "Save and Continue"

### 4. Create OAuth2 Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Choose "Web application"
4. Set the name (e.g., "Gmail Flask Client")
5. Add authorized redirect URIs:
   - `http://localhost:5000/oauth2callback`
   - `http://127.0.0.1:5000/oauth2callback`
6. Click "Create"
7. Copy the Client ID and Client Secret

### 5. Configure Your Application

#### Option 1: Environment Variables (Recommended)
Set these environment variables in your system or create a `.env` file:

```bash
GOOGLE_CLIENT_ID=your-client-id-here
GOOGLE_CLIENT_SECRET=your-client-secret-here
```

#### Option 2: Update config.py
Edit the `config.py` file and replace the placeholder values:

```python
CLIENT_ID = 'your-actual-client-id'
CLIENT_SECRET = 'your-actual-client-secret'
```

### 6. Test Your Setup

1. Run your Flask application:
   ```bash
   python app.py
   ```

2. Open your browser and go to `http://localhost:5000/show_login`

3. Click "Sign in with Google"

4. You should be redirected to Google's OAuth consent screen

5. Grant permissions and you should be redirected back to your app

## Security Notes

- Never commit your Client ID and Client Secret to version control
- Use environment variables or secure configuration management
- For production, configure proper authorized domains and redirect URIs
- Consider implementing HTTPS for production deployments

## Scopes Used

The application requests these Gmail API scopes:
- `gmail.readonly` - Read emails
- `gmail.send` - Send emails
- `userinfo.email` - Get user's email address
- `userinfo.profile` - Get user's profile information

## Troubleshooting

### "redirect_uri_mismatch" Error
- Check that your redirect URI in Google Cloud Console matches exactly: `http://localhost:5000/oauth2callback`
- Make sure there are no trailing slashes or extra characters

### "access_blocked" Error
- Your OAuth consent screen might not be verified
- Add your email as a test user in the OAuth consent screen
- For production, submit your app for verification

### "invalid_client" Error
- Check that your Client ID and Client Secret are correct
- Ensure they're properly loaded from environment variables or config

## Next Steps

1. Test sending and receiving emails
2. Customize the user interface
3. Add error handling and logging
4. Configure for production deployment
5. Submit for OAuth verification if needed for public use

For more information, visit the [Gmail API documentation](https://developers.google.com/gmail/api).