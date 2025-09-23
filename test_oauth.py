#!/usr/bin/env python3
"""
Test script to verify Gmail API OAuth2 setup
Run this script to test if your OAuth2 credentials are working
"""

import os
from google_auth_oauthlib.flow import Flow
from config import SCOPES, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI

def test_oauth_config():
    """Test if OAuth2 configuration is valid"""
    print("Testing Gmail API OAuth2 Configuration...")
    print("-" * 50)
    
    # Check if credentials are set
    if CLIENT_ID == 'your-google-client-id':
        print("❌ CLIENT_ID not configured")
        print("   Please update config.py or set GOOGLE_CLIENT_ID environment variable")
        return False
    else:
        print(f"✅ CLIENT_ID configured: {CLIENT_ID[:20]}...")
    
    if CLIENT_SECRET == 'your-google-client-secret':
        print("❌ CLIENT_SECRET not configured")
        print("   Please update config.py or set GOOGLE_CLIENT_SECRET environment variable")
        return False
    else:
        print(f"✅ CLIENT_SECRET configured: {CLIENT_SECRET[:10]}...")
    
    # Test OAuth flow creation
    try:
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
        print("✅ OAuth2 flow created successfully")
        
        # Generate authorization URL to test configuration
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        print(f"✅ Authorization URL generated")
        print(f"   Redirect URI: {REDIRECT_URI}")
        print(f"   Scopes: {', '.join(SCOPES)}")
        
    except Exception as e:
        print(f"❌ Error creating OAuth2 flow: {e}")
        return False
    
    print("-" * 50)
    print("✅ OAuth2 configuration looks good!")
    print("\nNext steps:")
    print("1. Make sure you've set up your Google Cloud Console project")
    print("2. Run your Flask app: python app.py")
    print("3. Go to http://localhost:5000/show_login")
    print("4. Test the Gmail login")
    
    return True

if __name__ == "__main__":
    test_oauth_config()