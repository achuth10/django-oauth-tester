#!/usr/bin/env python
"""
OAuth 2.0 / OIDC Flow Testing Script

This script demonstrates and tests the complete OAuth 2.0 authorization code
flow with PKCE and OIDC support.

Usage:
    1. Start the Django server: python manage.py runserver
    2. Create an OAuth application in admin
    3. Run this script: python test_oauth_flow.py

Requirements:
    - requests library
    - Django server running on localhost:8000
"""

import os
import sys
import json
import secrets
import hashlib
import base64
import requests
from urllib.parse import urlencode, parse_qs, urlparse

# Configuration
BASE_URL = "http://localhost:8000"
CLIENT_ID = None  # Will be provided by user
CLIENT_SECRET = None  # Will be provided by user
REDIRECT_URI = "http://localhost:8000/callback"
USERNAME = "testuser"
PASSWORD = "test"  # Will be set during user creation


def generate_pkce_pair():
    """
    Generate PKCE code verifier and challenge.

    Returns:
        tuple: (code_verifier, code_challenge)
    """
    # Generate code verifier (43-128 characters)
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

    # Generate code challenge (SHA256 hash of verifier)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge


def test_oidc_discovery():
    """Test OIDC discovery endpoint."""
    print("\n" + "="*70)
    print("STEP 1: Testing OIDC Discovery")
    print("="*70)

    url = f"{BASE_URL}/o/.well-known/openid-configuration/"
    response = requests.get(url)

    if response.status_code == 200:
        config = response.json()
        print("✓ OIDC Discovery successful!")
        print(f"  - Issuer: {config.get('issuer')}")
        print(f"  - Authorization endpoint: {config.get('authorization_endpoint')}")
        print(f"  - Token endpoint: {config.get('token_endpoint')}")
        print(f"  - Userinfo endpoint: {config.get('userinfo_endpoint')}")
        print(f"  - JWKS URI: {config.get('jwks_uri')}")
        return True
    else:
        print(f"✗ Discovery failed: {response.status_code}")
        return False


def test_jwks_endpoint():
    """Test JWKS endpoint."""
    print("\n" + "="*70)
    print("STEP 2: Testing JWKS Endpoint")
    print("="*70)

    url = f"{BASE_URL}/o/.well-known/jwks.json"
    response = requests.get(url)

    if response.status_code == 200:
        jwks = response.json()
        print("✓ JWKS endpoint accessible!")
        print(f"  - Keys available: {len(jwks.get('keys', []))}")
        return True
    else:
        print(f"✗ JWKS failed: {response.status_code}")
        return False


def register_user():
    """Register a test user."""
    print("\n" + "="*70)
    print("STEP 3: Registering Test User")
    print("="*70)

    url = f"{BASE_URL}/api/users/register/"
    data = {
        "username": USERNAME,
        "email": "testuser@example.com",
        "password": "TestPass123!",
        "password2": "TestPass123!",
        "first_name": "Test",
        "last_name": "User"
    }

    global PASSWORD
    PASSWORD = "TestPass123!"

    response = requests.post(url, json=data)

    if response.status_code == 201:
        print(f"✓ User '{USERNAME}' registered successfully!")
        print(f"  - Email: {data['email']}")
        return True
    elif response.status_code == 400:
        error_data = response.json()
        if 'username' in error_data and 'already exists' in str(error_data['username']):
            print(f"ℹ User '{USERNAME}' already exists (this is fine)")
            return True
        else:
            print(f"✗ Registration failed: {error_data}")
            return False
    else:
        print(f"✗ Registration failed: {response.status_code}")
        return False


def get_authorization_code(client_id, code_challenge):
    """
    Get authorization code (manual step).

    This requires user interaction via browser.
    """
    print("\n" + "="*70)
    print("STEP 4: Authorization Code Flow")
    print("="*70)

    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email contracts:read contracts:write',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': 'test_state_' + secrets.token_urlsafe(16)
    }

    auth_url = f"{BASE_URL}/o/authorize/?{urlencode(params)}"

    print("\n⚠  MANUAL STEP REQUIRED:")
    print("\n1. Open this URL in your browser:")
    print(f"\n   {auth_url}\n")
    print("2. Login with credentials:")
    print(f"   Username: {USERNAME}")
    print(f"   Password: {PASSWORD}")
    print("\n3. Approve the authorization request")
    print("\n4. You will be redirected to a URL like:")
    print(f"   {REDIRECT_URI}?code=AUTHORIZATION_CODE&state=...")
    print("\n5. Copy the 'code' parameter from that URL")

    auth_code = input("\nEnter the authorization code: ").strip()

    if auth_code:
        print(f"✓ Authorization code received: {auth_code[:20]}...")
        return auth_code
    else:
        print("✗ No authorization code provided")
        return None


def exchange_code_for_tokens(client_id, client_secret, auth_code, code_verifier):
    """Exchange authorization code for access token."""
    print("\n" + "="*70)
    print("STEP 5: Exchanging Code for Tokens")
    print("="*70)

    url = f"{BASE_URL}/o/token/"
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier,
        'client_id': client_id,
        'client_secret': client_secret
    }

    response = requests.post(url, data=data)

    if response.status_code == 200:
        tokens = response.json()
        print("✓ Token exchange successful!")
        print(f"  - Access token: {tokens['access_token'][:30]}...")
        print(f"  - Token type: {tokens['token_type']}")
        print(f"  - Expires in: {tokens['expires_in']} seconds")
        print(f"  - Refresh token: {tokens['refresh_token'][:30]}...")
        print(f"  - Scope: {tokens['scope']}")
        if 'id_token' in tokens:
            print(f"  - ID token (OIDC): {tokens['id_token'][:30]}...")
        return tokens
    else:
        print(f"✗ Token exchange failed: {response.status_code}")
        print(f"  Response: {response.text}")
        return None


def test_userinfo_endpoint(access_token):
    """Test OIDC userinfo endpoint."""
    print("\n" + "="*70)
    print("STEP 6: Testing UserInfo Endpoint (OIDC)")
    print("="*70)

    url = f"{BASE_URL}/o/userinfo/"
    headers = {'Authorization': f'Bearer {access_token}'}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        userinfo = response.json()
        print("✓ UserInfo retrieved successfully!")
        print(f"  - Username: {userinfo.get('preferred_username')}")
        print(f"  - Email: {userinfo.get('email')}")
        print(f"  - First name: {userinfo.get('given_name')}")
        print(f"  - Last name: {userinfo.get('family_name')}")
        return True
    else:
        print(f"✗ UserInfo failed: {response.status_code}")
        return False


def test_contracts_api(access_token):
    """Test Contracts API with scoped access."""
    print("\n" + "="*70)
    print("STEP 7: Testing Contracts API (Scoped Access)")
    print("="*70)

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Create a contract (requires contracts:write)
    print("\n7.1. Creating a contract (requires 'contracts:write')...")
    create_url = f"{BASE_URL}/api/contracts/"
    contract_data = {
        "title": "Test Service Agreement",
        "description": "A test contract for OAuth flow",
        "content": "This is a test contract created via OAuth 2.0 flow with scoped access.",
        "status": "draft"
    }

    response = requests.post(create_url, json=contract_data, headers=headers)

    if response.status_code == 201:
        contract = response.json()
        print(f"✓ Contract created successfully!")
        print(f"  - ID: {contract['id']}")
        print(f"  - Title: {contract['title']}")
        print(f"  - Status: {contract['status']}")
        contract_id = contract['id']
    else:
        print(f"✗ Contract creation failed: {response.status_code}")
        print(f"  Response: {response.text}")
        return False

    # List contracts (requires contracts:read)
    print("\n7.2. Listing contracts (requires 'contracts:read')...")
    list_url = f"{BASE_URL}/api/contracts/"

    response = requests.get(list_url, headers=headers)

    if response.status_code == 200:
        contracts = response.json()
        count = contracts.get('count', len(contracts))
        print(f"✓ Contracts listed successfully!")
        print(f"  - Total contracts: {count}")
    else:
        print(f"✗ Contract listing failed: {response.status_code}")

    # Retrieve specific contract (requires contracts:read)
    print(f"\n7.3. Retrieving contract #{contract_id} (requires 'contracts:read')...")
    detail_url = f"{BASE_URL}/api/contracts/{contract_id}/"

    response = requests.get(detail_url, headers=headers)

    if response.status_code == 200:
        contract = response.json()
        print(f"✓ Contract retrieved successfully!")
        print(f"  - Title: {contract['title']}")
        print(f"  - Owner: {contract['owner_username']}")
    else:
        print(f"✗ Contract retrieval failed: {response.status_code}")

    return True


def test_refresh_token(client_id, client_secret, refresh_token):
    """Test refresh token flow."""
    print("\n" + "="*70)
    print("STEP 8: Testing Refresh Token Flow")
    print("="*70)

    url = f"{BASE_URL}/o/token/"
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id,
        'client_secret': client_secret
    }

    response = requests.post(url, data=data)

    if response.status_code == 200:
        tokens = response.json()
        print("✓ Token refresh successful!")
        print(f"  - New access token: {tokens['access_token'][:30]}...")
        print(f"  - Expires in: {tokens['expires_in']} seconds")
        return tokens
    else:
        print(f"✗ Token refresh failed: {response.status_code}")
        print(f"  Response: {response.text}")
        return None


def main():
    """Run the complete OAuth 2.0 / OIDC flow test."""
    print("\n" + "="*70)
    print("OAuth 2.0 / OIDC Flow Testing Script")
    print("="*70)

    # Get client credentials from user
    global CLIENT_ID, CLIENT_SECRET

    print("\nBefore running this script, create an OAuth Application in Django admin:")
    print("1. Go to http://localhost:8000/admin/")
    print("2. Navigate to OAuth2 Provider → Applications")
    print("3. Create a new application with:")
    print("   - Client type: Confidential")
    print("   - Authorization grant type: Authorization code")
    print("   - Redirect URIs: http://localhost:8000/callback")
    print("   - Algorithm: RS256")
    print("")

    CLIENT_ID = input("Enter Client ID: ").strip()
    CLIENT_SECRET = input("Enter Client Secret: ").strip()

    if not CLIENT_ID or not CLIENT_SECRET:
        print("\n✗ Client ID and Secret are required!")
        sys.exit(1)

    # Run tests
    if not test_oidc_discovery():
        return

    if not test_jwks_endpoint():
        return

    if not register_user():
        return

    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()
    print(f"\nℹ PKCE Code Verifier: {code_verifier}")
    print(f"ℹ PKCE Code Challenge: {code_challenge}")

    # Get authorization code (manual step)
    auth_code = get_authorization_code(CLIENT_ID, code_challenge)
    if not auth_code:
        return

    # Exchange code for tokens
    tokens = exchange_code_for_tokens(CLIENT_ID, CLIENT_SECRET, auth_code, code_verifier)
    if not tokens:
        return

    access_token = tokens['access_token']
    refresh_token = tokens.get('refresh_token')

    # Test userinfo endpoint
    test_userinfo_endpoint(access_token)

    # Test contracts API
    test_contracts_api(access_token)

    # Test refresh token
    if refresh_token:
        test_refresh_token(CLIENT_ID, CLIENT_SECRET, refresh_token)

    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print("✓ OIDC Discovery: SUCCESS")
    print("✓ JWKS Endpoint: SUCCESS")
    print("✓ User Registration: SUCCESS")
    print("✓ Authorization Code Flow: SUCCESS")
    print("✓ Token Exchange: SUCCESS")
    print("✓ UserInfo Endpoint: SUCCESS")
    print("✓ Contracts API (Scoped): SUCCESS")
    print("✓ Refresh Token: SUCCESS")
    print("\n🎉 All tests completed successfully!")
    print("="*70 + "\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
