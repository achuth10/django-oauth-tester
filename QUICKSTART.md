# Quick Start Guide

Get your OAuth 2.0 / OIDC server running in 5 minutes!

## Prerequisites

- Python 3.10.17
- Git (optional)

## Setup (5 Steps)

### 1. Install Dependencies

```bash
# Activate virtual environment
source venv/bin/activate

# If not already installed
pip install -r requirements.txt
```

### 2. Run Migrations

```bash
python manage.py migrate
```

### 3. Create Superuser

```bash
./create_superuser.sh
```

This creates an admin user:
- **Username**: `admin`
- **Password**: `admin123`

### 4. Start Server

```bash
python manage.py runserver
```

Server will start at: `http://localhost:8000`

### 5. Create OAuth Application

1. Visit: http://localhost:8000/admin/
2. Login with `admin` / `admin123`
3. Go to **OAuth2 Provider → Applications**
4. Click **Add Application**
5. Fill in:
   - **Name**: `My Test App`
   - **Client type**: `Confidential`
   - **Authorization grant type**: `Authorization code`
   - **Redirect URIs**: `http://localhost:8000/callback` (one per line)
   - **Algorithm**: `RS256`
6. Click **Save**
7. **Copy** the **Client ID** and **Client Secret**

## Test the OAuth Flow

### Option 1: Automated Test Script

```bash
python test_oauth_flow.py
```

Follow the prompts and paste your Client ID and Secret.

### Option 2: Manual Testing with cURL

#### Step 1: Register a User

```bash
curl -X POST http://localhost:8000/api/users/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "password2": "SecurePass123!"
  }'
```

#### Step 2: Generate PKCE Parameters

```bash
# Code verifier
CODE_VERIFIER=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Code challenge
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | python3 -c "import sys, hashlib, base64; print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).decode().rstrip('='))")

echo "Verifier: $CODE_VERIFIER"
echo "Challenge: $CODE_CHALLENGE"
```

#### Step 3: Get Authorization Code

Visit this URL in your browser (replace `YOUR_CLIENT_ID` and `YOUR_CODE_CHALLENGE`):

```
http://localhost:8000/o/authorize/?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8000/callback&scope=openid%20profile%20contracts:read%20contracts:write&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256&state=test123
```

After logging in and approving, you'll get redirected to:
```
http://localhost:8000/callback?code=AUTHORIZATION_CODE&state=test123
```

Copy the `code` value.

#### Step 4: Exchange Code for Token

```bash
curl -X POST http://localhost:8000/o/token/ \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:8000/callback" \
  -d "code_verifier=$CODE_VERIFIER"
```

Save the `access_token` from the response.

#### Step 5: Use the API

```bash
# Get user info (OIDC)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/o/userinfo/

# Create a contract
curl -X POST http://localhost:8000/api/contracts/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My First Contract",
    "description": "Test contract",
    "content": "Contract content here...",
    "status": "draft"
  }'

# List contracts
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/api/contracts/
```

## Important Endpoints

| Endpoint | Purpose |
|----------|---------|
| http://localhost:8000/admin/ | Django Admin |
| http://localhost:8000/o/.well-known/openid-configuration/ | OIDC Discovery |
| http://localhost:8000/o/.well-known/jwks.json | Public Keys (JWKS) |
| http://localhost:8000/o/authorize/ | OAuth Authorization |
| http://localhost:8000/o/token/ | Token Endpoint |
| http://localhost:8000/o/userinfo/ | OIDC User Info |
| http://localhost:8000/api/contracts/ | Contracts API |

## Available Scopes

- `openid` - Required for OIDC
- `profile` - User profile information
- `email` - User email
- `contracts:read` - Read contracts
- `contracts:write` - Create/update contracts
- `contracts:delete` - Delete contracts

## Troubleshooting

### "RSA key not found"

Generate a new key:
```bash
mkdir -p oauth_project/keys
openssl genrsa -out oauth_project/keys/oidc.key 4096
```

### "Permission denied" on API

Check that your access token includes the required scope:
```bash
curl -X POST http://localhost:8000/o/introspect/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d "token=YOUR_TOKEN"
```

### Server not starting

Make sure you:
1. Activated the virtual environment: `source venv/bin/activate`
2. Installed dependencies: `pip install -r requirements.txt`
3. Ran migrations: `python manage.py migrate`

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Explore the Django admin interface
- Build a frontend application
- Deploy to production

## Need Help?

- Check the [README.md](README.md) for detailed documentation
- Review Django OAuth Toolkit docs: https://django-oauth-toolkit.readthedocs.io/
- Check OAuth 2.0 spec: https://oauth.net/2/

Happy coding! 🚀
