# Django OAuth 2.0 OIDC Implementation

A comprehensive OAuth 2.0 / OpenID Connect (OIDC) implementation using django-oauth-toolkit with scoped API access control.

## Features

- ✅ OAuth 2.0 Authorization Server with OIDC support
- ✅ RS256 JWT signing with RSA keys
- ✅ Scoped API access control (`contracts:read`, `contracts:write`, `contracts:delete`)
- ✅ User registration and profile management
- ✅ Django admin interface for OAuth management
- ✅ CORS enabled for frontend integration
- ✅ PKCE (Proof Key for Code Exchange) support
- ✅ Complete REST API with Django REST Framework

## Technology Stack

- **Python**: 3.10.17
- **Django**: 4.2.17
- **django-oauth-toolkit**: 3.1.0
- **djangorestframework**: 3.15.2
- **django-cors-headers**: 4.6.0
- **Database**: SQLite (development)

## Quick Start

### 1. Installation

```bash
# Clone or navigate to the project directory
cd oauth-django

# Create virtual environment
python3.10 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create superuser
./create_superuser.sh
# Default credentials: admin / admin123
```

### 2. Start the Development Server

```bash
source venv/bin/activate
python manage.py runserver
```

The server will be available at `http://localhost:8000`

## API Endpoints

### OAuth 2.0 / OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /o/authorize/` | OAuth2 authorization endpoint |
| `POST /o/token/` | Token endpoint (exchange code for tokens) |
| `POST /o/revoke_token/` | Token revocation endpoint |
| `POST /o/introspect/` | Token introspection endpoint |
| `GET /o/.well-known/openid-configuration/` | OIDC discovery endpoint |
| `GET /o/.well-known/jwks.json` | JWKS (public keys) endpoint |
| `GET /o/userinfo/` | OIDC user info endpoint |

### User Management

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/users/register/` | POST | Register new user | No |
| `/api/users/profile/` | GET | Get user profile | Yes |
| `/api/users/profile/` | PUT | Update user profile | Yes |

### Contracts API (OAuth2 Scoped)

| Endpoint | Method | Required Scope | Description |
|----------|--------|----------------|-------------|
| `/api/contracts/` | GET | `contracts:read` | List all contracts |
| `/api/contracts/` | POST | `contracts:write` | Create a contract |
| `/api/contracts/{id}/` | GET | `contracts:read` | Retrieve a contract |
| `/api/contracts/{id}/` | PUT | `contracts:write` | Update a contract |
| `/api/contracts/{id}/` | PATCH | `contracts:write` | Partial update |
| `/api/contracts/{id}/` | DELETE | `contracts:delete` | Delete a contract |

## OAuth 2.0 Scopes

The application supports the following scopes:

| Scope | Description |
|-------|-------------|
| `openid` | OpenID Connect scope (required for OIDC) |
| `profile` | Access to profile information |
| `email` | Access to email address |
| `contracts:read` | Read access to contracts |
| `contracts:write` | Create and update contracts |
| `contracts:delete` | Delete contracts |

## Testing the OAuth Flow

### Step 1: Create an OAuth Application

1. Login to admin: http://localhost:8000/admin/
   - Username: `admin`
   - Password: `admin123`

2. Navigate to **OAuth2 Provider** → **Applications**

3. Click **"Add Application"**

4. Fill in the details:
   - **Name**: My Test App
   - **Client type**: Confidential
   - **Authorization grant type**: Authorization code
   - **Redirect URIs**: `http://localhost:8000/callback`
   - **Algorithm**: RS256

5. Save and note the **Client ID** and **Client Secret**

### Step 2: Register a Test User

```bash
curl -X POST http://localhost:8000/api/users/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!",
    "password2": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User"
  }'
```

### Step 3: Authorization Code Flow

#### 3.1. Generate PKCE Code Verifier and Challenge

```bash
# Generate code verifier (random 43-128 char string)
CODE_VERIFIER=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "Code Verifier: $CODE_VERIFIER"

# Generate code challenge (SHA256 hash of verifier, base64url encoded)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | python3 -c "import sys, hashlib, base64; print(base64.urlsafe_b64encode(hashlib.sha256(sys.stdin.buffer.read()).digest()).decode().rstrip('='))")
echo "Code Challenge: $CODE_CHALLENGE"
```

#### 3.2. Visit Authorization URL

Open in your browser (replace CLIENT_ID and CODE_CHALLENGE):

```
http://localhost:8000/o/authorize/?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8000/callback&scope=openid%20profile%20email%20contracts:read%20contracts:write&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256&state=random_state_123
```

After logging in and approving, you'll be redirected to:
```
http://localhost:8000/callback?code=AUTHORIZATION_CODE&state=random_state_123
```

#### 3.3. Exchange Code for Tokens

```bash
curl -X POST http://localhost:8000/o/token/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://localhost:8000/callback" \
  -d "code_verifier=$CODE_VERIFIER"
```

Response:
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "scope": "openid profile email contracts:read contracts:write",
  "id_token": "..."
}
```

### Step 4: Use the Access Token

#### Create a Contract (requires contracts:write)

```bash
curl -X POST http://localhost:8000/api/contracts/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Service Agreement",
    "description": "Contract for web development services",
    "content": "This agreement is between...",
    "status": "draft"
  }'
```

#### List Contracts (requires contracts:read)

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/api/contracts/
```

#### Get User Info (OIDC)

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8000/o/userinfo/
```

### Step 5: Refresh Token

```bash
curl -X POST http://localhost:8000/o/token/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "YOUR_CLIENT_ID:YOUR_CLIENT_SECRET" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

## OIDC Discovery

The application supports OIDC discovery. Clients can fetch the configuration:

```bash
curl http://localhost:8000/o/.well-known/openid-configuration/
```

This returns all necessary endpoints and supported features.

## Project Structure

```
oauth-django/
├── oauth_project/          # Django project settings
│   ├── settings.py        # Main settings with OAuth configuration
│   ├── urls.py            # URL routing
│   └── keys/              # RSA private keys (not in git)
│       └── oidc.key       # RS256 signing key
├── api/                   # Main API app
│   ├── models.py          # Contract model
│   ├── views.py           # API views with scope permissions
│   ├── serializers.py     # DRF serializers
│   ├── urls.py            # API URL routing
│   └── admin.py           # Admin configuration
├── manage.py              # Django management script
├── requirements.txt       # Python dependencies
├── create_superuser.sh    # Helper script to create admin user
└── README.md              # This file
```

## Security Configuration

### RSA Keys

The project uses RS256 algorithm for JWT signing. The RSA private key is stored in:
```
oauth_project/keys/oidc.key
```

**Important**: This key should be kept secret and never committed to version control (already in `.gitignore`).

### CORS Configuration

For development, CORS is enabled for all origins:
```python
CORS_ALLOW_ALL_ORIGINS = True
```

**For production**, update `settings.py` to restrict origins:
```python
CORS_ALLOWED_ORIGINS = [
    "https://yourdomain.com",
]
```

### Secret Key

The Django `SECRET_KEY` in `settings.py` should be changed for production and stored in environment variables.

## Development Tips

### Django Admin

Access at: http://localhost:8000/admin/

You can manage:
- Users
- OAuth Applications
- Access Tokens
- Refresh Tokens
- Contracts
- And more...

### Browsable API

Django REST Framework provides a browsable API. Visit any API endpoint in your browser to see the interactive documentation.

### Token Introspection

Check if a token is valid:

```bash
curl -X POST http://localhost:8000/o/introspect/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d "token=TOKEN_TO_INTROSPECT"
```

## Troubleshooting

### Issue: RSA Key Not Found

**Error**: `FileNotFoundError: oauth_project/keys/oidc.key`

**Solution**: Regenerate the RSA key:
```bash
mkdir -p oauth_project/keys
openssl genrsa -out oauth_project/keys/oidc.key 4096
```

### Issue: Scope Permission Denied

**Error**: `{"detail": "You do not have permission to perform this action."}`

**Solution**: Ensure your access token includes the required scope. Check token scopes:
```bash
curl -X POST http://localhost:8000/o/introspect/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d "token=YOUR_TOKEN"
```

### Issue: Token Expired

**Solution**: Use the refresh token to get a new access token (see Step 5 above).

## Testing Checklist

- [ ] User registration works
- [ ] User can login through admin
- [ ] OAuth Application created in admin
- [ ] Authorization code flow completes successfully
- [ ] Access token is received
- [ ] ID token is present (OIDC)
- [ ] Contracts API works with `contracts:read` scope
- [ ] Contracts API works with `contracts:write` scope
- [ ] Contracts API rejects requests without proper scope
- [ ] Refresh token flow works
- [ ] OIDC discovery endpoint returns valid JSON
- [ ] Userinfo endpoint returns user data

## Next Steps

1. **Add more API endpoints** - Extend the contracts API or add new resources
2. **Implement frontend** - Create a React/Vue.js client application
3. **Add rate limiting** - Protect APIs from abuse
4. **Set up production database** - Use PostgreSQL or MySQL
5. **Deploy to production** - Use Gunicorn, Nginx, and HTTPS
6. **Add logging and monitoring** - Track OAuth flows and API usage
7. **Implement webhook notifications** - Notify clients of events
8. **Add API versioning** - Support multiple API versions

## Resources

- [Django OAuth Toolkit Documentation](https://django-oauth-toolkit.readthedocs.io/)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Django REST Framework](https://www.django-rest-framework.org/)

## License

This is a test/demo project. Use it as you see fit.

## Contact

For questions or issues, please refer to the project repository or documentation.
