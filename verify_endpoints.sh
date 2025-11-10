#!/bin/bash
# Quick endpoint verification script

echo "======================================================================"
echo "Django OAuth 2.0 OIDC - Endpoint Verification"
echo "======================================================================"
echo ""

# Check if server is running
echo "Checking if server is running on port 8000..."
if ! curl -s http://localhost:8000/admin/ > /dev/null 2>&1; then
    echo "❌ Server is not running on port 8000"
    echo ""
    echo "Please start the server first:"
    echo "  source venv/bin/activate"
    echo "  python manage.py runserver"
    echo ""
    exit 1
fi

echo "✅ Server is running"
echo ""

# Test OIDC Discovery
echo "1. Testing OIDC Discovery endpoint..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/o/.well-known/openid-configuration/ | grep -q "200"; then
    echo "   ✅ OIDC Discovery: http://localhost:8000/o/.well-known/openid-configuration/"
else
    echo "   ❌ OIDC Discovery failed"
fi

# Test JWKS
echo "2. Testing JWKS endpoint..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/o/.well-known/jwks.json | grep -q "200"; then
    echo "   ✅ JWKS: http://localhost:8000/o/.well-known/jwks.json"
else
    echo "   ❌ JWKS failed"
fi

# Test User Registration
echo "3. Testing User Registration endpoint..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/users/register/ | grep -q "405\|200"; then
    echo "   ✅ User Registration: http://localhost:8000/api/users/register/"
else
    echo "   ❌ User Registration failed"
fi

# Test Django Admin
echo "4. Testing Django Admin..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/admin/ | grep -q "200\|302"; then
    echo "   ✅ Django Admin: http://localhost:8000/admin/"
else
    echo "   ❌ Django Admin failed"
fi

echo ""
echo "======================================================================"
echo "Basic Endpoint Verification Complete"
echo "======================================================================"
echo ""
echo "Next Steps:"
echo "1. Login to admin: http://localhost:8000/admin/ (admin/admin123)"
echo "2. Create an OAuth Application"
echo "3. Run the full test: python test_oauth_flow.py"
echo ""
