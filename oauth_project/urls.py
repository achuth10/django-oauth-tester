"""
URL configuration for oauth_project project.

OAuth 2.0 / OIDC Endpoints:
    - /o/authorize/ - OAuth2 authorization endpoint
    - /o/token/ - Token endpoint
    - /o/revoke_token/ - Token revocation endpoint
    - /o/introspect/ - Token introspection endpoint
    - /o/.well-known/openid-configuration/ - OIDC discovery
    - /o/.well-known/jwks.json - JWKS endpoint
    - /o/userinfo/ - OIDC user info endpoint

API Endpoints:
    - /api/users/ - User management
    - /api/contracts/ - Contracts API (scoped access)
"""
from django.contrib import admin
from django.urls import path, include
from oauth2_provider import urls as oauth2_urls

urlpatterns = [
    # Django Admin
    path('admin/', admin.site.urls),

    # OAuth2 Provider & OIDC endpoints
    path('o/', include(oauth2_urls)),

    # API endpoints
    path('api/', include('api.urls')),
]
