"""
API URL Configuration

User Management:
    - POST /api/users/register/ - Register new user
    - GET /api/users/profile/ - Get user profile (requires authentication)
    - PUT /api/users/profile/ - Update user profile (requires authentication)

Contracts API (OAuth2 Scoped):
    - GET /api/contracts/ - List contracts (requires contracts:read)
    - POST /api/contracts/ - Create contract (requires contracts:write)
    - GET /api/contracts/<id>/ - Retrieve contract (requires contracts:read)
    - PUT /api/contracts/<id>/ - Update contract (requires contracts:write)
    - PATCH /api/contracts/<id>/ - Partial update (requires contracts:write)
    - DELETE /api/contracts/<id>/ - Delete contract (requires contracts:delete)

Authentication:
    - GET /auth/login/ - Custom login page
    - POST /auth/login/ - Handle username/password login
    - GET /auth/saml/initiate/ - Initiate SAML SSO flow
    - GET /auth/saml/provider/ - Mock SAML IDP page
    - POST /auth/saml/callback/ - SAML SSO callback
    - GET /auth/oauth/initiate/ - Initiate OAuth SSO flow
    - GET /auth/oauth/provider/ - Mock OAuth provider page
    - POST /auth/oauth/callback/ - OAuth SSO callback
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Router for viewsets
router = DefaultRouter()
router.register(r'contracts', views.ContractViewSet, basename='contract')

urlpatterns = [
    # User management endpoints
    path('users/register/', views.UserRegistrationView.as_view(), name='user-register'),
    path('users/profile/', views.UserProfileView.as_view(), name='user-profile'),

    # Custom authentication endpoints
    path('auth/login/', views.CustomLoginView.as_view(), name='custom-login'),

    # SAML SSO endpoints
    path('auth/saml/initiate/', views.MockSAMLInitiateView.as_view(), name='saml-initiate'),
    path('auth/saml/provider/', views.MockSAMLProviderView.as_view(), name='saml-provider'),
    path('auth/saml/callback/', views.MockSAMLCallbackView.as_view(), name='saml-callback'),

    # OAuth SSO endpoints
    path('auth/oauth/initiate/', views.MockOAuthInitiateView.as_view(), name='oauth-initiate'),
    path('auth/oauth/provider/', views.MockOAuthProviderView.as_view(), name='oauth-provider'),
    path('auth/oauth/callback/', views.MockOAuthCallbackView.as_view(), name='oauth-callback'),

    # Include router URLs (contracts endpoints)
    path('', include(router.urls)),
]
