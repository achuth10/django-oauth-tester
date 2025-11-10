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

    # Include router URLs (contracts endpoints)
    path('', include(router.urls)),
]
