"""
API Views for User Management and Contracts

This module contains views for:
- User registration and profile management
- Contract CRUD operations with OAuth2 scoped access
"""
from rest_framework import generics, status, viewsets
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from oauth2_provider.contrib.rest_framework import TokenHasScope, TokenHasReadWriteScope
from .models import Contract
from .serializers import (
    UserRegistrationSerializer,
    UserProfileSerializer,
    ContractSerializer,
    ContractListSerializer
)


class UserRegistrationView(generics.CreateAPIView):
    """
    User registration endpoint (public access).

    POST /api/users/register/
    Request body:
        {
            "username": "string",
            "email": "string",
            "password": "string",
            "password2": "string",
            "first_name": "string" (optional),
            "last_name": "string" (optional)
        }

    Response (201 Created):
        {
            "username": "string",
            "email": "string",
            "first_name": "string",
            "last_name": "string"
        }
    """
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response(
            {
                "user": UserProfileSerializer(user).data,
                "message": "User registered successfully. You can now obtain an OAuth2 access token."
            },
            status=status.HTTP_201_CREATED
        )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    User profile endpoint (requires authentication).

    GET /api/users/profile/
    Returns the authenticated user's profile information.

    PUT /api/users/profile/
    Updates the authenticated user's profile.
    Request body:
        {
            "email": "string",
            "first_name": "string",
            "last_name": "string"
        }

    Response:
        {
            "id": integer,
            "username": "string",
            "email": "string",
            "first_name": "string",
            "last_name": "string",
            "date_joined": "datetime"
        }
    """
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        """Return the authenticated user"""
        return self.request.user


class ContractViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Contract CRUD operations with OAuth2 scoped access.

    Scope Requirements:
        - List/Retrieve: contracts:read
        - Create: contracts:write
        - Update: contracts:write
        - Delete: contracts:delete

    Endpoints:
        - GET /api/contracts/ - List all contracts (requires contracts:read)
        - POST /api/contracts/ - Create a contract (requires contracts:write)
        - GET /api/contracts/{id}/ - Retrieve a contract (requires contracts:read)
        - PUT /api/contracts/{id}/ - Update a contract (requires contracts:write)
        - PATCH /api/contracts/{id}/ - Partial update (requires contracts:write)
        - DELETE /api/contracts/{id}/ - Delete a contract (requires contracts:delete)

    Filtering:
        - Users can only see their own contracts
        - Admins can see all contracts
    """
    queryset = Contract.objects.all()
    serializer_class = ContractSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Set permissions based on the action.

        Different actions require different OAuth2 scopes.
        """
        if self.action in ['list', 'retrieve']:
            permission_classes = [IsAuthenticated, TokenHasScope]
            self.required_scopes = ['contracts:read']
        elif self.action in ['create', 'update', 'partial_update']:
            permission_classes = [IsAuthenticated, TokenHasScope]
            self.required_scopes = ['contracts:write']
        elif self.action == 'destroy':
            permission_classes = [IsAuthenticated, TokenHasScope]
            self.required_scopes = ['contracts:delete']
        else:
            permission_classes = [IsAuthenticated]

        return [permission() for permission in permission_classes]

    def get_queryset(self):
        """
        Filter contracts based on user permissions.

        - Regular users: Only see their own contracts
        - Superusers: See all contracts
        """
        user = self.request.user
        if user.is_superuser:
            return Contract.objects.all()
        return Contract.objects.filter(owner=user)

    def get_serializer_class(self):
        """
        Use a lightweight serializer for list view.
        """
        if self.action == 'list':
            return ContractListSerializer
        return ContractSerializer

    def perform_create(self, serializer):
        """
        Set the owner to the authenticated user when creating a contract.
        """
        serializer.save(owner=self.request.user)

    def perform_update(self, serializer):
        """
        Ensure the owner cannot be changed during updates.
        """
        serializer.save()

    def perform_destroy(self, instance):
        """
        Delete the contract. Only owners (or superusers) can delete.
        """
        instance.delete()
