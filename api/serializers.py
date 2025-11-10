"""
API Serializers for User Management and Contracts

This module contains serializers for:
- User registration and authentication
- User profile management
- Contract CRUD operations
"""
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from .models import Contract


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    Fields:
        - username: Unique username
        - email: Valid email address (unique)
        - password: Password (write-only, validated)
        - password2: Password confirmation (write-only)
        - first_name: Optional first name
        - last_name: Optional last name
    """
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False}
        }

    def validate(self, attrs):
        """Validate that passwords match"""
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        """Create and return a new user"""
        # Remove password2 as it's not needed for user creation
        validated_data.pop('password2')

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
        )
        user.set_password(validated_data['password'])
        user.save()

        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile retrieval and updates.

    Fields:
        - id: User ID (read-only)
        - username: Username (read-only)
        - email: Email address
        - first_name: First name
        - last_name: Last name
        - date_joined: Account creation date (read-only)
    """
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'date_joined')
        read_only_fields = ('id', 'username', 'date_joined')


class UserInfoSerializer(serializers.ModelSerializer):
    """
    Minimal serializer for OIDC userinfo endpoint.

    Returns basic user information for OpenID Connect.
    """
    sub = serializers.CharField(source='username', read_only=True)
    preferred_username = serializers.CharField(source='username', read_only=True)

    class Meta:
        model = User
        fields = ('sub', 'preferred_username', 'email', 'first_name', 'last_name')


class ContractSerializer(serializers.ModelSerializer):
    """
    Serializer for Contract CRUD operations with OAuth2 scoped access.

    Required Scopes:
        - contracts:read - For GET operations
        - contracts:write - For POST and PUT operations
        - contracts:delete - For DELETE operations

    Fields:
        - id: Contract ID (read-only)
        - title: Contract title
        - description: Contract description
        - content: Full contract text
        - status: Contract status (draft, active, completed, cancelled)
        - owner: User who owns the contract (read-only, auto-set)
        - owner_username: Username of owner (read-only)
        - created_at: Creation timestamp (read-only)
        - updated_at: Last update timestamp (read-only)
    """
    owner_username = serializers.CharField(source='owner.username', read_only=True)

    class Meta:
        model = Contract
        fields = (
            'id', 'title', 'description', 'content', 'status',
            'owner', 'owner_username', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'owner', 'owner_username', 'created_at', 'updated_at')

    def create(self, validated_data):
        """Create a contract and set the owner to the current user"""
        # The owner is set in the view
        return super().create(validated_data)


class ContractListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for contract list view.

    Excludes the full content field for better performance.
    """
    owner_username = serializers.CharField(source='owner.username', read_only=True)

    class Meta:
        model = Contract
        fields = (
            'id', 'title', 'description', 'status',
            'owner_username', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'owner_username', 'created_at', 'updated_at')
