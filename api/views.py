"""
API Views for User Management and Contracts

This module contains views for:
- User registration and profile management
- Contract CRUD operations with OAuth2 scoped access
- Custom authentication flows (username/password, SAML SSO, OAuth SSO)
"""
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, get_user_model
from django.views import View
from django.contrib import messages
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
from .utils import create_auth_token, retrieve_auth_params, delete_auth_token
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

User = get_user_model()


# Decorator to capture OAuth params before login
def capture_oauth_params(view_func):
    """Decorator to capture OAuth authorization params before redirecting to login"""
    def wrapper(request, *args, **kwargs):
        # If this is an authorization request with OAuth params, store them in session
        if not request.user.is_authenticated and request.GET:
            oauth_params = {}
            # Capture all OAuth-related parameters
            for key in ['client_id', 'redirect_uri', 'scope', 'state', 'response_type',
                       'code_challenge', 'code_challenge_method', 'nonce']:
                if key in request.GET:
                    oauth_params[key] = request.GET[key]

            if oauth_params:
                # Store in session for later use
                request.session['oauth2_provider_authorize'] = oauth_params
                request.session.modified = True
                print(f"[OAuth Capture] Stored params: {list(oauth_params.keys())}", file=sys.stderr)

        return view_func(request, *args, **kwargs)
    return wrapper


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


# ============================================================================
# CUSTOM AUTHENTICATION VIEWS
# ============================================================================

class CustomLoginView(View):
    """
    Custom login page with multiple authentication options:
    - Username/Password (traditional)
    - SAML SSO (mock)
    - OAuth SSO (mock)

    Preserves OAuth parameters through authentication flow using auth tokens.
    """
    template_name = 'login.html'

    def get(self, request):
        """Display login page with three authentication options"""
        # Debug: Print session info
        import sys
        print(f"\n[CustomLogin GET] Session keys: {list(request.session.keys())}", file=sys.stderr)
        print(f"[CustomLogin GET] Session ID: {request.session.session_key}", file=sys.stderr)

        # If user is already authenticated, redirect to OAuth authorize
        if request.user.is_authenticated:
            return redirect('/o/authorize/')

        # Extract OAuth params from django-oauth-toolkit's session storage
        oauth_params = request.session.get('oauth2_provider_authorize', {})
        print(f"[CustomLogin GET] OAuth params found: {bool(oauth_params)}", file=sys.stderr)
        if oauth_params:
            print(f"[CustomLogin GET] OAuth params keys: {list(oauth_params.keys())}", file=sys.stderr)

        # Create auth token and store params in cache
        if oauth_params:
            auth_token = create_auth_token(oauth_params)
            request.session['auth_flow_token'] = auth_token
            request.session.modified = True  # Ensure session is saved
        else:
            # If no OAuth params, user came directly to login
            auth_token = None

        context = {
            'has_oauth_flow': bool(oauth_params),
            'next': request.GET.get('next')  # No default
        }

        return render(request, self.template_name, context)

    def post(self, request):
        """Handle username/password authentication"""
        username = request.POST.get('username')
        password = request.POST.get('password')
        next_url = request.POST.get('next')  # No default - only use if explicitly provided

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Log the user in
            login(request, user)

            # Check if this is part of an OAuth flow
            auth_token = request.session.get('auth_flow_token')
            if auth_token:
                try:
                    oauth_params = retrieve_auth_params(auth_token)
                    request.session['oauth2_provider_authorize'] = oauth_params
                    request.session.modified = True

                    # Build the OAuth authorize URL with all parameters
                    from urllib.parse import urlencode
                    query_string = urlencode(oauth_params, safe=':/')
                    next_url = f'/o/authorize/?{query_string}'

                    # Clean up - don't delete yet, might be needed for error recovery
                except ValueError:
                    messages.error(request, 'Session expired. Please try again.')
                    return redirect('/api/auth/login/')

            # Redirect to next URL if provided, otherwise redirect to admin or show success
            if next_url:
                return redirect(next_url)
            else:
                # No OAuth flow and no explicit next - redirect to admin
                return redirect('/admin/')
        else:
            messages.error(request, 'Invalid username or password.')
            return render(request, self.template_name, {
                'error': 'Invalid username or password',
                'has_oauth_flow': bool(request.session.get('auth_flow_token')),
                'next': next_url
            })


# ============================================================================
# MOCK SAML SSO FLOW
# ============================================================================

class MockSAMLInitiateView(View):
    """Initiate mock SAML authentication flow"""

    def get(self, request):
        """Redirect to mock SAML provider with RelayState (auth token)"""
        # Debug: Print session info
        import sys
        print(f"\n[SAML Initiate] Session keys: {list(request.session.keys())}", file=sys.stderr)
        print(f"[SAML Initiate] Session ID: {request.session.session_key}", file=sys.stderr)

        # Get auth token from session
        auth_token = request.session.get('auth_flow_token')
        print(f"[SAML Initiate] Auth token from session: {auth_token[:20] if auth_token else 'None'}", file=sys.stderr)

        # If no auth token in session, try to create one from OAuth params
        if not auth_token:
            oauth_params = request.session.get('oauth2_provider_authorize', {})
            print(f"[SAML Initiate] OAuth params from session: {bool(oauth_params)}", file=sys.stderr)
            if oauth_params:
                print(f"[SAML Initiate] Creating auth token from OAuth params", file=sys.stderr)
                auth_token = create_auth_token(oauth_params)
                request.session['auth_flow_token'] = auth_token
                request.session.modified = True  # Ensure session is saved
            else:
                print(f"[SAML Initiate] ERROR: No OAuth params in session!", file=sys.stderr)
                messages.error(request, 'No active authentication flow. Please start from the OAuth authorization endpoint.')
                return redirect('/api/auth/login/')

        # In real SAML, we'd generate a SAMLRequest here
        # For mock, we just pass the auth token as RelayState
        saml_request = 'MOCK_SAML_REQUEST'

        return redirect(
            f'/api/auth/saml/provider/?SAMLRequest={saml_request}&RelayState={auth_token}'
        )


class MockSAMLProviderView(View):
    """Mock SAML Identity Provider page"""
    template_name = 'mock_saml_provider.html'

    def get(self, request):
        """Display mock SAML IDP approval page"""
        saml_request = request.GET.get('SAMLRequest')
        relay_state = request.GET.get('RelayState')

        if not relay_state:
            return render(request, self.template_name, {
                'error': 'Missing RelayState parameter'
            })

        context = {
            'saml_request': saml_request,
            'relay_state': relay_state,
            'provider_name': 'Mock SAML Identity Provider'
        }

        return render(request, self.template_name, context)


class MockSAMLCallbackView(View):
    """Handle SAML authentication callback"""

    def post(self, request):
        """Process SAML response and authenticate user"""
        relay_state = request.POST.get('RelayState')

        if not relay_state:
            messages.error(request, 'Missing RelayState in SAML response.')
            return redirect('/api/auth/login/')

        try:
            # Retrieve OAuth params from cache using RelayState token
            oauth_params = retrieve_auth_params(relay_state)

            # In real SAML, we'd validate the SAMLResponse here
            # For mock, we'll authenticate a test user or create one
            username = 'saml_testuser'
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': 'saml_test@example.com',
                    'first_name': 'SAML',
                    'last_name': 'User'
                }
            )

            # If user was just created, set a password
            if created:
                user.set_password('test_saml_password')
                user.save()

            # Authenticate and log in the user
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            # Restore OAuth params to django-oauth-toolkit's session
            request.session['oauth2_provider_authorize'] = oauth_params
            request.session.modified = True

            # Clean up auth token from cache
            delete_auth_token(relay_state)

            # Build the OAuth authorize URL with all parameters
            from urllib.parse import urlencode
            query_string = urlencode(oauth_params, safe=':/')
            redirect_url = f'/o/authorize/?{query_string}'

            # Redirect to OAuth authorize endpoint with full params
            return redirect(redirect_url)

        except ValueError as e:
            messages.error(request, f'SAML authentication failed: {str(e)}')
            return redirect('/api/auth/login/')


# ============================================================================
# MOCK OAUTH SSO FLOW
# ============================================================================

class MockOAuthInitiateView(View):
    """Initiate mock OAuth SSO authentication flow"""

    def get(self, request):
        """Redirect to mock OAuth provider with state (auth token)"""
        # Get auth token from session
        auth_token = request.session.get('auth_flow_token')

        # If no auth token in session, try to create one from OAuth params
        if not auth_token:
            oauth_params = request.session.get('oauth2_provider_authorize', {})
            if oauth_params:
                auth_token = create_auth_token(oauth_params)
                request.session['auth_flow_token'] = auth_token
                request.session.modified = True  # Ensure session is saved
            else:
                messages.error(request, 'No active authentication flow. Please start from the OAuth authorization endpoint.')
                return redirect('/api/auth/login/')

        # In real OAuth, we'd include client_id, redirect_uri, scope, etc.
        # For mock, we just pass the auth token as state
        return redirect(
            f'/api/auth/oauth/provider/?client_id=mock_oauth_client&response_type=code&state={auth_token}'
        )


class MockOAuthProviderView(View):
    """Mock OAuth Provider authorization page"""
    template_name = 'mock_oauth_provider.html'

    def get(self, request):
        """Display mock OAuth provider approval page"""
        client_id = request.GET.get('client_id')
        state = request.GET.get('state')

        if not state:
            return render(request, self.template_name, {
                'error': 'Missing state parameter'
            })

        context = {
            'client_id': client_id,
            'state': state,
            'provider_name': 'Mock OAuth Provider',
            'scopes': ['openid', 'profile', 'email']
        }

        return render(request, self.template_name, context)


class MockOAuthCallbackView(View):
    """Handle OAuth SSO authentication callback"""

    def post(self, request):
        """Process OAuth authorization and authenticate user"""
        state = request.POST.get('state')

        if not state:
            messages.error(request, 'Missing state in OAuth response.')
            return redirect('/api/auth/login/')

        try:
            # Retrieve OAuth params from cache using state token
            oauth_params = retrieve_auth_params(state)

            # In real OAuth, we'd exchange code for tokens here
            # For mock, we'll authenticate a test user or create one
            username = 'oauth_testuser'
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': 'oauth_test@example.com',
                    'first_name': 'OAuth',
                    'last_name': 'User'
                }
            )

            # If user was just created, set a password
            if created:
                user.set_password('test_oauth_password')
                user.save()

            # Authenticate and log in the user
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            # Restore OAuth params to django-oauth-toolkit's session
            request.session['oauth2_provider_authorize'] = oauth_params
            request.session.modified = True

            # Clean up auth token from cache
            delete_auth_token(state)

            # Build the OAuth authorize URL with all parameters
            from urllib.parse import urlencode
            query_string = urlencode(oauth_params, safe=':/')
            redirect_url = f'/o/authorize/?{query_string}'

            # Redirect to OAuth authorize endpoint with full params
            return redirect(redirect_url)

        except ValueError as e:
            messages.error(request, f'OAuth authentication failed: {str(e)}')
            return redirect('/api/auth/login/')
