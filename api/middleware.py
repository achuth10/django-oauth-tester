"""
Middleware to capture OAuth authorization parameters.

This middleware intercepts requests to /o/authorize/ and stores OAuth parameters
in the session BEFORE django-oauth-toolkit's view runs. This is necessary because
django-oauth-toolkit only stores these params after authentication, but we need
them during the login flow for SSO buttons.
"""

import sys


class CaptureOAuthParamsMiddleware:
    """
    Middleware to capture and store OAuth parameters in session.

    This runs before any view logic, ensuring OAuth params are available
    in the session even when the user is redirected to login.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if this is an OAuth authorization request
        if request.path == '/o/authorize/' and not request.user.is_authenticated:
            oauth_params = {}

            # Capture all OAuth-related parameters from query string
            oauth_keys = [
                'client_id', 'redirect_uri', 'scope', 'state', 'response_type',
                'code_challenge', 'code_challenge_method', 'nonce'
            ]

            for key in oauth_keys:
                value = request.GET.get(key)
                if value:
                    oauth_params[key] = value

            # Store in session if we found any OAuth params
            if oauth_params:
                request.session['oauth2_provider_authorize'] = oauth_params
                request.session.modified = True
                print(f"\n[OAuth Middleware] Captured params: {list(oauth_params.keys())}", file=sys.stderr)
                print(f"[OAuth Middleware] Session ID: {request.session.session_key}", file=sys.stderr)

        # Continue with the request
        response = self.get_response(request)
        return response
