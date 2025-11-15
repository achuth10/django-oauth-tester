"""
Utilities for authentication flow token management.

This module provides functions to create, retrieve, and delete auth tokens
that are used to preserve OAuth parameters across authentication redirects.
"""

import uuid
from django.core.cache import caches

# Get the dedicated auth flow cache
auth_cache = caches['auth_flow_cache']


def create_auth_token(oauth_params):
    """
    Generate a unique auth token and cache OAuth parameters.

    Args:
        oauth_params (dict): Dictionary containing OAuth parameters like
                           client_id, redirect_uri, scope, state, etc.

    Returns:
        str: UUID token that can be used to retrieve the parameters

    Example:
        >>> params = {'client_id': 'abc', 'redirect_uri': 'http://...'}
        >>> token = create_auth_token(params)
        >>> # token = 'a1b2c3d4-...'
    """
    token = str(uuid.uuid4())
    auth_cache.set(token, oauth_params, timeout=600)  # 10 minute TTL
    return token


def retrieve_auth_params(token):
    """
    Retrieve OAuth parameters from cache using auth token.

    Args:
        token (str): The auth token returned by create_auth_token()

    Returns:
        dict: OAuth parameters dictionary

    Raises:
        ValueError: If token is invalid or has expired

    Example:
        >>> params = retrieve_auth_params('a1b2c3d4-...')
        >>> print(params['client_id'])
        'abc'
    """
    params = auth_cache.get(token)
    if params is None:
        raise ValueError("Invalid or expired auth token")
    return params


def delete_auth_token(token):
    """
    Delete auth token from cache (cleanup after use).

    Args:
        token (str): The auth token to delete

    Example:
        >>> delete_auth_token('a1b2c3d4-...')
    """
    auth_cache.delete(token)
