"""
Custom OIDC validator for django-oauth-toolkit.

This validator customizes the claims included in ID tokens and UserInfo responses
to match Clerk's expected attribute mapping.

Clerk Attribute Mapping:
- User ID → sub
- Avatar URL → picture
- Full name → name
- Username → preferred_username
- First name → given_name
- Last name → family_name
- Email address → email
- Email address verified → email_verified
- Phone number → phone_number
- Phone number verified → phone_number_verified
"""

from oauth2_provider.oauth2_validators import OAuth2Validator


class ClerkOIDCValidator(OAuth2Validator):
    """
    Custom OIDC validator that provides claims compatible with Clerk's expectations.
    """

    def get_additional_claims(self, request):
        """
        Add custom claims to the ID token based on Clerk's requirements.

        This method is called when generating ID tokens and UserInfo responses.
        """
        claims = {}

        # Get the user from the request
        user = request.user

        if user and user.is_authenticated:
            # Standard OIDC claims with Clerk's expected format

            # sub (subject) - User ID (this is typically handled by the framework)
            claims["sub"] = str(user.id)

            # name - Full name
            if user.first_name or user.last_name:
                claims["name"] = f"{user.first_name} {user.last_name}".strip()
            else:
                claims["name"] = user.username

            # given_name - First name
            if user.first_name:
                claims["given_name"] = user.first_name

            # family_name - Last name
            if user.last_name:
                claims["family_name"] = user.last_name

            # preferred_username - Username
            claims["preferred_username"] = user.username

            # email - Email address
            if user.email:
                claims["email"] = user.email
                # email_verified - Email verification status
                # Django's default User model doesn't have email verification
                # Set to False by default, or customize based on your implementation
                claims["email_verified"] = True

            # picture - Avatar URL (optional)
            # Django's default User model doesn't have a picture field
            # You can customize this if you have a user profile with avatar
            # claims['picture'] = user.profile.avatar_url if hasattr(user, 'profile') else None

            # phone_number - Phone number (optional)
            # Django's default User model doesn't have a phone field
            # You can customize this if you have a user profile with phone
            # if hasattr(user, 'profile') and user.profile.phone_number:
            #     claims['phone_number'] = user.profile.phone_number
            #     claims['phone_number_verified'] = user.profile.phone_verified

        return claims

    def get_userinfo_claims(self, request):
        """
        Get claims for the UserInfo endpoint.

        This is called when the /userinfo endpoint is accessed.
        """
        claims = super().get_userinfo_claims(request)

        # Add our custom claims to the UserInfo response
        additional_claims = self.get_additional_claims(request)
        claims.update(additional_claims)

        return claims

    def get_id_token_content(self, token, token_handler, request):
        """
        Customize the content of the ID token.

        This method adds our custom claims to the ID token JWT.
        """
        # Get the default claims from the parent class
        content = super().get_id_token_content(token, token_handler, request)

        # Add our custom claims
        additional_claims = self.get_additional_claims(request)
        content.update(additional_claims)

        return content
