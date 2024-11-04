"""
    authlib.oauth2.rfc6750.validator
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Validate Bearer Token for in request, scope and token.
"""

from ..rfc6749 import TokenValidator
from .errors import (
    InvalidTokenError,
    InsufficientScopeError
)


class BearerTokenValidator(TokenValidator):
    TOKEN_TYPE = 'bearer'

    def authenticate_token(self, token_string):
        """A method to query token from database with the given token string.
        Developers MUST re-implement this method. For instance::

            def authenticate_token(self, token_string):
                return get_token_from_database(token_string)

        :param token_string: A string to represent the access_token.
        :return: token
        """
        raise NotImplementedError()

    def validate_token(self, token, scopes, request):
        """Check if token is active and matches the requested scopes."""
        if not token:
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)

        #===========Yishan add===========
        #MSG : check token is from redis or mysql
        # token hasattr 'is_expired' means from mysql and has is_expired function
        # token doesn't hasattr 'is_expired' means from redis and this token key not expired no need to check again
        if hasattr(token, 'is_expired') and token.is_expired():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        #================================

        #===========Yishan add===========
        #MSG : check token is from redis or mysql
        # token has attr 'is_revoked' means from mysql and has is_revoked function
        # token doesn't hasattr 'is_revoked' means from redis
        if hasattr(token, 'is_revoked'):
            if token.is_revoked():
                raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        else:
            if token['revoked'] == 1:
                raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        #================================

        token_scopes = None
        if hasattr(token, 'get_scope'):
            token_scopes = token.get_scope()
        else:
            token_scopes = token['scope']
        if self.scope_insufficient(token_scopes, scopes):
            raise InsufficientScopeError()
