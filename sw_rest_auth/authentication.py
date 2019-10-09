# coding: utf-8
import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
import requests

logger = logging.getLogger('sw.rest.auth')
User = get_user_model()


class TokenServiceAuthentication(BaseAuthentication):
    """
    Token based authentication by means third part services.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "TokenService ".  For example:

        Authorization: TokenService 401f7ac837da42b97f613d789819ff93537bee6a
    """

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'tokenservice':
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token_key = auth[1].decode()
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)

        return self._check_token(token_key)

    @staticmethod
    def _check_token(token_key):
        try:
            params = {
                'headers': {'Authorization': 'Token %s' % settings.AUTH_TOKEN},
                'data': {'token': token_key},
                'verify': getattr(settings, 'AUTH_VERIFIED_SSL_CRT_PATH', None),
                'timeout': 5
            }
            logger.debug('---> Request: %s params: %s', settings.AUTH_SERVICE_CHECK_TOKEN_URL, params)
            r = requests.post(settings.AUTH_SERVICE_CHECK_TOKEN_URL, **params)
        except requests.ConnectionError:
            raise exceptions.AuthenticationFailed('Invalid token header. ConnectionError.')

        if r.status_code == 200:
            result = r.json()
            username = result['username']
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                user = User(username=username)
            logger.debug('<--- Response url: %s resp: %s', settings.AUTH_SERVICE_CHECK_TOKEN_URL, result)
            return user, None

        elif r.status_code == 400:
            result = r.json()
            token_err_description = ', '.join(result['token'])
            logger.error('<--- Response  auth failed url: %s error: %s',
                         settings.AUTH_SERVICE_CHECK_TOKEN_URL, result, exc_info=True)
            raise exceptions.AuthenticationFailed('Invalid token header. %s' % token_err_description)

        else:
            logger.error('<--- Response auth failed url: %s error: %s',
                         settings.AUTH_SERVICE_CHECK_TOKEN_URL, r.text, exc_info=True)
            raise exceptions.AuthenticationFailed('Invalid token header. Unknown error: %s' % r.text)

    def authenticate_header(self, request):
        return 'TokenService'
