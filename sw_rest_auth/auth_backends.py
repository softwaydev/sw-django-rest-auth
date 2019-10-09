# coding: utf-8
import logging

import requests
from django.conf import settings
from django.contrib.auth import get_user_model

from .permissions import CodePermission

User = get_user_model()
logger = logging.getLogger('sw.rest.auth')


class RestBackend(object):
    def authenticate(self, username, password):
        url = settings.AUTH_SERVICE_CHECK_LOGIN_PASSWORD_URL
        auth_token = settings.AUTH_TOKEN
        auth_verified_ssl_crt = getattr(settings, 'AUTH_VERIFIED_SSL_CRT_PATH', None)

        headers = {'Authorization': 'Token %s' % auth_token}
        data = {'username': username, 'password': password}
        try:
            kwargs = {'headers': headers, 'data': data, 'verify': auth_verified_ssl_crt, 'timeout': 5}
            logger.debug('---> Request: %s params: %s', url, kwargs)
            r = requests.post(url, **kwargs)
        except requests.ConnectionError:
            logger.error('<--- Response  auth failed url: %s', url, exc_info=True)
            return None

        if r.status_code == 200:
            result = r.json()
            result.pop('id')
            result.pop('user_permissions')
            result.pop('groups')
            try:
                user = User.objects.get(username=result['username'])
            except User.DoesNotExist:
                result['password'] = password
                user = User.objects.create_user(**result)
            logger.debug('<--- Response url: %s resp: %s', url, result)
            return user

        logger.error('<--- Response auth failed url: %s error: %s', url, r.text)
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            logger.error('User does not exists user_id: %s', user_id)
            return None

    def has_perm(self, user, perm, obj):
        return CodePermission.has_permission_by_params(user.username, perm, raise_exception=False)
