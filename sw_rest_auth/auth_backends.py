# coding: utf-8
import logging

import requests
from django.contrib.auth import get_user_model
from django.conf import settings

from .permissions import CodePermission

logger = logging.getLogger(__name__)


class RestBackend(object):
    def authenticate(self, request, username, password):
        url = settings.AUTH_SERVICE_CHECK_LOGIN_PASSWORD_URL
        auth_token = settings.AUTH_TOKEN
        auth_verified_ssl_crt = getattr(settings, 'AUTH_VERIFIED_SSL_CRT_PATH', None)

        headers = {'Authorization': 'Token %s' % auth_token}
        data = {'username': username, 'password': password}
        try:
            kwargs = {'headers': headers, 'data': data, 'verify': auth_verified_ssl_crt, 'timeout': 5}
            logger.info('---> Request: %s method: POST', url)
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
                user = get_user_model().objects.get(username=result['username'])
            except get_user_model().DoesNotExist:
                result['password'] = password
                user = get_user_model().objects.create_user(**result)
            logger.info('<--- Response url: %s resp: %s', url, result)
            return user

        logger.error('<--- Response auth failed url: %s error: %s', url, r.text)
        return None

    def get_user(self, user_id):
        try:
            return get_user_model().objects.get(pk=user_id)
        except get_user_model().DoesNotExist:
            logger.error('User does not exists user_id: %s', user_id)
            return None

    def has_perm(self, user, perm, obj):
        return CodePermission.has_permission_by_params(user.username, perm, raise_exception=False)
