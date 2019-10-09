# coding: utf-8
import logging

from django.conf import settings
from rest_framework import permissions
import requests
from rest_framework.exceptions import PermissionDenied


logger = logging.getLogger('sw.rest.auth')


class CodePermission(permissions.BasePermission):
    def __init__(self, permission_code):
        super(CodePermission, self).__init__()
        self.permission_code = permission_code

    def has_permission(self, request, view):
        if not (request.user and request.user.username):
            logger.debug('Unauthorized')
            return False

        return self.has_permission_by_params(
            username=request.user.username,
            permission_code=self.permission_code
        )

    @staticmethod
    def has_permission_by_params(username, permission_code, raise_exception=True):
        try:
            params = {
                'headers': {'Authorization': 'Token %s' % settings.AUTH_TOKEN},
                'params': {'user': username, 'perm': permission_code},
                'auth_verified_ssl_crt': getattr(settings, 'AUTH_VERIFIED_SSL_CRT_PATH', None),
                'timeout': getattr(settings, 'REQUEST_TIMEOUT', 5)
            }
            logger.debug('---> Request: %s params: %s', settings.AUTH_SERVICE_CHECK_PERM_URL, params)
            r = requests.get(settings.AUTH_SERVICE_CHECK_PERM_URL, **params)
        except requests.ConnectionError as e:
            logger.error('Permission denied %s', e, exc_info=True)
            if raise_exception:
                raise PermissionDenied(detail='Can not connect to authorization service')
            else:
                return False

        if r.status_code != 200:
            detail = '; '.join(['%s: %s' % (k, ', '.join(v)) for k, v in r.json().items()])
            logger.error('<--- Response permission denied url: %s detail: %s',
                         settings.AUTH_SERVICE_CHECK_PERM_URL, detail, exc_info=True)
            if raise_exception:
                raise PermissionDenied(detail=detail)
            else:
                return False

        logger.debug('<--- Response url: %s resp: %s', settings.AUTH_SERVICE_CHECK_PERM_URL, r.text)
        return True

    @classmethod
    def decorate(cls, code):
        def decorator():
            return cls(permission_code=code)
        return decorator
