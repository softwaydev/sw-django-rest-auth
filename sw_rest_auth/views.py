# coding: utf-8
import logging

from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
import rest_framework.authtoken.views
from . import serializers


AuthUser = get_user_model()
logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def check_token(request):
    """
    Resource check is token valid.
    ---
    request_serializer: serializers.CheckToken
    type:
        username:
            required: true
            type: string
            description: token related user

    responseMessages:
        - code: 200
          message: Token is valid

        - code: 400
          message: Token is not valid

        - code: 401
          message: Unauthorized
    """
    serializer = serializers.CheckToken(data=request.data)
    serializer.is_valid(raise_exception=True)
    token = serializer.validated_data['token']
    logger.debug('Token correct', extra={'token': token, 'username': token.user.username})
    return Response({'username': token.user.username})


@api_view(['POST'])
@permission_classes((IsAuthenticated,))
def check_login_password(request):
    """
    Resource check login and password combination is valid.
    ---
    request_serializer: serializers.CheckLoginPassword
    response_serializer: serializers.User

    responseMessages:
        - code: 200
          message: Login and password is valid

        - code: 400
          message: Login and password is not valid

        - code: 401
          message: Unauthorized
    """
    serializer = serializers.CheckLoginPassword(request=request, data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data['username']
    logger.debug('Username and password correct', extra={'username': username})
    user_serializer = serializers.User(instance=AuthUser.objects.get(username=username))
    return Response(user_serializer.data)


@api_view(['GET'])
@permission_classes((IsAuthenticated,))
def check_perm(request):
    """
    Check user permission.
    ---
    request_serializer: serializers.CheckPerm

    parameters:
        - name: user
          type: string
          required: true
          description: username
          paramType: query

        - name: perm
          type: string
          required: true
          description: permission code
          paramType: query

    type:
        result:
            required: true
            type: string
            description: user have permission

    responseMessages:
        - code: 200
          message: User have permission

        - code: 400
          message: User have not permission

        - code: 401
          message: Unauthorized
    """
    serializer = serializers.CheckPerm(data=request.query_params)
    serializer.is_valid(raise_exception=True)
    logger.debug('User have perm', extra=serializer.data)
    return Response({'result': 'ok'})


@api_view(['POST'])
def obtain_auth_token(request):
    """
    Getting api-token by login and password.
    ---
    request_serializer: rest_framework.authtoken.serializers.AuthTokenSerializer
    type:
        token:
            required: true
            type: string
            description: User token for using in request header "Authentication"
    """
    return rest_framework.authtoken.views.obtain_auth_token(request._request)
