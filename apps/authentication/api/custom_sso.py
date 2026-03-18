from django.utils.module_loading import import_string
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login
from django.http.response import HttpResponseRedirect

from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

from common.utils import get_logger
from ..mixins import AuthMixin

__all__  = ['CustomSSOLoginAPIView']

logger = get_logger(__file__)


custom_sso_authenticate_method = None

if settings.AUTH_CUSTOM_SSO:
    ''' 保证自定义 SSO 认证方法在服务运行时不能被更改，只在第一次调用时加载一次 '''
    try:
        custom_auth_method_path = 'data.auth.custom_sso.authenticate'
        custom_sso_authenticate_method = import_string(custom_auth_method_path)
    except Exception as e:
        logger.warning('Import custom SSO auth method failed: {}, Maybe not enabled'.format(e))


class CustomSSOLoginAPIView(AuthMixin, RetrieveAPIView):

    permission_classes = [AllowAny]

    def retrieve(self, request, *args, **kwargs):
        if not self.is_enabled():
            error = 'Custom SSO authentication is disabled.'
            return Response({'detail': error}, status=status.HTTP_403_FORBIDDEN)

        query_params = {}
        for param in settings.AUTH_CUSTOM_SSO_QUERY_PARAMS:
            value = self.request.query_params.get(param)
            if not value:
                error = f'Missing required query parameter: {param}'
                return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)
            query_params[param] = value
        
        user, error = self.authenticate(**query_params)
        if user:
            login(request, user, backend=settings.AUTH_BACKEND_CUSTOM_SSO)
            self.send_auth_signal(success=True, user=user)
            next_url = request.query_params.get('next', '/')
            return HttpResponseRedirect(next_url)
        else:
            self.send_auth_signal(success=False, reason=error)
            return Response({'detail': error}, status=status.HTTP_401_UNAUTHORIZED)

    def is_enabled(self):
        return settings.AUTH_CUSTOM_SSO and callable(custom_sso_authenticate_method)

    def authenticate(self, **query_params):
        try:
            userinfo: dict = custom_sso_authenticate_method(**query_params)
        except Exception as e:
            error = f'Custom SSO authenticate error: {e}'
            return None, error
        
        try:
            user, created = self.get_or_create_user_from_userinfo(userinfo)
            return user, ''
        except Exception as e:
            error = f'Custom SSO get or create user error: {e}'
            return None, error

    def get_or_create_user_from_userinfo(self, userinfo: dict):
        username = userinfo['username']
        attrs = ['name', 'username', 'email', 'is_active']
        defaults = {attr: userinfo[attr] for attr in attrs}
        user, created = get_user_model().objects.get_or_create(
            username=username, defaults=defaults
        )
        # TODO: get and set role attribute for user
        return user, created
