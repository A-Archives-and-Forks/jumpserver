# ~*~ coding: utf-8 ~*~

import json
import os
import re
import time
from urllib.parse import urlparse, quote

import pytz
from django.conf import settings
from django.core.exceptions import MiddlewareNotUsed
from django.db.utils import OperationalError
from django.middleware.csrf import CsrfViewMiddleware
from django.http.response import HttpResponseForbidden, JsonResponse
from django.shortcuts import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from .utils import set_current_request
from common.utils.common import text_hmac_sha256

IGNORE_CSRF_CHECK = '*' in os.getenv("DOMAINS", "").split(',')


class TimezoneMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tzname = request.META.get('HTTP_X_TZ')
        if not tzname or tzname == 'undefined':
            return self.get_response(request)
        try:
            tz = pytz.timezone(tzname)
            timezone.activate(tz)
        except pytz.UnknownTimeZoneError:
            pass
        response = self.get_response(request)
        return response


class DemoMiddleware:
    DEMO_MODE_ENABLED = os.environ.get("DEMO_MODE", "") in ("1", "ok", "True")
    SAFE_URL_PATTERN = re.compile(
        r'^/users/login|'
        r'^/api/terminal/v1/.*|'
        r'^/api/terminal/.*|'
        r'^/api/users/v1/auth/|'
        r'^/api/users/v1/profile/'
    )
    SAFE_METHOD = ("GET", "HEAD")

    def __init__(self, get_response):
        self.get_response = get_response

        if self.DEMO_MODE_ENABLED:
            print("Demo mode enabled, reject unsafe method and url")
            raise MiddlewareNotUsed

    def __call__(self, request):
        if self.DEMO_MODE_ENABLED and request.method not in self.SAFE_METHOD \
                and not self.SAFE_URL_PATTERN.match(request.path):
            return HttpResponse("Demo mode, only safe request accepted", status=403)
        else:
            response = self.get_response(request)
            return response


class RequestMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        set_current_request(request)
        response = self.get_response(request)
        return response


class RefererCheckMiddleware:
    def __init__(self, get_response):
        if not settings.REFERER_CHECK_ENABLED:
            raise MiddlewareNotUsed
        self.get_response = get_response
        self.http_pattern = re.compile('https?://')

    def check_referer(self, request):
        referer = request.META.get('HTTP_REFERER', '')
        referer = self.http_pattern.sub('', referer)
        if not referer:
            return True
        remote_host = request.get_host()
        return referer.startswith(remote_host)

    def __call__(self, request):
        match = self.check_referer(request)
        if not match:
            return HttpResponseForbidden('CSRF CHECK ERROR')
        response = self.get_response(request)
        return response


class SQLCountMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        if not settings.DEBUG_DEV:
            raise MiddlewareNotUsed

    def __call__(self, request):
        from django.db import connection
        response = self.get_response(request)
        response['X-JMS-SQL-COUNT'] = len(connection.queries) - 2
        return response


class StartMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        if not settings.DEBUG_DEV:
            raise MiddlewareNotUsed

    def __call__(self, request):
        request._s_time_start = time.time()
        response = self.get_response(request)
        request._s_time_end = time.time()
        if request.path == '/api/health/':
            data = response.data
            data['pre_middleware_time'] = request._e_time_start - request._s_time_start
            data['api_time'] = request._e_time_end - request._e_time_start
            data['post_middleware_time'] = request._s_time_end - request._e_time_end
            response.content = json.dumps(data)
            response.headers['Content-Length'] = str(len(response.content))
            return response
        return response


class EndMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        if not settings.DEBUG_DEV:
            raise MiddlewareNotUsed

    def __call__(self, request):
        request._e_time_start = time.time()
        response = self.get_response(request)
        request._e_time_end = time.time()
        return response

    def process_exception(self, request, exception):
        if isinstance(exception, OperationalError):
            return JsonResponse({
                'error': 'Database OperationalError: ' + str(exception),
                'message': 'Database operation failed, please try again later.',
                'code': 'DB_ERROR'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return None


class SafeRedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if not (300 <= response.status_code < 400):
            return response
        if (
                request.resolver_match and
                request.resolver_match.namespace.startswith('authentication') and
                not request.resolver_match.namespace.startswith('authentication:oauth2-provider')
        ):
            # 认证相关的路由跳过验证 /core/auth/..., 
            # 但 oauth2-provider 除外, 因为它会重定向到第三方客户端, 希望给出更友好的提示
            return response
        location = response.get('Location')
        if not location:
            return response
        parsed = urlparse(location)
        if parsed.scheme and parsed.netloc:
            target_host = parsed.netloc
            if target_host in [*settings.ALLOWED_HOSTS]:
                return response
            target_host, target_port = self._split_host_port(parsed.netloc)
            origin_host, origin_port = self._split_host_port(request.get_host())
            if target_host != origin_host:
                safe_redirect_url = '%s?%s' % (reverse('redirect-confirm'), f'next={quote(location)}')
                return redirect(safe_redirect_url)
        return response

    @staticmethod
    def _split_host_port(netloc):
        if ':' in netloc:
            host, port = netloc.split(':', 1)
            return host, port
        return netloc, '80'


class CsrfCheckMiddleware(CsrfViewMiddleware):
    def _origin_verified(self, request):
        if IGNORE_CSRF_CHECK:
            request._dont_enforce_csrf_checks = True
            return True
        return super()._origin_verified(request)


class HmacSignAuthMiddleware:
    """
    在响应中写入客户端可读会话状态 Cookie（名：jms_session_sign），
    供边缘代理、网关或安全设备（含 WAF）基于 Cookie 做访问策略，不特指某一种产品。

    取值约定（均为非空，便于写规则）：
    - 已登录：<hex_hmac>:<username>|<session_id>，HMAC 与 text_hmac_sha256 一致（消息会先 strip/lower）
    - 有会话 Cookie 但未认证：expired（含会话过期、登出后会话仍存在、或仅匿名会话等）
    - 请求未带会话 Cookie：unauth（首次访问等）
    """

    SIGN_COOKIE_NAME = 'jms_session_sign'
    MARKER_UNAUTH = 'unauth'
    MARKER_EXPIRED = 'expired'

    def __init__(self, get_response):
        self.get_response = get_response
        enabled = os.getenv("HMAC_SIGN_AUTH_ENABLED", "").lower() in ("1", "true", "yes")
        key_file_path = os.path.join(settings.PROJECT_DIR, "data", "unshare", "hmac.key")

        if os.path.isfile(key_file_path):
            with open(key_file_path, 'r') as f:
                self.hmac_sign_key = f.read().strip()
        else:
            self.hmac_sign_key = os.getenv("HMAC_SIGN_KEY", "")

        if not enabled or not self.hmac_sign_key:
            raise MiddlewareNotUsed

    def __call__(self, request):
        response = self.get_response(request)
        return self._set_session_sign_cookie(request, response)

    def _set_session_sign_cookie(self, request, response):
        session_cookie_name = settings.SESSION_COOKIE_NAME
        has_session_cookie = bool(request.COOKIES.get(session_cookie_name))

        if request.user.is_authenticated:
            session_id = request.session.session_key
            # request.user 可能为 IntegrationApplication对象
            username = getattr(request.user, 'username', None) or getattr(request.user, 'name', None)
            sign_data = f'{username}|{session_id}'
        elif request.path == '/api/v1/authentication/tokens/' \
                            and response.status_code == 201:
            user = response.data.get('user')
            if not user:
                sign_data = ''
            else:
                sign_data = f'{user["username"]}:{user["id"]}'
        else:
            sign_data = ''

        if sign_data:
            signature = text_hmac_sha256(sign_data, self.hmac_sign_key)
            value = f'{signature}:{sign_data}'
        elif has_session_cookie:
            value = self.MARKER_EXPIRED
        else:
            value = self.MARKER_UNAUTH

        response.set_cookie(
            self.SIGN_COOKIE_NAME,
            value,
        )
        return response