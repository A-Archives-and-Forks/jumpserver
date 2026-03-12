from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth.views import redirect_to_login
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import quote, urlsplit, urlunsplit
from common.utils.proxy import unix_socket_proxy_view


__all__ = ['jdmc_proxy_view']


def _rewrite_location(location):
    if not location:
        return location
    if location.startswith('http+unix://'):
        parsed = urlsplit(location)
        return urlunsplit(('', '', parsed.path, parsed.query, parsed.fragment))
    return location


@csrf_exempt
def jdmc_proxy_view(request, subpath=''):
    if not request.user.is_authenticated or not request.user.is_superuser:
        return redirect_to_login(request.get_full_path(), settings.LOGIN_URL)

    upstream_url = f"{settings.JDMC_BASE_URL}{request.path}"
    requests_args = {
        'headers': {
            'X-Forwarded-Proto': request.scheme,
            'X-Forwarded-Host': request.get_host(),
        },
        'allow_redirects': False,
        'timeout': (5, 60),
    }
    if request.method in {'GET', 'HEAD'}:
        requests_args['data'] = None

    return unix_socket_proxy_view(
        request=request,
        url=upstream_url,
        requests_args=requests_args,
        rewrite_location=_rewrite_location,
        error_prefix='JDMC proxy failed',
    )
