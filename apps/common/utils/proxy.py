# -*- coding: utf-8 -*-
#
import requests
import requests_unixsocket
from django.http import HttpResponse, QueryDict


def _get_headers(environ):
    headers = {}
    for key, value in environ.items():
        if key.startswith('HTTP_') and key != 'HTTP_HOST':
            headers[key[5:].replace('_', '-')] = value
        elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
            headers[key.replace('_', '-')] = value
    return headers


def unix_socket_proxy_view(
        request, url, requests_args=None, rewrite_location=None, 
        error_prefix='Proxy request failed'
    ):
    requests_args = (requests_args or {}).copy()
    headers = _get_headers(request.META)
    params = request.GET.copy()

    if 'headers' not in requests_args:
        requests_args['headers'] = {}
    if 'data' not in requests_args:
        requests_args['data'] = request.body
    if 'params' not in requests_args:
        requests_args['params'] = QueryDict('', mutable=True)

    headers.update(requests_args['headers'])
    params.update(requests_args['params'])

    for key in list(headers.keys()):
        if key.lower() == 'content-length':
            del headers[key]

    requests_args['headers'] = headers
    requests_args['params'] = params

    try:
        with requests_unixsocket.Session() as session:
            upstream_response = session.request(request.method, url, **requests_args)
    except requests.exceptions.RequestException as exc:
        return HttpResponse(f'{error_prefix}: {exc}', status=502)

    response = HttpResponse(upstream_response.content, status=upstream_response.status_code)
    excluded_headers = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers', 'transfer-encoding',
        'upgrade', 'content-encoding', 'content-length',
    }
    for key, value in upstream_response.headers.items():
        if key.lower() in excluded_headers:
            continue
        if key.lower() == 'location' and callable(rewrite_location):
            value = rewrite_location(value)
        response[key] = value

    return response
