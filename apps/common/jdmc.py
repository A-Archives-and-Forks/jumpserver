from django.conf import settings

import requests_unixsocket

__all__ = ['request_jdmc']


def request_jdmc(method='GET', path='', data=None, timeout=(5, 60)):
    ''' path: JDMC API path, e.g. /jdmc/api/v1/apps/license '''
    url = settings.JDMC_BASE_URL + path
    with requests_unixsocket.Session() as session:
        response = session.request(method, url, data=data, timeout=timeout)
    return response
