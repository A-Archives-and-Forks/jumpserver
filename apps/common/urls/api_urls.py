# -*- coding: utf-8 -*-
#

from django.urls import path
from django.conf import settings

from .. import api

app_name = 'common'

urlpatterns = [
    path('resources/cache/', api.ResourcesIDCacheApi.as_view(), name='resources-cache'),
    path('countries/', api.CountryListApi.as_view(), name='resources-cache'),
]

if settings.WEBHOOK_ENABLED:
    urlpatterns.append(path('webhook/', api.WebhookApi.as_view(), name='webhooks'))

if settings.JDMC_ENABLED:
    from xpack.plugins.jdmc.api import JdmcSSOTokenAPI
    urlpatterns.append(path('jdmc/sso-token/', JdmcSSOTokenAPI.as_view(), name='jdmc-sso-token'))
