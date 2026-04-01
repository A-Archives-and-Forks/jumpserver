# -*- coding: utf-8 -*-
#

from django.urls import path
from django.conf import settings

from .. import api

app_name = 'common'

urlpatterns = [
    path('resources/cache/', api.ResourcesIDCacheApi.as_view(), name='resources-cache'),
    path('countries/', api.CountryListApi.as_view(), name='resources-cache'),
    path('file/crypto/', api.FileCryptoApi.as_view(), name='file-crypto'),
]

if settings.WEBHOOK_ENABLED:
    urlpatterns.append(path('webhook/', api.WebhookApi.as_view(), name='webhooks'))

if settings.JDMC_ENABLED:
    urlpatterns.append(path('jdmc/sso-token/', api.JdmcSSOTokenAPI.as_view(), name='jdmc-sso-token'))