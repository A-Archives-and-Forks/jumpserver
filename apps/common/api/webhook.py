import hashlib
import hmac

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from common.signals import webhook_signal


class WebhookApi(APIView):
    """
    data:
    {
        "event": "license_updated",
        "payload": {
    }
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)

    signature_header = 'HTTP_X_WEBHOOK_SIGNATURE'

    @staticmethod
    def _normalize_signature(signature):
        signature = str(signature or '').strip()
        if signature.startswith('sha256='):
            return signature.split('=', 1)[1]
        return signature

    def _is_valid_signature(self, body, signature):
        token = getattr(settings, 'WEBHOOK_TOKEN', '')
        if not token:
            return False

        expected = hmac.new(
            token.encode('utf-8'),
            msg=body,
            digestmod=hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, self._normalize_signature(signature))

    def post(self, request, *args, **kwargs):
        signature = request.META.get(self.signature_header, '')
        body = request.body or b''
        data = request.data
        sender = data.get('sender', '')
        event = data.get('event', '')
        payload = data.get('payload', {})

        if not signature:
            return Response({'detail': 'Missing X-WEBHOOK-Signature'}, status=status.HTTP_400_BAD_REQUEST)

        if not self._is_valid_signature(body, signature):
            return Response({'detail': 'Invalid webhook signature'}, status=status.HTTP_403_FORBIDDEN)

        webhook_signal.send(
            sender=self.__class__,
            event_sender=sender,
            event=event,
            payload=payload,
            headers=request.headers,
        )
        return Response({'detail': 'Webhook accepted'}, status=status.HTTP_202_ACCEPTED)
