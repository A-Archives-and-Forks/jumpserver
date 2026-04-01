from django.http import HttpResponse
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from urllib.parse import quote

from common.permissions import OnlyAdminSuperUser
from common.utils.crypto.gm import get_gm_sm4_ecb_crypto

'''
POST /api/v1/files/crypto/
Content-Type: multipart/form-data

action=encrypt / decrypt
key=key
file=<binary>
'''

class FileCryptoApi(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = (OnlyAdminSuperUser,)

    @staticmethod
    def _build_output_filename(original_name, action):
        original_name = original_name or 'file.txt'
        if action == 'encrypt':
            return f'{original_name}.enc'
        if original_name.endswith('.enc'):
            return original_name[:-4]
        return f'{original_name}.dec'

    def post(self, request, *args, **kwargs):
        action = str(request.data.get('action', '')).strip().lower()
        key = request.data.get('key')
        upload = request.data.get('file')

        if action not in {'encrypt', 'decrypt'}:
            return Response({'detail': 'Invalid action, must be encrypt or decrypt'}, status=400)
        if not key:
            return Response({'detail': 'Missing key'}, status=400)
        if upload is None:
            return Response({'detail': 'Missing file'}, status=400)

        try:
            content = upload.read().decode('utf-8')
        except UnicodeDecodeError:
            return Response({'detail': 'Uploaded file must be UTF-8 text'}, status=400)

        crypto = get_gm_sm4_ecb_crypto(key)
        try:
            if action == 'encrypt':
                result = crypto.encrypt(content)
            else:
                result = crypto.decrypt(content)
        except Exception as exc:
            return Response({'detail': f'File {action} failed: {exc}'}, status=400)

        output_name = self._build_output_filename(getattr(upload, 'name', ''), action)
        response = HttpResponse(result, content_type='application/octet-stream')
        quoted_name = quote(output_name)
        response['Content-Disposition'] = (
            f'attachment; filename="{output_name}"; filename*=UTF-8\'\'{quoted_name}'
        )
        return response
