import base64

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from common.serializers.fields import EncryptedField

__all__ = ['CertSettingSerializer']

# SM2 曲线 OID：1.2.156.10197.1.301，DER 编码
_SM2_OID_DER = bytes([0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d])


def _detect_cert_algorithm(pem_content):
    """从 PEM 证书内容检测公钥算法，返回 'SM2' / 'RSA-2048' 等字符串，失败返回空字符串。"""
    if not pem_content:
        return ''
    try:
        lines = pem_content.strip().splitlines()
        b64 = ''.join(ln for ln in lines if not ln.startswith('-----'))
        der = base64.b64decode(b64)
        if _SM2_OID_DER in der:
            return 'SM2'
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        cert = x509.load_pem_x509_certificate(pem_content.encode())
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return 'RSA-{}'.format(pub.key_size)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return 'ECDSA-{}'.format(pub.key_size)
        return _('Unknown')
    except Exception:
        return ''


class CertSettingSerializer(serializers.Serializer):
    PREFIX_TITLE = _('UKey')

    AUTH_CERT = serializers.BooleanField(
        default=False, label=_('UKey')
    )
    AUTH_CERT_CHALLENGE_TTL = serializers.IntegerField(
        default=300, label=_('Challenge TTL (seconds)'),
        help_text=_('Time-to-live (seconds) for authentication challenge codes')
    )
    AUTH_CERT_DEFAULT_PIN = EncryptedField(
        default='', allow_blank=True, label=_('USB-Key Default PIN'),
        help_text=_('Default USB Key PIN used for administrator reset')
    )
    # ENROLLMENT SETTINGS
    AUTH_CERT_ENROLL_ENABLED = serializers.BooleanField(
        default=False, label=_('Enrollment'),
        help_text=_('Whether to enable user certificate enrollment')
    )
    AUTH_CERT_ENROLL_VALIDITY_DAYS = serializers.IntegerField(
        default=365, label=_('Enrollment Validity Days'), min_value=1,
        help_text=_('Validity period (days) for issued certificates')
    )
    AUTH_CERT_CA_KEY_CONTENT = EncryptedField(
        default='', allow_blank=True, label=_('CA Key'),
        help_text=_('PEM content of CA private key used for certificate enrollment')
    )
    AUTH_CERT_CA_CERT_CONTENT = EncryptedField(
        default='', allow_blank=True, label=_('CA Cert'),
        help_text=_('PEM content of CA certificate used for certificate enrollment and authentication')
    )
    AUTH_CERT_CA_KEY_PASS = EncryptedField(
        default='', allow_blank=True, label=_('CA Key Password'),
        help_text=_('Password for CA private key used for certificate enrollment (leave blank if not set)')
    )
    AUTH_CERT_CA_CERT_ALGORITHM = serializers.SerializerMethodField(
        label=_('CA Cert Algorithm')
    )

    def get_AUTH_CERT_CA_CERT_ALGORITHM(self, obj):
        content = obj.get('AUTH_CERT_CA_CERT_CONTENT', '')
        algo = _detect_cert_algorithm(content)
        return algo or '-'
