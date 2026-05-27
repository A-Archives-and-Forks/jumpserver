import os
import yaml
import json
from django.conf import settings
from common.utils import get_logger
from common.decorators import Singleton
from common.const import Language


logger = get_logger(__name__)

class Setting:
    VENDOR = getattr(settings, 'VENDOR', '')


@Singleton
class CertVendorDriverConfig:

    def __init__(self):
        if not settings.AUTH_CERT:
            logger.debug('CertVendorDriverConfig: authentication backend not enabled')
            return
        config_file = getattr(settings, 'AUTH_CERT_VENDOR_DRIVER_CONFIG_FILE', None)
        self._raw = self._load_yaml(config_file)

    # ── YAML 加载 ────────────────────────────────────────────────────────────

    @staticmethod
    def _load_yaml(config_file):
        if not config_file or not os.path.isfile(config_file):
            logger.warning('CertVendorDriverConfig: config file not found: %s', config_file)
            return {}
        with open(config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    # ── CA / 证书链（只读系统设置，不允许在 YAML 中配置）────────────────────────

    @property
    def ca_cert_content(self):
        """CA 根证书 PEM 内容，只从系统设置读取。"""
        return getattr(settings, 'AUTH_CERT_CA_CERT_CONTENT', '') or ''

    @property
    def ca_key_content(self):
        """CA 私钥 PEM 内容，只从系统设置读取。"""
        return getattr(settings, 'AUTH_CERT_CA_KEY_CONTENT', '') or ''

    @property
    def ca_key_pass(self):
        """CA 私钥密码，只从系统设置读取。"""
        return str(getattr(settings, 'AUTH_CERT_CA_KEY_PASS', ''))

    @property
    def driver_js_file(self):
        """返回厂商 SDK 驱动文件的 FileResponse，供 API 层使用。"""
        return getattr(settings, 'AUTH_CERT_VENDOR_DRIVER_JS_FILE', None)

    # ── 工具 ─────────────────────────────────────────────────────────────────

    @property
    def gmssl_bin(self):
        """gmssl 二进制路径，默认 'gmssl'（系统 PATH 中查找）。"""
        return 'gmssl'

    # ── 认证流程 ──────────────────────────────────────────────────────────────

    @property
    def challenge_ttl(self):
        """Challenge 码在 Redis 中的存活时间（秒），默认 300。"""
        v = getattr(settings, 'AUTH_CERT_CHALLENGE_TTL', 300)
        return int(v)

    # ── 证书签发 ──────────────────────────────────────────────────────────────

    @property
    def enroll_enabled(self):
        """是否开启用户证书签发功能。"""
        v = getattr(settings, 'AUTH_CERT_ENROLL_ENABLED', False)
        return bool(v)

    @property
    def enroll_validity_days(self):
        """签发证书的有效期（天），默认 365。"""
        v = getattr(settings, 'AUTH_CERT_ENROLL_VALIDITY_DAYS', 365)
        return int(v)
    
    @property
    def default_pin(self):
        """证书默认 PIN 码，默认为空字符串（不设置 PIN）。"""
        v = getattr(settings, 'AUTH_CERT_DEFAULT_PIN', '')
        return str(v)

    # ── 厂商 SDK 映射（原始数据，供 API 层序列化给前端）───────────────────────
        
    @staticmethod
    def _render(data, trans_filter=None):
        """
        渲染 YAML 数据中的 Jinja2 模板表达式。
          - {{ settings.xxx }}  → 系统设置值（任何时候都生效）
          - {{ user.xxx }}      → 原样保留，留给前端 JS 运行时解析
          - {{ 'text' | trans }} → 按 trans_filter 翻译；不传则原文返回（初始化阶段）
        """
        from jinja2 import Undefined, Environment

        class KeepUndefined(Undefined):
            """未定义变量原样保留占位符，支持任意深度的属性链。"""
            def __str__(self):
                return '{{ ' + self._undefined_name + ' }}'
            def __getattr__(self, name):
                return KeepUndefined(name=f'{self._undefined_name}.{name}')

        template_str = json.dumps(data, ensure_ascii=False)
        env = Environment(undefined=KeepUndefined)
        env.filters['trans'] = trans_filter or (lambda s: s)
        rendered = env.from_string(template_str).render(settings=Setting)
        return json.loads(rendered)

    def _build_trans_filter(self, lang):
        """构建 Jinja2 | trans filter 函数，按 lang 从 YAML i18n 表查找翻译。
        未找到翻译时原文返回；语言键自动归一化（zh_hant → zh-hant）。
        """
        i18n_raw = self._raw.get('i18n') or {}
        i18n = {
            text: {
                Language.to_internal_code(lk.replace('_', '-')): lv
                for lk, lv in entries.items()
            }
            for text, entries in i18n_raw.items()
            if isinstance(entries, dict)
        }

        def trans_filter(s):
            translations = i18n.get(str(s))
            if not translations:
                return s
            return translations.get(lang) or translations.get('en') or s

        return trans_filter

    def get_vendor_sdk_data(self, lang='en'):
        """返回去掉 'cert'/'i18n' 顶层 key 后的厂商 SDK 方法映射。
        YAML 中任意字符串值均可用 {{ 'text' | trans }} 语法标记为可翻译。
        """
        lang = Language.to_internal_code(lang)
        trans_filter = self._build_trans_filter(lang)
        data = self._render(self._raw, trans_filter)
        data = self._apply_cert_config_to_data(data)
        data = {k: v for k, v in data.items() if k not in ('i18n',)}
        return data
    
    def _apply_cert_config_to_data(self, data):
        """将 'cert' 配置段渲染后添加到 data['cert']，供前端 API 层使用。"""
        cert = {
            'challenge_ttl': self.challenge_ttl,
            'enroll': {
                'enabled': self.enroll_enabled,
                'validity_days': self.enroll_validity_days,
            },
            'pin': {
                'default': self.default_pin
            }

        }
        data['cert'] = cert
        return data


cert_vd_cfg = CertVendorDriverConfig()
