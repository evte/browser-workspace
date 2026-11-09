"""Server-only TOTP configuration, encrypted storage, and RFC 6238 codes."""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from cryptography.fernet import Fernet, InvalidToken


class TotpError(ValueError):
    """Safe to show to a client: messages never contain secret material."""


def parse_totp(value: str) -> dict:
    """Accept a Base32 secret or an otpauth TOTP provisioning URI."""
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise TotpError('2FA 密钥格式无效')
    value = value.strip()
    algorithm, digits, period = 'SHA1', 6, 30
    if '://' in value:
        try:
            uri = urlsplit(value)
            if uri.scheme.lower() != 'otpauth' or uri.netloc.lower() != 'totp' or uri.fragment:
                raise ValueError()
            pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
            params = {}
            for key, item in pairs:
                if key in params:
                    raise ValueError()
                params[key] = item
            value = params['secret']
            algorithm = params.get('algorithm', 'SHA1').upper()
            digits_text, period_text = params.get('digits', '6'), params.get('period', '30')
            if not re.fullmatch(r'[0-9]+', digits_text) or not re.fullmatch(r'[0-9]+', period_text):
                raise ValueError()
            digits, period = int(digits_text), int(period_text)
            if 'counter' in params:
                raise ValueError()
        except (ValueError, KeyError):
            raise TotpError('请输入有效的 TOTP 密钥或 otpauth://totp 链接') from None
    if algorithm not in ('SHA1', 'SHA256', 'SHA512') or digits not in (6, 8) or not 15 <= period <= 120:
        raise TotpError('2FA 支持 SHA1/SHA256/SHA512、6 或 8 位验证码和 15–120 秒周期')
    compact = re.sub(r'[ \t\r\n\f\v]', '', value).upper()
    if not re.fullmatch(r'[A-Z2-7]+={0,6}', compact):
        raise TotpError('2FA 密钥必须使用 Base32 字母和数字 2–7')
    normalized = compact.rstrip('=')
    try:
        decoded = base64.b32decode(normalized + '=' * (-len(normalized) % 8))
    except (ValueError, binascii.Error):
        raise TotpError('2FA 密钥的 Base32 编码无效') from None
    # Reject truncated input and non-canonical trailing bits instead of accepting
    # two different strings for the same bytes.
    if not 10 <= len(decoded) <= 128 or base64.b32encode(decoded).decode().rstrip('=') != normalized:
        raise TotpError('2FA 密钥长度或编码无效')
    if '=' in compact and compact != normalized + '=' * (-len(normalized) % 8):
        raise TotpError('2FA 密钥的 Base32 填充无效')
    return {'secret': normalized, 'algorithm': algorithm, 'digits': digits, 'period': period}


def generate_code(config: dict, timestamp: float) -> str:
    """Return an RFC 6238 code for Unix time in seconds, preserving zeroes."""
    secret = config['secret']
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    counter = int(timestamp // config['period'])
    digest = hmac.new(key, counter.to_bytes(8, 'big'), getattr(hashlib, config['algorithm'].lower())).digest()
    offset = digest[-1] & 0x0f
    number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    return str(number % (10 ** config['digits'])).zfill(config['digits'])


class TotpStore:
    def __init__(self, key_path: Path, encrypted_present: bool = False):
        self.key_path = Path(key_path)
        try:
            if not self.key_path.exists() and not self.key_path.is_symlink():
                if encrypted_present:
                    raise TotpError('2FA 加密密钥缺失，请从备份恢复 totp.key')
                self._create_key()
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(self.key_path, flags)
            try:
                metadata = os.fstat(fd)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
                    raise TotpError('2FA 加密密钥文件必须由服务用户持有，权限为 0600')
                key = os.read(fd, 128)
                if metadata.st_size != 44 or len(key) != 44:
                    raise TotpError('2FA 加密密钥文件无效，请恢复备份')
            finally:
                os.close(fd)
            self._fernet = Fernet(key)
        except TotpError:
            raise
        except (OSError, ValueError):
            raise TotpError('无法读取 2FA 加密密钥，请检查文件和备份') from None

    def _create_key(self):
        # Link a fully written temporary file into place without overwriting an
        # existing key. A process crash can never publish a partial key file.
        fd, temporary = tempfile.mkstemp(prefix='.totp-key-', dir=self.key_path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(Fernet.generate_key())
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, self.key_path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
        directory_fd = os.open(self.key_path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def encrypt(self, value: str) -> str:
        config = parse_totp(value)
        return self._fernet.encrypt(json.dumps(config, separators=(',', ':')).encode()).decode('ascii')

    def decrypt(self, token: str) -> dict:
        try:
            if not isinstance(token, str):
                raise ValueError()
            config = json.loads(self._fernet.decrypt(token.encode('ascii')))
            # Authenticated ciphertext must still contain a supported shape.
            if not isinstance(config, dict) or set(config) != {'secret', 'algorithm', 'digits', 'period'}:
                raise ValueError()
            if (not isinstance(config['secret'], str) or not isinstance(config['algorithm'], str)
                    or type(config['digits']) is not int or type(config['period']) is not int):
                raise ValueError()
            validated = parse_totp('otpauth://totp/environment?secret={secret}&algorithm={algorithm}&digits={digits}&period={period}'.format(**config))
            if validated != config:
                raise ValueError()
            return config
        except (InvalidToken, ValueError, TypeError, KeyError, UnicodeError):
            raise TotpError('无法读取此环境的 2FA 密钥，请恢复密钥备份或重新设置') from None

    def code(self, token: str, timestamp: float) -> dict:
        config = self.decrypt(token)
        valid_from = int(timestamp // config['period']) * config['period'] * 1000
        return {'code': generate_code(config, timestamp), 'period': config['period'],
                'valid_from': valid_from, 'valid_until': valid_from + config['period'] * 1000}
