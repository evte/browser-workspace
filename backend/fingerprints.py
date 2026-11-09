"""Persisted browser identity; use the engine's own UA and client hints together."""
import secrets
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, field_validator


class Fingerprint(BaseModel):
    seed: int = Field(default_factory=lambda: secrets.randbelow(2**31 - 1) + 1, ge=1, le=2**32 - 1)
    platform: Literal['linux', 'windows', 'macos'] = 'linux'
    language: str = Field(default='en-US', pattern=r'^[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8}){0,2}$')
    timezone: str = Field(default='UTC', max_length=80)
    hardware_concurrency: int = Field(default=8, ge=1, le=128)
    width: int = Field(default=1365, ge=800, le=3840)
    height: int = Field(default=768, ge=600, le=2160)

    @field_validator('timezone')
    @classmethod
    def valid_timezone(cls, value):
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError('请使用有效的 IANA 时区，如 Asia/Shanghai') from None
        return value


def browser_flags(kernel, fingerprint):
    identity = Fingerprint(**fingerprint)
    flags = [f'--window-size={identity.width},{identity.height}']
    if kernel['engine'] == 'fingerprint-chromium':
        language = identity.language
        languages = ','.join(dict.fromkeys([language, language.split('-')[0]]))
        flags += [f'--fingerprint={identity.seed}', f'--fingerprint-platform={identity.platform}',
                  '--fingerprint-brand=Chrome', f"--fingerprint-brand-version={kernel['version']}",
                  f'--fingerprint-hardware-concurrency={identity.hardware_concurrency}',
                  f'--lang={language}', f'--accept-lang={languages}', f'--timezone={identity.timezone}']
    return flags
