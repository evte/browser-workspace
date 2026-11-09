"""Websockify Basic authentication using a private server-side secret file.

Only the file path appears in websockify's command line. The random secret is
read once at startup and is never included in errors or authentication logs.
"""
import hmac
import os
import stat

from websockify.auth_plugins import BasicHTTPAuth


class FileSecretAuth(BasicHTTPAuth):
    def __init__(self, src=None):
        super().__init__(None)
        fd = None
        try:
            before = os.lstat(src)
            if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
                raise ValueError()
            # NOFOLLOW also protects the lstat/open race. NONBLOCK avoids getting
            # stuck if an attacker replaces the file with a FIFO before open.
            fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
                    or not 1 <= info.st_size <= 512):
                raise ValueError()
            raw = os.read(fd, 513)
            secret = raw.rstrip(b'\r\n')
            if (not secret or len(raw) > 512
                    or any(value < 33 or value > 126 for value in secret)):
                raise ValueError()
            self._secret = secret
        except (OSError, TypeError, ValueError):
            raise ValueError('Desktop authentication secret file is invalid') from None
        finally:
            if fd is not None:
                os.close(fd)

    def validate_creds(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str):
            return False
        try:
            user_matches = hmac.compare_digest(username.encode('utf-8'), b'viewer')
            password_matches = hmac.compare_digest(password.encode('utf-8'), self._secret)
            return user_matches and password_matches
        except UnicodeError:
            return False
