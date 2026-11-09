"""Stable per-environment Linux users and authenticated X11 displays.

Call filesystem preparation while the profile is stopped, from the root manager.
The profile's top-directory owner is changed last and is the migration marker.
"""
import os
from pathlib import Path
import secrets
import stat
import struct

MIN_RUNTIME_UID = 20_000
MAX_RUNTIME_UID = 2**31 - 1


class RuntimeIdentityError(RuntimeError):
    pass


def _validate_uid(uid):
    if isinstance(uid, bool) or not isinstance(uid, int) or not MIN_RUNTIME_UID <= uid <= MAX_RUNTIME_UID:
        raise RuntimeIdentityError('浏览器运行用户编号无效')
    return uid


def allocate_identity(conn, profile_id):
    """Reserve a stable UID; caller commits its transaction (usually `with db()`).

    If a transaction is already active it must be a writer transaction, as with
    BEGIN IMMEDIATE in the profile creation/start endpoint. The unique index is
    the final cross-process guard; UIDs are never recycled after profile deletion.
    """
    if not conn.in_transaction:
        conn.execute('BEGIN IMMEDIATE')
    conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS profiles_runtime_uid ON profiles(runtime_uid)')
    conn.execute('''CREATE TABLE IF NOT EXISTS runtime_uid_allocator (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1), next_uid INTEGER NOT NULL)''')
    row = conn.execute('SELECT runtime_uid FROM profiles WHERE id = ?', (profile_id,)).fetchone()
    if row is None:
        raise RuntimeIdentityError('环境不存在')
    if row['runtime_uid'] is not None:
        return _validate_uid(row['runtime_uid'])
    maximum = conn.execute('SELECT MAX(runtime_uid) FROM profiles').fetchone()[0]
    minimum_next = max(MIN_RUNTIME_UID, (maximum + 1) if maximum is not None else MIN_RUNTIME_UID)
    conn.execute('INSERT OR IGNORE INTO runtime_uid_allocator(singleton, next_uid) VALUES (1, ?)', (minimum_next,))
    value = conn.execute('SELECT next_uid FROM runtime_uid_allocator WHERE singleton = 1').fetchone()[0]
    uid = _validate_uid(max(value, minimum_next))
    conn.execute('UPDATE runtime_uid_allocator SET next_uid = ? WHERE singleton = 1', (uid + 1,))
    conn.execute('UPDATE profiles SET runtime_uid = ? WHERE id = ?', (uid, profile_id))
    return uid


def _directory_fd(path):
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise RuntimeIdentityError('环境目录必须是普通目录，不能使用符号链接') from exc


def _own_directory(fd, uid):
    os.fchown(fd, uid, uid)
    os.fchmod(fd, 0o700)


def _migrate_tree(directory_fd, uid):
    # Walk using directory file descriptors. Replacing a child with a symlink
    # between listing and opening never follows it out of the profile tree.
    for name in os.listdir(directory_fd):
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            # Link ownership is not needed to use/remove a link inside a private
            # directory. Leave it alone: even lchown has a replacement race with
            # a hardlink when an old same-UID browser is still running elsewhere.
            continue
        elif stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                _migrate_tree(child, uid)
                _own_directory(child, uid)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                opened = os.fstat(child)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink > 1:
                    raise RuntimeIdentityError('环境包含硬链接或特殊文件，无法安全迁移运行用户')
                os.fchown(child, uid, uid)
                # Preserve owner execute bits for downloaded tools, never grant
                # other browser identities access to private profile content.
                os.fchmod(child, (opened.st_mode & 0o700) | 0o600)
            finally:
                os.close(child)
        else:
            raise RuntimeIdentityError('环境包含特殊文件，无法安全迁移运行用户')


def prepare_profile_identity(profile_path, uid):
    """Migrate old UID 10001 data once and return a private HOME Path.

    A failed partial migration keeps the top directory's old owner, so the next
    attempt revisits nested files. Root ownership must not be changed beforehand.
    """
    uid = _validate_uid(uid)
    if os.geteuid() != 0:
        raise RuntimeIdentityError('浏览器用户隔离需要 Linux 容器内的管理权限')
    profile_path = Path(profile_path).absolute()
    profile_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_fd = _directory_fd(profile_path)
    try:
        info = os.fstat(root_fd)
        if info.st_uid != uid or info.st_gid != uid:
            _migrate_tree(root_fd, uid)
            # The completed ownership migration marker is written last.
            _own_directory(root_fd, uid)
        else:
            os.fchmod(root_fd, 0o700)
        try:
            os.mkdir('home', mode=0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        home_fd = os.open('home', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            _own_directory(home_fd, uid)
        finally:
            os.close(home_fd)
    except OSError as exc:
        raise RuntimeIdentityError('环境文件权限准备失败，请检查目录和文件权限') from exc
    finally:
        os.close(root_fd)
    return profile_path / 'home'


def create_xauthority(path, uid, display):
    """Create a fresh MIT-MAGIC-COOKIE-1 Xauthority and return its path string.

    `path.parent` should be a per-profile directory beneath a manager-owned
    runtime root. FamilyWild supports both Xvfb's Unix socket and x11vnc lookup.
    """
    uid = _validate_uid(uid)
    if isinstance(display, bool) or not isinstance(display, int) or not 0 <= display <= 65535:
        raise RuntimeIdentityError('显示器编号无效')
    if os.geteuid() != 0:
        raise RuntimeIdentityError('显示器认证需要 Linux 容器内的管理权限')
    path = Path(path).absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_fd = _directory_fd(path.parent)
    temporary = '.xauthority-' + secrets.token_hex(12)
    try:
        _own_directory(parent_fd, uid)
        def field(value):
            return struct.pack('!H', len(value)) + value
        content = (struct.pack('!H', 65535) + field(b'') + field(str(display).encode('ascii'))
                   + field(b'MIT-MAGIC-COOKIE-1') + field(secrets.token_bytes(16)))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as output:
                output.write(content)
                output.flush()
                os.fsync(fd)
            os.fchmod(fd, 0o600)
            os.fchown(fd, uid, uid)
        finally:
            os.close(fd)
        # Atomic replacement removes a stale symlink instead of following it.
        os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise RuntimeIdentityError('显示器认证文件创建失败') from exc
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)
    return str(path)
