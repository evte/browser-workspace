"""Server-owned, pinned browser binaries. No profiles or cookies live here.

Only the bundled catalog is used in production. Updating a binary requires an
explicit catalog change including the SHA-256 published for that release.
"""
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath


SYSTEM_KERNEL_ID = 'chromium-system'
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 50000
TRUSTED_RELEASES = (
    'https://github.com/babelcloud/fingerprint-chromium-arm64/releases/download/',
    'https://github.com/adryfish/fingerprint-chromium/releases/download/',
)


class KernelError(ValueError):
    """A safe, user-facing download or installation failure."""


def normalize_architecture(value):
    return {'aarch64': 'arm64', 'arm64': 'arm64',
            'x86_64': 'amd64', 'amd64': 'amd64'}.get(value.lower(), value.lower())


def _safe_path(value):
    path = PurePosixPath(value)
    if (not value or '\\' in value or '\x00' in value or path.is_absolute()
            or '..' in path.parts or not path.parts):
        raise KernelError('内核压缩包包含不安全的路径')
    return path


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class KernelStore:
    def __init__(self, root_path, catalog=None, architecture=None, host_platform=None):
        # catalog/architecture/platform injection exists for deterministic offline tests.
        self.root = Path(root_path).absolute()
        if self.root.is_symlink():
            raise KernelError('内核目录不能是符号链接')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o755)
        if os.geteuid() == 0:
            os.chown(self.root, 0, 0)
        self.root.chmod(0o755)
        self.architecture = normalize_architecture(architecture or platform.machine())
        self.host_platform = host_platform or platform.system().lower()
        if catalog is None:
            catalog = json.loads(Path(__file__).with_name('kernel_catalog.json').read_text())
        self._catalog = {}
        for entry in catalog:
            self._validate_catalog_entry(entry)
            if entry['id'] in self._catalog or entry['id'] == SYSTEM_KERNEL_ID:
                raise KernelError('内核目录存在重复编号')
            self._catalog[entry['id']] = dict(entry)
        self._guard = threading.Lock()
        self._locks = {}
        self._states = {}

    @staticmethod
    def _validate_catalog_entry(entry):
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,100}', entry.get('id', '')):
            raise KernelError('内核目录编号无效')
        if not re.fullmatch(r'[0-9a-f]{64}', entry.get('sha256', '')):
            raise KernelError('内核目录缺少固定 SHA-256')
        if not any(entry.get('url', '').startswith(prefix) for prefix in TRUSTED_RELEASES):
            raise KernelError('内核下载来源不在受信任目录中')
        if not (0 < entry.get('download_size', 0) <= MAX_DOWNLOAD_BYTES):
            raise KernelError('内核压缩包大小超出限制')
        _safe_path(entry.get('executable', ''))
        for field in ('name', 'version', 'architecture', 'engine', 'platforms', 'supported_platforms'):
            if not entry.get(field):
                raise KernelError('内核目录配置不完整')

    def _set_state(self, kernel_id, state, progress, message):
        with self._guard:
            self._states[kernel_id] = {
                'state': state, 'progress': progress,
                'download_progress': progress, 'message': message,
            }

    def _compatible(self, entry):
        return (normalize_architecture(entry['architecture']) == self.architecture
                and self.host_platform in entry['platforms'])

    @staticmethod
    def _system_executable():
        return shutil.which('chromium') or shutil.which('chromium-browser')

    def get_kernel(self, kernel_id):
        if kernel_id == SYSTEM_KERNEL_ID:
            executable = self._system_executable()
            return {
                'id': SYSTEM_KERNEL_ID, 'name': '系统 Chromium', 'version': 'system',
                'architecture': self.architecture, 'engine': 'chromium',
                'platforms': ['linux'], 'supported_platforms': ['linux'],
                'native': True, 'recommended': False,
                'state': 'ready' if executable else 'unavailable',
                'progress': 100 if executable else 0,
                'download_progress': 100 if executable else 0,
                'message': '已安装' if executable else '服务器未安装系统 Chromium',
            }
        entry = self._catalog.get(kernel_id)
        if entry is None:
            raise KernelError('未知的浏览器内核')
        public = {key: value for key, value in entry.items()
                  if key not in ('url', 'sha256', 'executable')}
        public['native'] = self._compatible(entry)
        public['recommended'] = public['native'] and entry['engine'] == 'fingerprint-chromium'
        if not public['native']:
            status = {'state': 'unavailable', 'progress': 0,
                      'message': '此内核不支持当前服务器架构或操作系统'}
        else:
            with self._guard:
                status = dict(self._states.get(kernel_id, {}))
            if status.get('state') not in ('downloading', 'extracting', 'verifying'):
                if self._installed_executable(entry):
                    status = {'state': 'ready', 'progress': 100, 'message': '已安装'}
                elif status.get('state') != 'error':
                    status = {'state': 'missing', 'progress': 0, 'message': '首次启动时自动下载'}
        status['download_progress'] = status['progress']
        return dict(public, **status)

    def list_kernels(self):
        return [self.get_kernel(SYSTEM_KERNEL_ID)] + [self.get_kernel(key) for key in self._catalog]

    def _installed_executable(self, entry, verify_hash=False):
        install = self.root / entry['id']
        try:
            if install.is_symlink() or not install.is_dir():
                return None
            metadata_path = install / '.kernel-install.json'
            if metadata_path.is_symlink():
                return None
            metadata = json.loads(metadata_path.read_text())
            if any(metadata.get(key) != entry[key] for key in ('id', 'version', 'sha256', 'executable')):
                return None
            executable = install.joinpath(*_safe_path(entry['executable']).parts)
            for part in (executable, *executable.parents):
                if part == self.root:
                    break
                info = part.stat()
                if (part.is_symlink() or info.st_mode & 0o022
                        or info.st_uid != os.geteuid()):
                    return None
            info = executable.stat()
            if (not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK)
                    or info.st_size != metadata.get('executable_size')
                    or info.st_mtime_ns != metadata.get('executable_mtime_ns')):
                return None
            if verify_hash and _sha256(executable) != metadata.get('executable_sha256'):
                return None
            return executable
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def ensure_kernel(self, kernel_id):
        if kernel_id == SYSTEM_KERNEL_ID:
            executable = self._system_executable()
            if not executable:
                raise KernelError('服务器未安装系统 Chromium')
            return executable
        entry = self._catalog.get(kernel_id)
        if entry is None:
            raise KernelError('未知的浏览器内核')
        if not self._compatible(entry):
            raise KernelError('此内核不支持当前服务器架构或操作系统')
        with self._guard:
            lock = self._locks.setdefault(kernel_id, threading.Lock())
        with lock:
            # flock also serializes multiple service processes sharing this volume.
            lock_path = self.root / ('.' + kernel_id + '.lock')
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'a+b') as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                return self._ensure_locked(entry)

    def _ensure_locked(self, entry):
        kernel_id = entry['id']
        executable = self._installed_executable(entry, verify_hash=True)
        if executable:
            self._set_state(kernel_id, 'ready', 100, '已安装')
            return str(executable)
        archive = self.root / ('.' + kernel_id + '.download')
        staging = self.root / ('.' + kernel_id + '.installing')
        destination = self.root / kernel_id
        try:
            self._remove(archive)
            self._remove(staging)
            self._remove(destination)  # Only an incomplete or invalid install reaches here.
            self._set_state(kernel_id, 'downloading', 0, '正在下载内核')
            self._download(entry, archive)
            self._set_state(kernel_id, 'extracting', 100, '正在解压内核')
            staging.mkdir(mode=0o755)
            self._extract(archive, staging)
            executable = staging.joinpath(*_safe_path(entry['executable']).parts)
            if executable.is_symlink() or not executable.is_file():
                raise KernelError('压缩包缺少预期的浏览器可执行文件')
            executable.chmod(0o755)
            self._set_state(kernel_id, 'verifying', 100, '正在验证内核')
            self._verify_binary(executable, entry)
            info = executable.stat()
            metadata = {key: entry[key] for key in ('id', 'version', 'sha256', 'executable')}
            metadata.update(executable_size=info.st_size,
                            executable_mtime_ns=info.st_mtime_ns,
                            executable_sha256=_sha256(executable))
            metadata_path = staging / '.kernel-install.json'
            if metadata_path.exists() or metadata_path.is_symlink():
                raise KernelError('压缩包包含保留的安装元数据文件')
            metadata_path.write_text(json.dumps(metadata))
            metadata_path.chmod(0o644)
            staging.rename(destination)
            self._set_state(kernel_id, 'ready', 100, '已安装')
            return str(destination / entry['executable'])
        except KernelError as exc:
            self._set_state(kernel_id, 'error', 0, str(exc))
            raise
        except (OSError, tarfile.TarError, ValueError) as exc:
            message = '内核下载或安装失败，请检查服务器网络、磁盘空间和运行库后重试'
            self._set_state(kernel_id, 'error', 0, message)
            raise KernelError(message) from exc
        finally:
            self._remove(archive)
            self._remove(staging)

    @staticmethod
    def _remove(path):
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.exists():
            shutil.rmtree(path)

    def _download(self, entry, target):
        request = urllib.request.Request(entry['url'], headers={'User-Agent': 'ServerBrowserKernel/1.0'})
        digest = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(request, timeout=60) as response, target.open('xb') as output:
                if urllib.parse.urlsplit(response.geturl()).scheme != 'https':
                    raise KernelError('内核下载地址必须使用 HTTPS')
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) != entry['download_size']:
                    raise KernelError('内核压缩包大小与固定版本不一致')
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > entry['download_size'] or size > MAX_DOWNLOAD_BYTES:
                        raise KernelError('内核压缩包大小超出限制')
                    output.write(chunk)
                    digest.update(chunk)
                    progress = min(99, int(size * 100 / entry['download_size']))
                    self._set_state(entry['id'], 'downloading', progress, '正在下载内核')
                output.flush()
                os.fsync(output.fileno())
        except (urllib.error.URLError, TimeoutError) as exc:
            raise KernelError('内核下载失败，请检查服务器网络后重试') from exc
        if size != entry['download_size'] or digest.hexdigest() != entry['sha256']:
            raise KernelError('内核压缩包 SHA-256 校验失败，请重新下载')

    @staticmethod
    def _extract(archive, destination):
        # Validate the complete member map before writing; never use extractall.
        with tarfile.open(archive, 'r:xz') as bundle:
            members = {}
            link_targets = {}
            total = 0
            for item in bundle:
                path = _safe_path(item.name)
                key = str(path)
                if key in members:
                    if item.isdir() and members[key].isdir():
                        continue
                    raise KernelError('内核压缩包存在重复文件路径')
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise KernelError('内核压缩包文件数量超限')
                if not (item.isdir() or item.isfile() or item.issym() or item.islnk()):
                    raise KernelError('内核压缩包包含不支持的设备或特殊文件')
                total += item.size
                if total > MAX_EXTRACTED_BYTES or item.size < 0:
                    raise KernelError('内核解压大小超出限制')
                members[key] = item
            for key, item in members.items():
                for parent in PurePosixPath(key).parents:
                    ancestor = members.get(str(parent))
                    if ancestor is not None and not ancestor.isdir():
                        raise KernelError('内核压缩包包含链接路径冲突')
                if item.issym() or item.islnk():
                    link = PurePosixPath(item.linkname)
                    if link.is_absolute() or '\\' in item.linkname or '\x00' in item.linkname:
                        raise KernelError('内核压缩包包含不安全的链接')
                    # Resolve '..' without consulting the filesystem. No link chains.
                    pieces = list(PurePosixPath(key).parent.parts) if item.issym() else []
                    for piece in link.parts:
                        if piece == '..':
                            if not pieces:
                                raise KernelError('内核压缩包链接超出安装目录')
                            pieces.pop()
                        elif piece != '.':
                            pieces.append(piece)
                    linked = members.get(str(PurePosixPath(*pieces)))
                    if linked is None or not (linked.isfile() or (item.issym() and linked.isdir())):
                        raise KernelError('内核压缩包包含无效链接或链接链')
                    for parent in PurePosixPath(*pieces).parents:
                        ancestor = members.get(str(parent))
                        if ancestor is not None and not ancestor.isdir():
                            raise KernelError('内核压缩包链接目标存在路径冲突')
                    link_targets[key] = destination.joinpath(*pieces)
            # Parents are created with no group/other write bits; all files are
            # daemon-owned. In the service the daemon is root and browsers are UID 10001.
            for key, item in members.items():
                target = destination.joinpath(*PurePosixPath(key).parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                if item.isdir():
                    target.mkdir(exist_ok=True, mode=0o755)
                    target.chmod(0o755)
                elif item.isfile():
                    source = bundle.extractfile(item)
                    if source is None:
                        raise KernelError('内核压缩包文件无法读取')
                    with source, target.open('xb') as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    target.chmod(0o755 if item.mode & 0o111 else 0o644)
            # mkdir(parents=True) can create implicit parents with the process
            # umask, so normalize those too before exposing the installed tree.
            for directory, _, _ in os.walk(destination, followlinks=False):
                Path(directory).chmod(0o755)
            for key, item in members.items():
                target = destination.joinpath(*PurePosixPath(key).parts)
                if item.issym():
                    target.symlink_to(item.linkname)
                elif item.islnk():
                    os.link(link_targets[key], target)

    @staticmethod
    def _verify_binary(executable, entry):
        try:
            result = subprocess.run([str(executable), '--version'], capture_output=True,
                                    text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise KernelError('内核无法运行，请检查服务器架构及所需运行库') from exc
        if result.returncode != 0 or entry['version'] not in result.stdout:
            raise KernelError('内核版本或运行库验证失败，请检查服务器兼容性')
