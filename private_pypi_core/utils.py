import base64
from dataclasses import dataclass
from datetime import datetime
import json
import hashlib
import os
import os.path
import re
import shutil
from typing import Callable, TextIO, Any
import uuid
import zlib

from cryptography.fernet import Fernet
from filelock import FileLock
import toml


def write_toml(path, struct):
    with open(path, 'w') as fout:
        fout.write(toml.dumps(struct))


def read_toml(path):
    with open(path) as fin:
        return toml.loads(fin.read())


def locked_read_file(lock_path, file_path, timeout=-1):
    try:
        with FileLock(lock_path, timeout=timeout):
            if not os.path.exists(file_path):
                return True, None
            with open(file_path) as fin:
                return True, fin.read()
    except TimeoutError:
        return False, ''


def locked_read_toml(lock_path, file_path, timeout=-1):
    status, text = locked_read_file(lock_path, file_path, timeout=timeout)
    struct = None
    if status and text is not None:
        struct = toml.loads(text)
    return status, struct


def locked_write_file(lock_path, file_path, text, timeout=-1):
    try:
        with FileLock(lock_path, timeout=timeout):
            with open(file_path, 'w') as fout:
                fout.write(text)
            return True
    except TimeoutError:
        return False


def locked_write_toml(lock_path, file_path, struct, timeout=-1):
    return locked_write_file(lock_path, file_path, toml.dumps(struct), timeout=timeout)


def locked_copy_file(lock_path, src_path, dst_path, timeout=-1):
    try:
        with FileLock(lock_path, timeout=timeout):
            shutil.copyfile(src_path, dst_path)
            return True
    except TimeoutError:
        return False


def file_lock_is_busy(lock_path):
    flock = FileLock(lock_path)
    busy = False
    try:
        flock.acquire(timeout=0.1, poll_intervall=0.05)
    except TimeoutError:
        busy = True
    finally:
        flock.release()
    return busy


@dataclass
class LockedFileLikeObject(TextIO):
    # pylint: disable=abstract-method
    lock_path: str
    write_func: Callable

    def write(self, s: str) -> int:
        with FileLock(self.lock_path):
            self.write_func(s)
        return 0


def normalize_distribution_name(name: str) -> str:
    # https://www.python.org/dev/peps/pep-0503/#normalized-names
    return re.sub(r'[-_.]+', '-', name).lower()


def update_hash_algo_with_file(path: str, hash_alog: Any) -> None:
    with open(path, 'rb') as fin:
        # 64KB block.
        for block in iter(lambda: fin.read(65536), b''):
            hash_alog.update(block)


def git_hash_sha(path: str) -> str:
    # https://stackoverflow.com/questions/5290444/why-does-git-hash-object-return-a-different-hash-than-openssl-sha1
    sha1_algo = hashlib.sha1()
    size = os.path.getsize(path)
    sha1_algo.update(f'blob {size}\0'.encode())
    update_hash_algo_with_file(path, sha1_algo)
    return sha1_algo.hexdigest()


def get_secret_key():
    secret_key = os.getenv('PRIVATE_PYPI_SECRET_KEY')
    if secret_key is None:
        secret_key = str(uuid.getnode())
    return secret_key


_FERNET_SECRET_KEY = Fernet.generate_key()


def encrypt_object_to_base64(obj):
    try:
        dumped = json.dumps(obj).encode()
        compressed_dumped = zlib.compress(dumped)
        data = Fernet(_FERNET_SECRET_KEY).encrypt(compressed_dumped)
        return base64.b64encode(data).decode()
    except Exception:  # pylint: disable=broad-except
        return None


def decrypt_base64_to_object(text):
    try:
        base64_decoded = base64.b64decode(text.encode())
        compressed_dumped = Fernet(_FERNET_SECRET_KEY).decrypt(base64_decoded)
        dumped = zlib.decompress(compressed_dumped)
        return json.loads(dumped.decode())
    except Exception:  # pylint: disable=broad-except
        return None


def now_timestamp() -> int:
    return int(datetime.now().timestamp())


def encrypt_local_file_ref(path: str, filename: str, max_expired: int = 300):
    return encrypt_object_to_base64({
            'path': path,
            'filename': filename,
            'timestamp': now_timestamp(),
            'max_expired': max_expired,
    })


def decrypt_local_file_ref(text):
    msg = decrypt_base64_to_object(text)
    if msg is None:
        return False, None, None

    path = msg.get('path')
    filename = msg.get('filename')
    timestamp = msg.get('timestamp')
    max_expired = msg.get('max_expired')
    if not all((path, filename, timestamp, max_expired)):
        return False, None, None

    if now_timestamp() - timestamp >= max_expired:
        return False, None, None

    return True, path, filename


# https://github.com/pypa/pip/blob/716afdb4cf4783ba2f610c2010aa76c4ffdb22e7/src/pip/_internal/utils/filetypes.py
_ARCHIVE_EXTENSIONS = {
        '.zip',
        '.whl',
        '.tar.bz2',
        '.tbz',
        '.tar.gz',
        '.tgz',
        '.tar',
        '.tar.xz',
        '.txz',
        '.tlz',
        '.tar.lz',
        '.tar.lzma',
}

_ARCHIVE_EXTENSION_LENGTHS = sorted(set(map(len, _ARCHIVE_EXTENSIONS)), reverse=True)


def split_package_ext(filename):
    for ext_len in _ARCHIVE_EXTENSION_LENGTHS:
        if len(filename) > ext_len and filename[-ext_len:] in _ARCHIVE_EXTENSIONS:
            package = filename[:-ext_len]
            ext = filename[1 - ext_len:]  # Remove the leading dot.
            return package, ext
    return '', None
