from dataclasses import dataclass
from os import makedirs
from os.path import isdir, join, exists
import pathlib
import shutil
from typing import Dict, List, Tuple
import traceback

from filelock import FileLock
import shortuuid

from private_pypi_core.backend import (
        PkgRef,
        PkgRepo,
        PkgRepoConfig,
        PkgRepoSecret,
        UploadPackageStatus,
        UploadPackageResult,
        UploadPackageContext,
        UploadIndexStatus,
        UploadIndexResult,
        DownloadIndexStatus,
        DownloadIndexResult,
        BackendInstanceManager,
)
from private_pypi_core.utils import (
        write_toml,
        read_toml,
        git_hash_sha,
        encrypt_local_file_ref,
        split_package_ext,
)

FILE_SYSTEM_TYPE = 'file_system'


class FileSystemConfig(PkgRepoConfig):
    # Override.
    type: str = FILE_SYSTEM_TYPE
    max_file_bytes: int = 5 * 1024**3 - 1
    # File system specific.
    read_secret: str = ''
    write_secret: str = ''


class FileSystemSecret(PkgRepoSecret):
    # Override.
    type: str = FILE_SYSTEM_TYPE

    @property
    def token(self) -> str:
        return self.raw


class FileSystemPkgRef(PkgRef):
    # Override.
    type: str = FILE_SYSTEM_TYPE
    # File system specific.
    package_path: str

    def auth_url(self, config: FileSystemConfig, secret: FileSystemSecret) -> str:
        encrypted_ref = encrypt_local_file_ref(self.package_path, f'{self.package}.{self.ext}')
        if not encrypted_ref:
            raise RuntimeError(f'encrypt_local_file_ref failed ({self.package_path})')

        return f'/local_file/{encrypted_ref}#sha256={self.sha256}'


@dataclass
class FileSystemPkgRepoPrivateFields:
    ready: bool
    err_msg: str


LOCK_TIMEOUT = 0.5
META_SUFFIX = '.meta'


class FileSystemPkgRepo(PkgRepo):
    # Override.
    type: str = FILE_SYSTEM_TYPE
    # File system specific.
    config: FileSystemConfig
    secret: FileSystemSecret

    __slots__ = ('_private_fields',)

    @property
    def _pvt(self) -> FileSystemPkgRepoPrivateFields:
        return object.__getattribute__(self, '_private_fields')

    def __init__(self, **data):
        super().__init__(**data)
        object.__setattr__(
                self,
                '_private_fields',
                FileSystemPkgRepoPrivateFields(ready=True, err_msg=''),
        )

        if not isdir(self.local_paths.cache):
            self._pvt.ready = False
            self._pvt.err_msg = 'Cache path not exists'

        makedirs(self._storage_path, exist_ok=True)

    def record_error(self, error_message: str) -> None:
        self._pvt.ready = False
        self._pvt.err_msg = error_message

    def ready(self) -> Tuple[bool, str]:
        return self._pvt.ready, self._pvt.err_msg

    def auth_read(self) -> bool:
        return self.secret.token in (self.config.read_secret, self.config.write_secret)

    def auth_write(self) -> bool:
        return self.secret.token == self.config.write_secret

    def _package_lock_path(self, filename: str) -> str:
        return join(self.local_paths.lock, filename + '.lock')

    @property
    def _storage_path(self) -> str:
        return join(self.local_paths.cache, 'storage')

    @property
    def _index_path(self) -> str:
        return join(self._storage_path, 'index.toml')

    @property
    def _index_lock_path(self) -> str:
        return join(self.local_paths.lock, 'index.toml.lock')

    def _distrib_path(self, distrib: str) -> str:
        path = join(self._storage_path, distrib)
        makedirs(path, exist_ok=True)
        return path

    def _package_path(self, distrib: str, filename: str) -> str:
        distrib_path = self._distrib_path(distrib)
        return join(distrib_path, filename)

    def _package_meta_path(self, distrib: str, filename: str) -> str:
        distrib_path = self._distrib_path(distrib)
        return join(distrib_path, filename + META_SUFFIX)

    def _upload_package(self, ctx: UploadPackageContext):
        try:
            with FileLock(self._package_lock_path(ctx.filename), timeout=LOCK_TIMEOUT):
                pkg_path = self._package_path(ctx.meta_distrib, ctx.filename)
                pkg_meta_path = self._package_meta_path(ctx.meta_distrib, ctx.filename)

                if exists(pkg_path) and exists(pkg_meta_path):
                    ctx.failed = True
                    ctx.message = 'Package exists.'
                    return

                # Save package & meta.
                shutil.copyfile(ctx.path, pkg_path)
                write_toml(pkg_meta_path, ctx.meta)

            # Update index.
            pkg_refs = self.collect_all_published_packages()
            tmp_index_path = join(self.local_paths.cache, f'tmp_index_{shortuuid.uuid()}.toml')
            BackendInstanceManager.dump_pkg_refs_and_mtime(tmp_index_path, pkg_refs)
            self.upload_index(tmp_index_path)

        except TimeoutError:
            ctx.failed = True
            ctx.message = '_upload_package: Lock acquire timeout.'

        except Exception:  # pylint: disable=broad-except
            ctx.failed = True
            ctx.message = '_upload_package:\n' + traceback.format_exc()

    def upload_package(self, filename: str, meta: Dict[str, str], path: str) -> UploadPackageResult:
        ctx = UploadPackageContext(filename=filename, meta=meta, path=path)

        for action in (
                lambda _: None,  # Validate the context initialization.
                self._upload_package,
        ):
            action(ctx)
            if ctx.failed:
                break

        status = UploadPackageStatus.SUCCEEDED if not ctx.failed else UploadPackageStatus.FAILED
        return UploadPackageResult(status=status, message=ctx.message)

    def collect_all_published_packages(self) -> List[PkgRef]:
        pkg_refs = []

        storage_path = pathlib.Path(self._storage_path)
        for distrib_path in storage_path.iterdir():
            if not distrib_path.is_dir():
                continue

            filename_to_package = {}
            filename_to_meta = {}

            for child in distrib_path.iterdir():
                if child.name.endswith(META_SUFFIX):
                    filename = child.name[:-len(META_SUFFIX)]
                    filename_to_meta[filename] = str(child)
                else:
                    filename = child.name
                    filename_to_package[filename] = str(child)

            for filename in sorted(set(filename_to_package) & set(filename_to_meta)):
                meta = read_toml(filename_to_meta[filename])

                distrib = meta.get('distrib')
                sha256 = meta.get('sha256')
                if not distrib or not sha256:
                    continue

                package, ext = split_package_ext(filename)
                if not ext:
                    continue

                pkg_refs.append(
                        FileSystemPkgRef(
                                distrib=distrib,
                                package=package,
                                ext=ext,
                                sha256=sha256,
                                meta=meta,
                                package_path=filename_to_package[filename],
                        ))

        return pkg_refs

    def local_index_is_up_to_date(self, path: str) -> bool:
        try:
            with FileLock(self._index_lock_path, timeout=LOCK_TIMEOUT):
                return exists(self._index_path) \
                        and git_hash_sha(path) == git_hash_sha(self._index_path)
        except Exception:  # pylint: disable=broad-except
            return False

    def upload_index(self, path: str) -> UploadIndexResult:
        try:
            with FileLock(self._index_lock_path, timeout=LOCK_TIMEOUT):
                shutil.copyfile(path, self._index_path)
            return UploadIndexResult(status=UploadIndexStatus.SUCCEEDED)

        except TimeoutError:
            return UploadIndexResult(
                    status=UploadIndexStatus.FAILED,
                    message='upload_index: Lock acquire timeout.',
            )

        except Exception:  # pylint: disable=broad-except
            return UploadIndexResult(
                    status=UploadIndexStatus.FAILED,
                    message='upload_index:\n' + traceback.format_exc(),
            )

    def download_index(self, path: str) -> DownloadIndexResult:
        try:
            with FileLock(self._index_lock_path, timeout=LOCK_TIMEOUT):
                if not exists(self._index_path):
                    # Initialize index file.
                    BackendInstanceManager.dump_pkg_refs_and_mtime(self._index_path, [])
                shutil.copyfile(self._index_path, path)
            return DownloadIndexResult(status=DownloadIndexStatus.SUCCEEDED)

        except TimeoutError:
            return DownloadIndexResult(
                    status=DownloadIndexStatus.FAILED,
                    message='download_index: Lock acquire timeout.',
            )

        except Exception:  # pylint: disable=broad-except
            return DownloadIndexResult(
                    status=DownloadIndexStatus.FAILED,
                    message='download_index:\n' + traceback.format_exc(),
            )
