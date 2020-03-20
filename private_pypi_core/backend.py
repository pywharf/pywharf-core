from abc import abstractmethod
from enum import Enum, auto
import functools
import hashlib
import importlib
import os
import pkgutil
import traceback
from typing import Callable, Dict, List, Tuple, Iterable, TypeVar, Type, Optional
import inspect

# TODO: follows https://github.com/PyCQA/pylint/issues/1524
from pydantic import BaseModel  # pylint: disable=no-name-in-module

from private_pypi_core.utils import (
        read_toml,
        write_toml,
        normalize_distribution_name,
        now_timestamp,
        update_hash_algo_with_file,
)


####################
# Static I/O types #
####################
class LocalPaths(BaseModel):
    index: str
    log: str
    lock: str
    job: str
    cache: str

    def makedirs(self):
        os.makedirs(self.index, exist_ok=True)
        os.makedirs(self.log, exist_ok=True)
        os.makedirs(self.lock, exist_ok=True)
        os.makedirs(self.job, exist_ok=True)
        os.makedirs(self.cache, exist_ok=True)


class UploadPackageStatus(Enum):
    SUCCEEDED = auto()
    CONFLICT = auto()
    BAD_REQUEST = auto()


class UploadPackageResult(BaseModel):
    status: UploadPackageStatus
    message: str = ''


class UploadPackageContext(BaseModel):
    filename: str
    path: str
    meta: Dict[str, str] = {}
    failed: bool = False
    message: str = ''

    def __init__(self, **data):
        super().__init__(**data)

        # Fill distribution name.
        if not self.meta.get('distrib'):
            name = self.meta.get('name')
            if name:
                self.meta['distrib'] = normalize_distribution_name(name)
            else:
                self.failed = True
                self.message = 'Cannot generate the distribution name.'
        assert self.meta_distrib

        # SHA256 checksum, also suggested by PEP-503.
        if not self.meta.get('sha256'):
            sha256_algo = hashlib.sha256()
            update_hash_algo_with_file(self.path, sha256_algo)
            self.meta['sha256'] = sha256_algo.hexdigest()
        assert self.meta_sha256

    @property
    def meta_distrib(self) -> str:
        return self.meta['distrib']

    @property
    def meta_sha256(self) -> str:
        return self.meta['sha256']


class UploadIndexStatus(Enum):
    SUCCEEDED = auto()
    FAILED = auto()


class UploadIndexResult(BaseModel):
    status: UploadIndexStatus
    message: str = ''


class DownloadIndexStatus(Enum):
    SUCCEEDED = auto()
    FAILED = auto()


class DownloadIndexResult(BaseModel):
    status: DownloadIndexStatus
    message: str = ''


####################################
# Interfaces of package repository #
####################################
class PkgRepoConfig(BaseModel):
    type: str
    name: str
    max_file_bytes: int = 1024**3
    sync_index_interval: int = 60


class PkgRepoSecret(BaseModel):
    type: str
    name: str
    raw: str

    def secret_hash(self) -> str:
        sha256_algo = hashlib.sha256()
        sha256_algo.update(self.raw.encode())
        return f'{self.name}-{sha256_algo.hexdigest()}'


class PkgRef(BaseModel):
    type: str
    distrib: str
    package: str
    ext: str
    sha256: str
    meta: Dict[str, str]

    @abstractmethod
    def auth_url(self, config: PkgRepoConfig, secret: PkgRepoSecret) -> str:
        pass


class PkgRepo(BaseModel):
    type: str
    config: PkgRepoConfig
    secret: PkgRepoSecret
    local_paths: LocalPaths

    @abstractmethod
    def record_error(self, error_message: str) -> None:
        pass

    @abstractmethod
    def ready(self) -> Tuple[bool, str]:
        pass

    @abstractmethod
    def auth_read(self) -> bool:
        pass

    @abstractmethod
    def auth_write(self) -> bool:
        pass

    @abstractmethod
    def upload_package(self, filename: str, meta: Dict[str, str], path: str) -> UploadPackageResult:
        pass

    @abstractmethod
    def collect_all_published_packages(self) -> List[PkgRef]:
        pass

    @abstractmethod
    def local_index_is_up_to_date(self, path: str) -> bool:
        pass

    @abstractmethod
    def upload_index(self, path: str) -> UploadIndexResult:
        pass

    @abstractmethod
    def download_index(self, path: str) -> DownloadIndexResult:
        pass


class BackendRegistration:
    type: str = ''
    pkg_repo_config_cls: Type[PkgRepoConfig] = PkgRepoConfig
    pkg_repo_secret_cls: Type[PkgRepoSecret] = PkgRepoSecret
    pkg_repo_cls: Type[PkgRepo] = PkgRepo
    pkg_ref_cls: Type[PkgRef] = PkgRef
    cli_name_to_func: Dict[str, Callable[[], int]] = {}


######################
# Backend reflection #
######################
class BackendInstanceManager:

    def __init__(self) -> None:
        self._type_to_registration: Dict[str, Type[BackendRegistration]] = {}

        # Namespace package root.
        root_module = importlib.import_module('.', 'private_pypi_backends')
        # Find all submodules.
        for module_info in pkgutil.iter_modules(
                root_module.__path__,  # type: ignore
                root_module.__name__ + '.',
        ):
            # Load module.
            module = importlib.import_module(module_info.name)

            # Find the registration class.
            registration = None
            for obj in module.__dict__.values():
                if inspect.isclass(obj) \
                        and issubclass(obj, BackendRegistration) and obj is not BackendRegistration:
                    registration = obj

            if registration is None:
                continue

            # Type validation.
            assert issubclass(registration, BackendRegistration)

            assert registration.type

            assert issubclass(registration.pkg_repo_config_cls, PkgRepoConfig) \
                    and registration.pkg_repo_config_cls is not PkgRepoConfig

            assert issubclass(registration.pkg_repo_secret_cls, PkgRepoSecret) \
                    and registration.pkg_repo_secret_cls is not PkgRepoSecret

            assert issubclass(registration.pkg_repo_cls, PkgRepo) \
                    and registration.pkg_repo_cls is not PkgRepo

            assert issubclass(registration.pkg_ref_cls, PkgRef) \
                    and registration.pkg_ref_cls is not PkgRef

            self._type_to_registration[registration.type] = registration

    @property
    def all_registrations(self) -> Iterable[Type[BackendRegistration]]:
        return self._type_to_registration.values()

    def _registration(self, **kwargs) -> Type[BackendRegistration]:
        assert 'type' in kwargs
        assert kwargs['type'] in self._type_to_registration
        return self._type_to_registration[kwargs['type']]

    def create_pkg_repo_config(self, **kwargs) -> PkgRepoConfig:
        return self._registration(**kwargs).pkg_repo_config_cls(**kwargs)

    def create_pkg_repo_secret(self, **kwargs) -> PkgRepoSecret:
        name = kwargs.get('name')
        type_ = kwargs.get('type')
        if not name or not type_:
            raise ValueError(f'name or type not set. kwargs={kwargs}')

        raw = kwargs.get('raw')
        env = kwargs.get('env')
        if raw and env:
            raise ValueError(f'Can either set raw or env, but not both. kwargs={kwargs}')

        struct = {'name': name, 'type': type_}
        if raw:
            # Harcoded secret.
            struct['raw'] = raw
        else:
            # Load from the environment variable.
            assert env
            raw_from_env = os.getenv(env)
            if not raw_from_env:
                raise ValueError(f'{env} is not set. name={name}, struct={struct}')
            struct['raw'] = raw_from_env

        return self._registration(type=type_).pkg_repo_secret_cls(**struct)

    def create_pkg_repo(self, **kwargs) -> PkgRepo:
        return self._registration(**kwargs).pkg_repo_cls(**kwargs)

    def create_pkg_ref(self, **kwargs) -> PkgRef:
        return self._registration(**kwargs).pkg_ref_cls(**kwargs)

    def load_pkg_repo_configs(self, path: str) -> Dict[str, PkgRepoConfig]:
        name_to_pkg_repo_config: Dict[str, PkgRepoConfig] = {}

        for name, struct in read_toml(path).items():
            if not isinstance(struct, dict):
                raise ValueError(f'Invalid pkg_repo_config, name={name}, struct={struct}')

            name = name.lower()
            config = self.create_pkg_repo_config(name=name, **struct)
            name_to_pkg_repo_config[name] = config

        return name_to_pkg_repo_config

    @staticmethod
    def dump_pkg_repo_configs(path: str, pkg_repo_configs: Iterable[PkgRepoConfig]) -> None:
        dump = {}

        for pkg_repo_config in pkg_repo_configs:
            struct = pkg_repo_config.dict()
            name = struct.pop('name')
            name = name.lower()
            dump[name] = struct

        write_toml(path, dump)

    def load_pkg_repo_secrets(self, path: str) -> Dict[str, PkgRepoSecret]:
        name_to_pkg_repo_secret: Dict[str, PkgRepoSecret] = {}

        for name, struct in read_toml(path).items():
            if not isinstance(struct, dict):
                raise ValueError(f'Invalid pkg_repo_secret, name={name}, struct={struct}')

            secret = self.create_pkg_repo_secret(name=name, **struct)
            name_to_pkg_repo_secret[name] = secret

        return name_to_pkg_repo_secret

    @staticmethod
    def dump_pkg_repo_secrets(
            path: str,
            pkg_repo_secrets: Iterable[PkgRepoSecret],
            name_to_env: Optional[Dict[str, str]] = None,
    ) -> None:
        dump = {}

        for pkg_repo_config in pkg_repo_secrets:
            struct = pkg_repo_config.dict()
            name = struct['name'].lower()

            dump_struct = {'type': struct['type']}
            if not name_to_env:
                dump_struct['raw'] = struct['raw']
            else:
                assert name in name_to_env
                dump_struct['env'] = name_to_env[name]

            dump[name] = dump_struct

        write_toml(path, dump)

    def load_pkg_refs_and_mtime(self, path: str) -> Tuple[List[PkgRef], int]:
        struct = read_toml(path)
        pkg_refs = [self.create_pkg_ref(**struct_pkg_ref) for struct_pkg_ref in struct['pkgs']]
        mtime = struct['mtime']
        return pkg_refs, mtime

    @staticmethod
    def dump_pkg_refs_and_mtime(path: str, pkg_refs: Iterable[PkgRef]) -> None:
        struct = {
                'pkgs': [pkg_ref.dict() for pkg_ref in pkg_refs],
                'mtime': now_timestamp(),
        }
        write_toml(path, struct)


##########
# Helper #
##########
def basic_model_get_default(basic_model_cls: BaseModel, key: str):
    assert key in basic_model_cls.__fields__
    return basic_model_cls.__fields__[key].default


_METHOD = TypeVar('_METHOD')


def record_error_if_raises(method: _METHOD) -> _METHOD:

    @functools.wraps(method)
    def decorated(self, *args, **kwargs):
        try:
            ret = method(self, *args, **kwargs)
            return ret
        except:
            self.record_error(traceback.format_exc())
            raise

    return decorated


class PkgRepoIndex:

    def __init__(self, pkg_refs: List[PkgRef], mtime: int) -> None:
        self._mtime = mtime

        self._distrib_to_pkg_refs: Dict[str, List[PkgRef]] = {}
        self._package_to_pkg_ref: Dict[str, PkgRef] = {}

        for pkg_ref in pkg_refs:
            self.add_pkg_ref(pkg_ref)

    @property
    def mtime(self) -> int:
        return self._mtime

    @property
    def all_distributions(self) -> Iterable[str]:
        return self._distrib_to_pkg_refs.keys()

    def add_pkg_ref(self, pkg_ref: PkgRef) -> None:
        if pkg_ref.package in self._package_to_pkg_ref:
            raise KeyError(f'package={pkg_ref.package} duplicated.')

        if pkg_ref.distrib not in self._distrib_to_pkg_refs:
            self._distrib_to_pkg_refs[pkg_ref.distrib] = []

        self._distrib_to_pkg_refs[pkg_ref.distrib].append(pkg_ref)
        self._package_to_pkg_ref[pkg_ref.package] = pkg_ref

    def get_pkg_refs(self, query_distrib: str) -> Optional[List[PkgRef]]:
        distrib = normalize_distribution_name(query_distrib)
        return self._distrib_to_pkg_refs.get(distrib)

    def get_single_pkg_ref(self, query_distrib: str, query_package: str) -> Optional[PkgRef]:
        pkg_ref = self._package_to_pkg_ref.get(query_package)
        if pkg_ref is None or normalize_distribution_name(query_distrib) != pkg_ref.distrib:
            return None
        return pkg_ref
