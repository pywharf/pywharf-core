from abc import abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
import os.path
import functools
import traceback
from typing import Dict, List, Optional, Tuple, TypeVar


# TODO: Using dataclass with inheritance leads to some issues, need to reconsider the design.
@dataclass
class PkgRepoConfig:
    name: str
    type: str = ''
    max_file_bytes: int = 1024**3
    local_sync_index_interval: int = 60


@dataclass
class PkgRepoSecret:
    name: str
    raw: str
    type: str = ''

    @abstractmethod
    def secret_hash(self) -> str:
        pass


@dataclass
class PkgRef:
    distrib: str
    package: str
    ext: str
    sha256: str
    meta: Dict[str, str]
    type: str = ''

    @abstractmethod
    def auth_url(self, config: PkgRepoConfig, secret: PkgRepoSecret) -> str:
        pass


@dataclass
class LocalPaths:
    index: str
    log: str
    lock: str
    job: str
    cache: str


class UploadPackageStatus(Enum):
    SUCCEEDED = auto()
    FAILED = auto()
    JOB_CREATED = auto()


@dataclass
class UploadPackageResult:
    status: UploadPackageStatus
    message: str = ''
    job_id: Optional[str] = None


class DownloadPackageStatus(Enum):
    pass  # TODO


@dataclass
class DownloadPackageResult:
    pass  # TODO


class UploadIndexStatus(Enum):
    SUCCEEDED = auto()
    FAILED = auto()


@dataclass
class UploadIndexResult:
    status: UploadIndexStatus
    message: str = ''


class DownloadIndexStatus(Enum):
    SUCCEEDED = auto()
    FAILED = auto()


@dataclass
class DownloadIndexResult:
    status: DownloadIndexStatus
    message: str = ''


@dataclass
class PkgRepo:
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
    def ping(self) -> str:
        pass

    @abstractmethod
    def upload_package(self, filename: str, meta: Dict[str, str], path: str) -> UploadPackageResult:
        pass

    @abstractmethod
    def view_job_upload_package(self, filename: str, job_id: str) -> UploadPackageResult:
        pass

    @abstractmethod
    def download_package(self, filename: str, output: str) -> DownloadPackageResult:
        pass

    @abstractmethod
    def view_job_download_package(self, filename: str, job_id: str) -> DownloadPackageResult:
        pass

    @abstractmethod
    def delete_package(self, filename: str) -> bool:
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


@dataclass
class JobPath:
    local_paths: LocalPaths
    config_name: str
    job_name: str
    filename: str
    job_id: Optional[str] = None

    def _path_join_log(self, filename: str):
        return os.path.join(self.local_paths.log, filename)

    def _path_join_lock(self, filename: str):
        return os.path.join(self.local_paths.lock, filename)

    def _path_join_job(self, filename: str):
        return os.path.join(self.local_paths.job, filename)

    def _path_join_cache(self, filename: str):
        return os.path.join(self.local_paths.cache, filename)

    # <job_type>-<distribution>
    @property
    def _job_name(self):
        return f'{self.config_name}-{self.job_name}-{self.filename}'

    @property
    def lock(self):
        return self._path_join_lock(f'{self._job_name}.lock')

    # runstat: metadata of the running job like job id.
    @property
    def runstat_lock(self):
        return self._path_join_lock(f'{self._job_name}.runstat.lock')

    @property
    def runstat(self):
        return self._path_join_job(f'{self._job_name}.runstat')

    # <job_type>-<distribution>-<job_id>
    @property
    def _job_name_id(self):
        assert self.job_id
        return f'{self._job_name}-{self.job_id}'

    # args: the input of job.
    @property
    def args(self):
        return self._path_join_job(f'{self._job_name_id}.args')

    # logging: the logging of job.
    @property
    def logging_lock(self):
        return self._path_join_lock(f'{self._job_name_id}.log.lock')

    @property
    def logging(self):
        return self._path_join_log(f'{self._job_name_id}.log')

    # final: metadata of the final result.
    @property
    def finalstat_lock(self):
        return self._path_join_lock(f'{self._job_name_id}.finalstat.lock')

    @property
    def finalstat(self):
        return self._path_join_job(f'{self._job_name_id}.finalstat')


METHOD = TypeVar('METHOD')


def record_error_if_raises(method: METHOD) -> METHOD:

    @functools.wraps(method)
    def decorated(self, *args, **kwargs):
        try:
            ret = method(self, *args, **kwargs)
            return ret
        except:
            self.record_error(traceback.format_exc())
            raise

    return decorated
