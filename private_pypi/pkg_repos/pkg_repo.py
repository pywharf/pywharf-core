from abc import abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
import functools
import traceback
from typing import Dict, List, Optional, Tuple, TypeVar


@dataclass
class PkgRepoConfig:
    name: str


@dataclass
class PkgRepoSecret:
    raw: str

    @abstractmethod
    def secret_hash(self) -> str:
        pass


@dataclass
class LocalPaths:
    stat: Optional[str] = None
    cache: Optional[str] = None


class UploadPackageStatus(Enum):
    SUCCEEDED = auto()
    FAILED = auto()
    TASK_CREATED = auto()


@dataclass
class UploadPackageResult:
    status: UploadPackageStatus
    message: str = ''
    task_id: Optional[str] = None


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
class PkgRef:
    distrib: str
    package: str
    ext: str
    sha256: str
    meta: Dict[str, str]

    @abstractmethod
    def auth_url(self, config: PkgRepoConfig, secret: PkgRepoSecret) -> str:
        pass


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
    def upload_package(self, filename: str, meta: Dict[str, str], path: str) -> UploadPackageResult:
        pass

    @abstractmethod
    def view_task_upload_package(self, filename: str, task_id: str) -> UploadPackageResult:
        pass

    @abstractmethod
    def download_package(self, filename: str, output: str) -> DownloadPackageResult:
        pass

    @abstractmethod
    def view_task_download_package(self, filename: str, task_id: str) -> DownloadPackageResult:
        pass

    @abstractmethod
    def delete_package(self, filename: str) -> bool:
        pass

    @abstractmethod
    def collect_all_published_packages(self) -> List[PkgRef]:
        pass

    @abstractmethod
    def upload_index(self, path: str) -> UploadIndexResult:
        pass

    @abstractmethod
    def download_index(self, output: str) -> DownloadIndexResult:
        pass


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
