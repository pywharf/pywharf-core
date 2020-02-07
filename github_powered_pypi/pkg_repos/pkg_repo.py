from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional


@dataclass
class PkgRepoConfig:
    name: str


@dataclass
class PkgRepoSecret:
    raw: str


@dataclass
class LocalPaths:
    stat: Optional[str] = None
    cache: Optional[str] = None


class UploadPackageStatus(Enum):
    FINISHED = auto()
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


@dataclass
class PkgRepo:
    config: PkgRepoConfig
    secret: PkgRepoSecret
    local_paths: LocalPaths

    def auth_read(self):
        raise NotImplementedError()

    def auth_write(self):
        raise NotImplementedError()

    def upload_package(self, name: str, meta: Dict[str, str], path: str):
        raise NotImplementedError()

    def show_task_upload_package(self, name: str, task_id: str):
        raise NotImplementedError()

    def download_package(self, name: str, output: str):
        raise NotImplementedError()

    def show_task_download_package(self, name: str, task_id: str):
        raise NotImplementedError()

    def download_index_struct(self):
        raise NotImplementedError()

    def upload_index(self, path: str):
        raise NotImplementedError()

    def download_index(self):
        raise NotImplementedError()
