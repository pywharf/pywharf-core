from enum import Enum, auto
from typing import Dict, Type

from private_pypi.pkg_repos.github import (
        GitHubAuthToken,
        GitHubConfig,
        GitHubPkgRef,
        GitHubPkgRepo,
)
from private_pypi.pkg_repos.pkg_repo import (
        LocalPaths,
        PkgRef,
        PkgRepo,
        PkgRepoConfig,
        PkgRepoSecret,
        UploadPackageResult,
        UploadPackageStatus,
        UploadIndexStatus,
        UploadIndexResult,
        DownloadIndexStatus,
        DownloadIndexResult,
)


class PkgRepoType(Enum):
    GITHUB = auto()


def text_to_pkg_repo_type(name: str) -> PkgRepoType:
    return getattr(PkgRepoType, name.upper())


def pkg_repo_type_to_text(pkg_repo_type: PkgRepoType) -> str:
    return pkg_repo_type.name.lower()


PKG_REPO_CONFIG_CLS: Dict[PkgRepoType, Type[PkgRepoConfig]] = {
        PkgRepoType.GITHUB: GitHubConfig,
}


def create_pkg_repo_config(pkg_repo_type: PkgRepoType, *args, **kwargs) -> PkgRepoConfig:
    return PKG_REPO_CONFIG_CLS[pkg_repo_type](*args, **kwargs)


PKG_REPO_SECRET_CLS: Dict[PkgRepoType, Type[PkgRepoSecret]] = {
        PkgRepoType.GITHUB: GitHubAuthToken,
}


def create_pkg_repo_secret(pkg_repo_type: PkgRepoType, *args, **kwargs) -> PkgRepoSecret:
    return PKG_REPO_SECRET_CLS[pkg_repo_type](*args, **kwargs)


PKG_REPO_CLS: Dict[PkgRepoType, Type[PkgRepo]] = {
        PkgRepoType.GITHUB: GitHubPkgRepo,
}


def create_pkg_repo(pkg_repo_type, config, secret, local_paths) -> PkgRepo:
    return PKG_REPO_CLS[pkg_repo_type](config=config, secret=secret, local_paths=local_paths)


PKG_REF_CLS: Dict[PkgRepoType, Type[PkgRef]] = {
        PkgRepoType.GITHUB: GitHubPkgRef,
}


def create_pkg_ref(pkg_repo_type: PkgRepoType, *args, **kwargs) -> PkgRef:
    return PKG_REF_CLS[pkg_repo_type](*args, **kwargs)
