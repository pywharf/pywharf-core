from enum import Enum, auto
from typing import Dict, Type

from private_pypi.pkg_repos.github import (
        GITHUB_TYPE,
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
from private_pypi.pkg_repos.index import (
        PkgRepoIndex,
        build_pkg_repo_index_from_pkg_refs,
        dump_pkg_repo_index,
        load_pkg_repo_index,
)


class PkgRepoType(Enum):
    GITHUB = auto()


TEXT_TO_PKG_REPO_TYPE: Dict[str, PkgRepoType] = {
        GITHUB_TYPE: PkgRepoType.GITHUB,
}
PKG_REPO_TYPE_TO_TEXT = {val: key for key, val in TEXT_TO_PKG_REPO_TYPE.items()}


def text_to_pkg_repo_type(text: str) -> PkgRepoType:
    return TEXT_TO_PKG_REPO_TYPE[text.lower()]


def pkg_repo_type_to_text(pkg_repo_type: PkgRepoType) -> str:
    return PKG_REPO_TYPE_TO_TEXT[pkg_repo_type]


PKG_REPO_CONFIG_CLS: Dict[PkgRepoType, Type[PkgRepoConfig]] = {
        PkgRepoType.GITHUB: GitHubConfig,
}


def create_pkg_repo_config(**kwargs) -> PkgRepoConfig:
    pkg_repo_type = text_to_pkg_repo_type(kwargs['type'])
    return PKG_REPO_CONFIG_CLS[pkg_repo_type](**kwargs)


PKG_REPO_SECRET_CLS: Dict[PkgRepoType, Type[PkgRepoSecret]] = {
        PkgRepoType.GITHUB: GitHubAuthToken,
}


def create_pkg_repo_secret(**kwargs) -> PkgRepoSecret:
    pkg_repo_type = text_to_pkg_repo_type(kwargs['type'])
    return PKG_REPO_SECRET_CLS[pkg_repo_type](**kwargs)


PKG_REF_CLS: Dict[PkgRepoType, Type[PkgRef]] = {
        PkgRepoType.GITHUB: GitHubPkgRef,
}


def create_pkg_ref(**kwargs) -> PkgRef:
    pkg_repo_type = text_to_pkg_repo_type(kwargs['type'])
    return PKG_REF_CLS[pkg_repo_type](**kwargs)


PKG_REPO_CLS: Dict[PkgRepoType, Type[PkgRepo]] = {
        PkgRepoType.GITHUB: GitHubPkgRepo,
}


def create_pkg_repo(config: PkgRepoConfig, secret: PkgRepoSecret,
                    local_paths: LocalPaths) -> PkgRepo:
    pkg_repo_type = text_to_pkg_repo_type(config.type)
    return PKG_REPO_CLS[pkg_repo_type](config=config, secret=secret, local_paths=local_paths)
