from enum import Enum, auto
from dataclasses import asdict
from typing import Dict, Type, Iterable

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
from private_pypi.utils import read_toml, write_toml


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


def dump_pkg_repo_configs(path: str, pkg_repo_configs: Iterable[PkgRepoConfig]) -> None:
    dump = {}
    for pkg_repo_config in pkg_repo_configs:
        struct = asdict(pkg_repo_config)
        name = struct.pop('name')
        dump[name] = struct

    write_toml(path, dump)


def load_pkg_repo_configs(path: str) -> Dict[str, PkgRepoConfig]:
    name_to_pkg_repo_config: Dict[str, PkgRepoConfig] = {}

    for name, struct in read_toml(path).items():
        if not isinstance(struct, dict):
            raise ValueError(f'Invalid config, name={name}, struct={struct}')

        config = create_pkg_repo_config(name=name, **struct)
        name_to_pkg_repo_config[name] = config

    return name_to_pkg_repo_config
