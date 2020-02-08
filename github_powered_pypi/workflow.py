from dataclasses import dataclass
from typing import Dict, Optional, Tuple
import threading
from os.path import join, exists
from datetime import datetime

from github_powered_pypi.pkg_repos import (
        text_to_pkg_repo_type,
        create_pkg_repo_config,
        PkgRepoConfig,
        PkgRepo,
        LocalPaths,
)
from github_powered_pypi.utils import read_toml


@dataclass
class WorkflowStat:
    # Package repository configs.
    name_to_pkg_repo_config: Dict[str, PkgRepoConfig]
    # Package index paths [(<lock-path>, <toml-path>)...]
    name_to_index_paths: Dict[str, Tuple[str, str]]
    # Locked package repos.
    pkg_repo_global_lock: threading.Lock
    name_to_pkg_repo_lock: Dict[str, threading.Lock]
    name_to_pkg_repo: Dict[str, PkgRepo]
    name_to_pkg_repo_mtime: Dict[str, datetime]
    auth_read_expires: int
    auth_write_expires: int
    # Local paths.
    local_paths: LocalPaths


def load_pkg_repo_configs(pkg_repo_config: str) -> Dict[str, PkgRepoConfig]:
    name_to_pkg_repo_config: Dict[str, PkgRepoConfig] = {}

    for name, struct in read_toml(pkg_repo_config).items():
        if not isinstance(struct, dict) or 'type' not in struct:
            raise ValueError(f'Invalid config, name={name}, struct={struct}')

        type_ = struct.pop('type')
        pkg_repo_type = text_to_pkg_repo_type(type_)
        if not pkg_repo_type:
            raise TypeError(f'Invalid type, name={name}, type={type_}, struct={struct}')

        name_to_pkg_repo_config[name] = create_pkg_repo_config(
                pkg_repo_type,
                name=name,
                **struct,
        )

    return name_to_pkg_repo_config


def build_workflow_stat(
        pkg_repo_config: str,
        index_folder: str,
        stat_folder: Optional[str],
        cache_folder: Optional[str],
        auth_read_expires: int,
        auth_write_expires: int,
) -> WorkflowStat:
    if not exists(pkg_repo_config):
        raise ValueError(f'pkg_repo_config={pkg_repo_config} not exists.')
    if not exists(index_folder):
        raise ValueError(f'index_folder={index_folder} not exists.')

    name_to_pkg_repo_config = load_pkg_repo_configs(pkg_repo_config)

    name_to_index_paths = {}
    for name in name_to_pkg_repo_config:
        index_lock_path = join(index_folder, f'{name}.index.lock')
        index_path = join(index_folder, f'{name}.index')
        name_to_index_paths[name] = (index_lock_path, index_path)

    local_paths = LocalPaths(stat=stat_folder, cache=cache_folder)

    return WorkflowStat(
            name_to_pkg_repo_config=name_to_pkg_repo_config,
            name_to_index_paths=name_to_index_paths,
            pkg_repo_global_lock=threading.Lock(),
            name_to_pkg_repo_lock={},
            name_to_pkg_repo={},
            name_to_pkg_repo_mtime={},
            auth_read_expires=auth_read_expires,
            auth_write_expires=auth_write_expires,
            local_paths=local_paths,
    )
