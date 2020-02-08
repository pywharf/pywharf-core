from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, DefaultDict, Optional, Tuple, TypeVar, Generic
import threading
from os.path import join, exists
from datetime import datetime

from github_powered_pypi.pkg_repos import (
        create_pkg_repo,
        text_to_pkg_repo_type,
        create_pkg_repo_config,
        PkgRepoConfig,
        PkgRepo,
        LocalPaths,
        PkgRepoSecret,
        PkgRepoType,
)
from github_powered_pypi.utils import read_toml

SHST = TypeVar('SHST')


class SecretHashedStorage(Generic[SHST]):

    def __init__(self) -> None:
        self._hash_to_item: Dict[str, SHST] = {}

    def has_item(self, secret: PkgRepoSecret) -> bool:
        return secret.secret_hash() in self._hash_to_item

    def set_item(self, secret: PkgRepoSecret, item: SHST) -> None:
        self._hash_to_item[secret.secret_hash()] = item

    def get_item(self, secret: PkgRepoSecret) -> SHST:
        return self._hash_to_item[secret.secret_hash()]


@dataclass
class WorkflowStat:
    # Package repository configs.
    rtype_to_pkg_repo_config: Dict[PkgRepoType, PkgRepoConfig]
    # Package index paths [(<lock-path>, <toml-path>)...]
    rtype_to_index_paths: Dict[PkgRepoType, Tuple[str, str]]
    # Locked package repos.
    auth_read_expires: int
    auth_write_expires: int
    pkg_repo_global_lock: threading.Lock
    rtype_to_pkg_repo_lock_shstg: DefaultDict[PkgRepoType, SecretHashedStorage[threading.RLock]]
    rtype_to_pkg_repo_shstg: DefaultDict[PkgRepoType, SecretHashedStorage[PkgRepo]]
    rtype_to_pkg_repo_mtime_shstg: DefaultDict[PkgRepoType, SecretHashedStorage[datetime]]
    # Local paths.
    local_paths: LocalPaths


def load_pkg_repo_configs(pkg_repo_config: str) -> Dict[PkgRepoType, PkgRepoConfig]:
    rtype_to_pkg_repo_config: Dict[PkgRepoType, PkgRepoConfig] = {}

    for name, struct in read_toml(pkg_repo_config).items():
        if not isinstance(struct, dict) or 'type' not in struct:
            raise ValueError(f'Invalid config, name={name}, struct={struct}')

        type_ = struct.pop('type')
        pkg_repo_type = text_to_pkg_repo_type(type_)
        if not pkg_repo_type:
            raise TypeError(f'Invalid type, name={name}, type={type_}, struct={struct}')

        rtype_to_pkg_repo_config[pkg_repo_type] = create_pkg_repo_config(
                pkg_repo_type,
                name=name,
                **struct,
        )

    return rtype_to_pkg_repo_config


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

    rtype_to_pkg_repo_config = load_pkg_repo_configs(pkg_repo_config)

    rtype_to_index_paths = {}
    for name in rtype_to_pkg_repo_config:
        index_lock_path = join(index_folder, f'{name}.index.lock')
        index_path = join(index_folder, f'{name}.index')
        rtype_to_index_paths[name] = (index_lock_path, index_path)

    local_paths = LocalPaths(stat=stat_folder, cache=cache_folder)

    return WorkflowStat(
            rtype_to_pkg_repo_config=rtype_to_pkg_repo_config,
            rtype_to_index_paths=rtype_to_index_paths,
            auth_read_expires=auth_read_expires,
            auth_write_expires=auth_write_expires,
            pkg_repo_global_lock=threading.Lock(),
            rtype_to_pkg_repo_lock_shstg=defaultdict(SecretHashedStorage),
            rtype_to_pkg_repo_shstg=defaultdict(SecretHashedStorage),
            rtype_to_pkg_repo_mtime_shstg=defaultdict(SecretHashedStorage),
            local_paths=local_paths,
    )


def should_initialize_pkg_repo(
        wstat: WorkflowStat,
        pkg_repo_type: PkgRepoType,
        pkg_repo_secret: PkgRepoSecret,
        check_auth_read: bool,
        pkg_repo_lock: threading.RLock,
) -> bool:
    with pkg_repo_lock:
        pkg_repo_shstg = wstat.rtype_to_pkg_repo_shstg[pkg_repo_type]
        pkg_repo_mtime_shstg = wstat.rtype_to_pkg_repo_mtime_shstg[pkg_repo_type]

        if not pkg_repo_shstg.has_item(pkg_repo_secret):
            # Cannot find the instance.
            return True

        pkg_repo = pkg_repo_shstg.get_item(pkg_repo_secret)
        ready, _ = pkg_repo.ready()
        if not ready:
            # Error in the last request.
            return True

        assert pkg_repo_mtime_shstg.has_item(pkg_repo_secret)
        mtime = pkg_repo_mtime_shstg.get_item(pkg_repo_secret)
        max_gap = wstat.auth_read_expires if check_auth_read else wstat.auth_write_expires
        if (datetime.now() - mtime).seconds > max_gap:
            # Time expires.
            return True

        return False


def setup_and_authenticate_pkg_repo(
        wstat: WorkflowStat,
        pkg_repo_type: PkgRepoType,
        pkg_repo_secret: PkgRepoSecret,
        check_auth_read: bool,
) -> Tuple[bool, str]:
    """name has been validated.
    """
    pkg_repo_config = wstat.rtype_to_pkg_repo_config[pkg_repo_type]

    # Get package repository lock.
    with wstat.pkg_repo_global_lock:
        pkg_repo_lock_shstg = wstat.rtype_to_pkg_repo_lock_shstg[pkg_repo_type]

        if not pkg_repo_lock_shstg.has_item(pkg_repo_secret):
            pkg_repo_lock_shstg.set_item(pkg_repo_secret, threading.RLock())
        pkg_repo_lock = pkg_repo_lock_shstg.get_item(pkg_repo_secret)

    # Prepare the package repository.
    with pkg_repo_lock:
        pkg_repo_shstg = wstat.rtype_to_pkg_repo_shstg[pkg_repo_type]
        pkg_repo_mtime_shstg = wstat.rtype_to_pkg_repo_mtime_shstg[pkg_repo_type]

        if should_initialize_pkg_repo(
                wstat,
                pkg_repo_type,
                pkg_repo_secret,
                check_auth_read,
                pkg_repo_lock,
        ):
            # Initialize.
            pkg_repo = create_pkg_repo(
                    pkg_repo_type=pkg_repo_type,
                    config=pkg_repo_config,
                    secret=pkg_repo_secret,
                    local_paths=wstat.local_paths,
            )

            ready, err_msg = pkg_repo.ready()
            if ready:
                auth_passed = pkg_repo.auth_read() if check_auth_read else pkg_repo.auth_write()
                if not auth_passed:
                    ready = False
                    err_msg = f'Auth error (readonly={check_auth_read})'
            if not ready:
                return False, err_msg

            # Succeeded.
            pkg_repo_shstg.set_item(pkg_repo_secret, pkg_repo)
            pkg_repo_mtime_shstg.set_item(pkg_repo_secret, datetime.now())
            return True, ''

        else:
            assert pkg_repo_shstg.has_item(pkg_repo_secret)
            pkg_repo = pkg_repo_shstg.get_item(pkg_repo_secret)

            auth_passed = pkg_repo.auth_read() if check_auth_read else pkg_repo.auth_write()
            err_msg = ''
            if auth_passed:
                # Succeeded, refresh mtime.
                pkg_repo_mtime_shstg.set_item(pkg_repo_secret, datetime.now())
            else:
                err_msg = f'Auth error (readonly={check_auth_read})'
                pkg_repo.record_error(err_msg)

            return auth_passed, err_msg
