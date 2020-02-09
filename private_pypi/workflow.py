from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, DefaultDict, Optional, Tuple, TypeVar, Generic
import threading
from os.path import join, exists
from datetime import datetime

from private_pypi.pkg_repos import (
        create_pkg_repo,
        PkgRepoConfig,
        PkgRepo,
        LocalPaths,
        PkgRepoSecret,
        load_pkg_repo_configs,
)

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
    name_to_pkg_repo_config: Dict[str, PkgRepoConfig]

    # Package index paths [(<lock-path>, <toml-path>)...]
    name_to_index_paths: Dict[str, Tuple[str, str]]

    # Locked package repos.
    auth_read_expires: int
    auth_write_expires: int
    pkg_repo_global_lock: threading.Lock
    name_to_pkg_repo_lock_shstg: DefaultDict[str, SecretHashedStorage[threading.RLock]]
    name_to_pkg_repo_shstg: DefaultDict[str, SecretHashedStorage[PkgRepo]]
    name_to_pkg_repo_mtime_shstg: DefaultDict[str, SecretHashedStorage[datetime]]

    # Local paths.
    local_paths: LocalPaths
    upload_folder: Optional[str]


def build_workflow_stat(
        pkg_repo_config: str,
        index_folder: str,
        stat_folder: Optional[str],
        upload_folder: Optional[str],
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
            auth_read_expires=auth_read_expires,
            auth_write_expires=auth_write_expires,
            pkg_repo_global_lock=threading.Lock(),
            name_to_pkg_repo_lock_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_mtime_shstg=defaultdict(SecretHashedStorage),
            local_paths=local_paths,
            upload_folder=upload_folder,
    )


def should_initialize_pkg_repo(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
        check_auth_read: bool,
        pkg_repo_lock: threading.RLock,
) -> bool:
    with pkg_repo_lock:
        pkg_repo_shstg = wstat.name_to_pkg_repo_shstg[name]
        pkg_repo_mtime_shstg = wstat.name_to_pkg_repo_mtime_shstg[name]

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
        name: str,
        pkg_repo_secret: PkgRepoSecret,
        check_auth_read: bool,
) -> Tuple[bool, str]:
    """name has been validated.
    """
    pkg_repo_config = wstat.name_to_pkg_repo_config[name]

    # Get package repository lock.
    with wstat.pkg_repo_global_lock:
        pkg_repo_lock_shstg = wstat.name_to_pkg_repo_lock_shstg[name]

        if not pkg_repo_lock_shstg.has_item(pkg_repo_secret):
            pkg_repo_lock_shstg.set_item(pkg_repo_secret, threading.RLock())
        pkg_repo_lock = pkg_repo_lock_shstg.get_item(pkg_repo_secret)

    # Prepare the package repository.
    with pkg_repo_lock:
        pkg_repo_shstg = wstat.name_to_pkg_repo_shstg[name]
        pkg_repo_mtime_shstg = wstat.name_to_pkg_repo_mtime_shstg[name]

        if should_initialize_pkg_repo(
                wstat,
                name,
                pkg_repo_secret,
                check_auth_read,
                pkg_repo_lock,
        ):
            # Initialize.
            pkg_repo = create_pkg_repo(
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
