from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from os.path import exists, getmtime, getsize, join
import threading
from typing import DefaultDict, Dict, Generic, Optional, Tuple, TypeVar
import traceback

from filelock import FileLock

from private_pypi.pkg_repos import (
        LocalPaths,
        PkgRepo,
        PkgRepoConfig,
        PkgRepoSecret,
        PkgRepoIndex,
        create_pkg_repo,
        load_pkg_repo_configs,
        load_pkg_repo_index,
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


def get_mtime_size(path: str) -> Tuple[datetime, int]:
    mtime = datetime.fromtimestamp(getmtime(path))
    size = getsize(path)
    return mtime, size


@dataclass
class WorkflowStat:
    # Package repository configs.
    name_to_pkg_repo_config: Dict[str, PkgRepoConfig]

    # Package index paths [(<lock-path>, <toml-path>)...]
    name_to_index_paths: Dict[str, Tuple[str, str]]
    name_to_index_mtime_size: Dict[str, Tuple[datetime, int]]
    name_to_pkg_repo_index: Dict[str, PkgRepoIndex]

    # Locked package repos.
    auth_read_expires: int
    auth_write_expires: int
    pkg_repo_global_lock: threading.Lock
    name_to_pkg_repo_lock_shstg: DefaultDict[str, SecretHashedStorage[threading.RLock]]
    name_to_pkg_repo_shstg: DefaultDict[str, SecretHashedStorage[PkgRepo]]
    # Read.
    name_to_pkg_repo_read_mtime_shstg: DefaultDict[str, SecretHashedStorage[datetime]]
    name_to_pkg_repo_write_mtime_shstg: DefaultDict[str, SecretHashedStorage[datetime]]

    # Local paths.
    local_paths: LocalPaths
    upload_folder: Optional[str]


def build_workflow_stat(
        pkg_repo_config_file: str,
        index_folder: str,
        stat_folder: Optional[str],
        cache_folder: Optional[str],
        upload_folder: Optional[str],
        auth_read_expires: int,
        auth_write_expires: int,
) -> WorkflowStat:
    # Config.
    if not exists(pkg_repo_config_file):
        raise FileNotFoundError(f'pkg_repo_config_file={pkg_repo_config_file} not exists.')

    name_to_pkg_repo_config = load_pkg_repo_configs(pkg_repo_config_file)

    # Index.
    if not exists(index_folder):
        raise FileNotFoundError(f'index_folder={index_folder} not exists.')

    name_to_index_paths = {}
    name_to_index_mtime_size = {}
    name_to_pkg_repo_index = {}
    for pkg_repo_config in name_to_pkg_repo_config.values():
        index_lock_path = join(index_folder, f'{pkg_repo_config.name}.index.lock')

        index_path = join(index_folder, f'{pkg_repo_config.name}.index')
        if not exists(index_path):
            raise FileNotFoundError(
                    f'index file={index_path} for name={pkg_repo_config.name} not exists')

        name_to_index_paths[pkg_repo_config.name] = (index_lock_path, index_path)
        name_to_index_mtime_size[pkg_repo_config.name] = get_mtime_size(index_path)
        name_to_pkg_repo_index[pkg_repo_config.name] = load_pkg_repo_index(
                index_path,
                pkg_repo_config.type,
        )

    # Paths for repositories.
    local_paths = LocalPaths(stat=stat_folder, cache=cache_folder)

    return WorkflowStat(
            name_to_pkg_repo_config=name_to_pkg_repo_config,
            name_to_index_paths=name_to_index_paths,
            name_to_index_mtime_size=name_to_index_mtime_size,
            name_to_pkg_repo_index=name_to_pkg_repo_index,
            auth_read_expires=auth_read_expires,
            auth_write_expires=auth_write_expires,
            pkg_repo_global_lock=threading.Lock(),
            name_to_pkg_repo_lock_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_read_mtime_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_write_mtime_shstg=defaultdict(SecretHashedStorage),
            local_paths=local_paths,
            upload_folder=upload_folder,
    )


def pkg_repo_is_expired(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_lock: threading.RLock,
        pkg_repo_secret: PkgRepoSecret,
        check_auth_read: bool,
) -> bool:
    with pkg_repo_lock:
        pkg_repo_shstg = wstat.name_to_pkg_repo_shstg[name]

        if check_auth_read:
            pkg_repo_mtime_shstg = wstat.name_to_pkg_repo_read_mtime_shstg[name]
        else:
            pkg_repo_mtime_shstg = wstat.name_to_pkg_repo_write_mtime_shstg[name]

        if not pkg_repo_shstg.has_item(pkg_repo_secret):
            # Cannot find the instance.
            return True

        pkg_repo = pkg_repo_shstg.get_item(pkg_repo_secret)
        ready, _ = pkg_repo.ready()
        if not ready:
            # Error in the last request.
            return True

        if not pkg_repo_mtime_shstg.has_item(pkg_repo_secret):
            # Unknow.
            return True

        mtime = pkg_repo_mtime_shstg.get_item(pkg_repo_secret)
        auth_expires = wstat.auth_read_expires if check_auth_read else wstat.auth_write_expires
        if (datetime.now() - mtime).total_seconds() >= auth_expires:
            # Last passed but time expires.
            return True

        # Last passed and not expired.
        return False


def pkg_repo_secret_is_authenticated(
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

        if check_auth_read:
            pkg_repo_mtime_shstg = wstat.name_to_pkg_repo_read_mtime_shstg[name]
        else:
            pkg_repo_mtime_shstg = wstat.name_to_pkg_repo_write_mtime_shstg[name]

        if pkg_repo_is_expired(
                wstat,
                name,
                pkg_repo_lock,
                pkg_repo_secret,
                check_auth_read,
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


def keep_pkg_repo_index_up_to_date(wstat: WorkflowStat, name: str) -> Tuple[bool, str]:
    pkg_repo_config = wstat.name_to_pkg_repo_config[name]
    index_lock_path, index_path = wstat.name_to_index_paths[name]

    try:
        # Timeout = 1.0 second should be enough
        # since the current design is only for small index file.
        with FileLock(index_lock_path, timeout=1.0):
            cur_mtime_size = get_mtime_size(index_path)
            last_mtime_size = wstat.name_to_index_mtime_size[name]

            if cur_mtime_size != last_mtime_size:
                # Index has been updated, reload.
                wstat.name_to_pkg_repo_index[pkg_repo_config.name] = load_pkg_repo_index(
                        index_path,
                        pkg_repo_config.type,
                )

    except:  # pylint: disable=bare-except
        return False, traceback.format_exc()

    return True, ''
