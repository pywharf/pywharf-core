import atexit
from collections import defaultdict
import contextlib
from dataclasses import dataclass
from datetime import datetime
import logging
import os
from os.path import abspath, exists, getmtime, getsize, join
import subprocess
import socket
import tempfile
import threading
import traceback
from typing import DefaultDict, Dict, Generic, List, Optional, Tuple, TypeVar, Any

from filelock import FileLock
from jinja2 import Template
import psutil
import redis_server
from apscheduler.schedulers.background import BackgroundScheduler as _BackgroundScheduler
from apscheduler.schedulers import SchedulerNotRunningError
import fire

from private_pypi_core.backend import (
        DownloadIndexStatus,
        LocalPaths,
        PkgRef,
        PkgRepo,
        PkgRepoConfig,
        PkgRepoSecret,
        PkgRepoIndex,
        UploadPackageStatus,
        UploadIndexStatus,
        BackendInstanceManager,
)
from private_pypi_core.job import dynamic_dramatiq
from private_pypi_core.utils import locked_copy_file

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


class BackgroundScheduler(_BackgroundScheduler):

    def __del__(self):
        try:
            self.shutdown()
        except SchedulerNotRunningError:
            pass


@dataclass
class WorkflowStat:
    # Backend reflection.
    backend_instance_manager: BackendInstanceManager

    # Package repository configs.
    name_to_pkg_repo_config: Dict[str, PkgRepoConfig]

    # Local paths.
    root_folder: str
    root_local_paths: LocalPaths
    name_to_local_paths: Dict[str, LocalPaths]

    # Admin secrets for index synchronization.
    name_to_admin_pkg_repo_secret: Optional[Dict[str, PkgRepoSecret]]

    # Package index paths [(<lock-path>, <toml-path>)...]
    name_to_index_paths: Dict[str, Tuple[str, str]]
    name_to_index_mtime_size: Dict[str, Tuple[datetime, int]]
    name_to_pkg_repo_index: Dict[str, PkgRepoIndex]

    # Package repositories guarded by threading locks.
    auth_read_expires: int
    auth_write_expires: int
    pkg_repo_global_lock: threading.Lock
    name_to_pkg_repo_lock_shstg: DefaultDict[str, SecretHashedStorage[threading.RLock]]
    name_to_pkg_repo_shstg: DefaultDict[str, SecretHashedStorage[PkgRepo]]
    # Read/write last succeeded authentication datetime.
    name_to_pkg_repo_read_mtime_shstg: DefaultDict[str, SecretHashedStorage[datetime]]
    name_to_pkg_repo_write_mtime_shstg: DefaultDict[str, SecretHashedStorage[datetime]]

    scheduler: BackgroundScheduler


def build_workflow_stat(
        root_folder: str,
        pkg_repo_config_file: Optional[str],
        admin_pkg_repo_secret_file: Optional[str],
        auth_read_expires: int,
        auth_write_expires: int,
) -> WorkflowStat:
    backend_instance_manager = BackendInstanceManager()

    # Config.
    name_to_pkg_repo_config = {}
    if pkg_repo_config_file is not None:
        if not exists(pkg_repo_config_file):
            raise FileNotFoundError(f'pkg_repo_config_file={pkg_repo_config_file} not exists.')
        name_to_pkg_repo_config = \
                backend_instance_manager.load_pkg_repo_configs(pkg_repo_config_file)

    # Admin secret.
    name_to_admin_pkg_repo_secret = None
    if admin_pkg_repo_secret_file is not None:
        if not exists(admin_pkg_repo_secret_file):
            raise FileNotFoundError(
                    f'admin_pkg_repo_secret_file={admin_pkg_repo_secret_file} not exists.')
        name_to_admin_pkg_repo_secret = \
                backend_instance_manager.load_pkg_repo_secrets(admin_pkg_repo_secret_file)

    # Root folders.
    root_local_paths = LocalPaths(
            index=join(root_folder, 'index'),
            log=join(root_folder, 'log'),
            lock=join(root_folder, 'lock'),
            job=join(root_folder, 'job'),
            cache=join(root_folder, 'cache'),
    )
    root_local_paths.makedirs()

    name_to_local_paths = {}
    name_to_index_paths = {}
    for pkg_repo_config in name_to_pkg_repo_config.values():
        name = pkg_repo_config.name

        # Create isolated folders for each package repository.
        name_to_local_paths[name] = LocalPaths(
                index=join(root_local_paths.index, name),
                log=join(root_local_paths.log, name),
                lock=join(root_local_paths.lock, name),
                job=join(root_local_paths.job, name),
                cache=join(root_local_paths.cache, name),
        )
        name_to_local_paths[name].makedirs()

        # Index paths of (index_lock, index).
        name_to_index_paths[name] = (
                join(name_to_local_paths[name].lock, f'index.toml.lock'),
                join(name_to_local_paths[name].index, f'index.toml'),
        )

    # Build WorkflowStat.
    wstat = WorkflowStat(
            backend_instance_manager=backend_instance_manager,
            name_to_pkg_repo_config=name_to_pkg_repo_config,
            root_folder=root_folder,
            root_local_paths=root_local_paths,
            name_to_local_paths=name_to_local_paths,
            name_to_admin_pkg_repo_secret=name_to_admin_pkg_repo_secret,
            name_to_index_paths=name_to_index_paths,
            name_to_index_mtime_size={},  # Will setup later.
            name_to_pkg_repo_index={},  # Will setup later.
            auth_read_expires=auth_read_expires,
            auth_write_expires=auth_write_expires,
            pkg_repo_global_lock=threading.Lock(),
            name_to_pkg_repo_lock_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_read_mtime_shstg=defaultdict(SecretHashedStorage),
            name_to_pkg_repo_write_mtime_shstg=defaultdict(SecretHashedStorage),
            scheduler=BackgroundScheduler(),
    )

    if name_to_admin_pkg_repo_secret:
        passed, log = sync_local_index(wstat)
        if not passed:
            raise RuntimeError(log)

    # Index file signature (mtime, size) and instance.
    for pkg_repo_config in name_to_pkg_repo_config.values():
        _, index_path = name_to_index_paths[pkg_repo_config.name]
        if not exists(index_path):
            raise FileNotFoundError(
                    f'index file={index_path} for name={pkg_repo_config.name} not exists')

        wstat.name_to_index_mtime_size[pkg_repo_config.name] = get_mtime_size(index_path)

        pkg_refs, remote_mtime = wstat.backend_instance_manager.load_pkg_refs_and_mtime(index_path)
        wstat.name_to_pkg_repo_index[pkg_repo_config.name] = PkgRepoIndex(pkg_refs, remote_mtime)

    return wstat


def sync_single_local_index(wstat: WorkflowStat, name: str) -> Tuple[bool, str]:
    pkg_repo_config = wstat.name_to_pkg_repo_config[name]

    pkg_repo_secret = wstat.name_to_admin_pkg_repo_secret.get(name)
    if pkg_repo_secret is None:
        return True, f'[WARN] secret of "{name}" is not provided, skip index sync.'

    index_lock_path, index_path = wstat.name_to_index_paths[name]
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
    index_tmp_path = f'{index_path}.tmp.{timestamp}'

    try:
        pkg_repo = wstat.backend_instance_manager.create_pkg_repo(
                type=pkg_repo_config.type,
                config=pkg_repo_config,
                secret=pkg_repo_secret,
                local_paths=wstat.name_to_local_paths[name],
        )

        up_to_date = False
        if exists(index_path):
            # Make a copy to avoid holding the lock for a long time.
            locked_copy_file(index_lock_path, index_path, index_tmp_path, timeout=0.1)
            # Check.
            up_to_date = pkg_repo.local_index_is_up_to_date(index_tmp_path)

        if not up_to_date:
            # Sync.
            result = pkg_repo.download_index(index_tmp_path)
            if result.status != DownloadIndexStatus.SUCCEEDED:
                return False, f'[ERROR] "{name}" failed to download index:\n' + result.message
            # And replace.
            locked_copy_file(index_lock_path, index_tmp_path, index_path, timeout=0.1)

        # index_tmp_path should exists.
        try:
            os.remove(index_tmp_path)
        except IOError:
            pass

        return True, f'[PASS] "{name}" is up-to-date.'

    except Exception:  # pylint: disable=broad-except
        return False, f'[ERROR] traceback of "{name}":\n' + traceback.format_exc()


def sync_local_index(wstat: WorkflowStat) -> Tuple[bool, str]:
    if wstat.name_to_admin_pkg_repo_secret is None:
        return False, 'name_to_admin_pkg_repo_secret is None.'

    all_passed = []
    all_logs = []
    for name in wstat.name_to_pkg_repo_config:
        passed, log = sync_single_local_index(wstat, name)
        all_passed.append(passed)
        all_logs.append(log)

    return all(all_passed), '\n'.join(all_logs)


@dynamic_dramatiq.actor()
def sync_local_index_job(
        pkg_repo_config_file: str,
        admin_pkg_repo_secret_file: str,
        root_folder: str,
        name: str,
):
    wstat = build_workflow_stat(
            root_folder=root_folder,
            pkg_repo_config_file=pkg_repo_config_file,
            admin_pkg_repo_secret_file=admin_pkg_repo_secret_file,
            auth_read_expires=0,
            auth_write_expires=0,
    )

    # Setup logging.
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('filelock').setLevel(logging.WARNING)
    logger = logging.getLogger()
    logging_path = join(wstat.name_to_local_paths[name].log, 'sync_local_index_job.log')
    logger.addHandler(logging.FileHandler(logging_path))

    # Sync.
    try:
        passed, log = sync_single_local_index(wstat, name)
        if passed:
            logger.info(log)
        else:
            logger.error(log)

    except Exception:  # pylint: disable=broad-except
        logger.error(traceback.format_exc())


def random_select_port() -> str:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as _socket:
        _socket.bind(('localhost', 0))
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _, port = _socket.getsockname()
        return str(port)


def stop_all_children_processes():
    procs = psutil.Process().children()
    for proc in procs:
        proc.terminate()

    _, alive = psutil.wait_procs(procs, timeout=10)
    for proc in alive:
        proc.kill()


def initialize_task_worker(
        dramatiq_processes: int = 1,
        dramatiq_log_file: Optional[str] = None,
):
    # All processes in the current process group will be terminated
    # with the lead process.
    try:
        os.setpgrp()
    except PermissionError:
        # TODO: Occurred in github action. Investigate the root cause.
        pass

    atexit.register(stop_all_children_processes)

    # Run Redis.
    redis_port = random_select_port()
    pgid = os.getpgrp()
    subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
            [redis_server.REDIS_SERVER_PATH, '--port', redis_port],
            # Attach to the current process group.
            preexec_fn=lambda: os.setpgid(0, pgid),
            # Suppress stdout and stderr.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
    )

    # Set broker.
    from dramatiq.brokers.redis import RedisBroker  # pylint: disable=import-outside-toplevel
    dynamic_dramatiq.set_broker(RedisBroker(host='localhost', port=redis_port))

    # Run worker.
    dramatiq_env = dict(os.environ)
    dramatiq_env['DYNAMIC_DRAMATIQ_REDIS_BROKER_PORT'] = redis_port

    dramatiq_command = [
            'dramatiq',
            'private_pypi_core.job',
            '--processes',
            str(dramatiq_processes),
    ]
    if dramatiq_log_file:
        dramatiq_command.extend([
                '--log-file',
                dramatiq_log_file,
        ])

    subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
            dramatiq_command,
            # Share env.
            env=dramatiq_env,
            # Attach to the current process group.
            preexec_fn=lambda: os.setpgid(0, pgid),
            # Suppress stdout and stderr.
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
    )


def initialize_workflow(
        root_folder: str,
        pkg_repo_config_file: Optional[str],
        admin_pkg_repo_secret_file: Optional[str],
        auth_read_expires: int,
        auth_write_expires: int,
        enable_task_worker_initialization: bool = False,
) -> WorkflowStat:
    # Initialize workflow state.
    # NOTE: backend_instance_manager must be created before broker setup.
    wstat = build_workflow_stat(
            root_folder=abspath(root_folder),
            pkg_repo_config_file=pkg_repo_config_file,
            admin_pkg_repo_secret_file=admin_pkg_repo_secret_file,
            auth_read_expires=auth_read_expires,
            auth_write_expires=auth_write_expires,
    )

    if enable_task_worker_initialization:
        # Initialize task queue related stuff.
        initialize_task_worker(
                dramatiq_log_file=join(wstat.root_local_paths.log, 'dramatiq_worker.log'))

    # Schedule sync_local_index_job.
    for name, pkg_repo_config in wstat.name_to_pkg_repo_config.items():
        wstat.scheduler.add_job(
                sync_local_index_job,
                trigger='interval',
                kwargs={
                        'pkg_repo_config_file': pkg_repo_config_file,
                        'admin_pkg_repo_secret_file': admin_pkg_repo_secret_file,
                        'root_folder': root_folder,
                        'name': name,
                },
                seconds=pkg_repo_config.sync_index_interval,
        )
    wstat.scheduler.start()

    return wstat


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
) -> Tuple[Optional[PkgRepo], str]:
    '''name has been validated.
    '''
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
            pkg_repo = wstat.backend_instance_manager.create_pkg_repo(
                    type=pkg_repo_config.type,
                    config=pkg_repo_config,
                    secret=pkg_repo_secret,
                    local_paths=wstat.name_to_local_paths[name],
            )

            ready, err_msg = pkg_repo.ready()
            if ready:
                auth_passed = pkg_repo.auth_read() if check_auth_read else pkg_repo.auth_write()
                if not auth_passed:
                    ready = False
                    err_msg = f'Auth error (readonly={check_auth_read})'
            else:
                err_msg = f'Auth setup error (readonly={check_auth_read})\n' + err_msg
            if not ready:
                return None, err_msg

            # Succeeded.
            pkg_repo_shstg.set_item(pkg_repo_secret, pkg_repo)
            pkg_repo_mtime_shstg.set_item(pkg_repo_secret, datetime.now())

        return pkg_repo_shstg.get_item(pkg_repo_secret), ''


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
                pkg_refs, remote_mtime = \
                        wstat.backend_instance_manager.load_pkg_refs_and_mtime(index_path)
                wstat.name_to_pkg_repo_index[pkg_repo_config.name] = \
                        PkgRepoIndex(pkg_refs, remote_mtime)

    except Exception:  # pylint: disable=broad-except
        return False, traceback.format_exc()

    return True, ''


def get_pkg_repo_index(wstat: WorkflowStat, name: str) -> Tuple[Optional[PkgRepoIndex], str]:
    index_lock_path, _ = wstat.name_to_index_paths[name]
    try:
        with FileLock(index_lock_path, timeout=1.0):
            return wstat.name_to_pkg_repo_index[name], ''

    except Exception:  # pylint: disable=broad-except
        return None, traceback.format_exc()


@dataclass
class LinkItem:
    href: str
    text: str


# PEP 503 -- Simple Repository API
# https://www.python.org/dev/peps/pep-0503/
PAGE_TEMPLATE = Template('''<!DOCTYPE html>
<html>
<head><title>{{ title }}</title></head>
<body>
<h1>{{ title }}</h1>

{% for link_item in link_items %}
    <a href="{{ link_item.href }}">{{ link_item.text }}</a>
    <br>
{% endfor %}

</body>
</html>
''')


def build_page_api_simple(pkg_repo_index: PkgRepoIndex) -> str:
    link_items = [
            LinkItem(href=f'{distrib}/', text=distrib)
            for distrib in pkg_repo_index.all_distributions
    ]
    return PAGE_TEMPLATE.render(
            title='Links for all distributions',
            link_items=link_items,
    )


def build_page_api_simple_distrib(distrib: str, pkg_refs: List[PkgRef]) -> str:
    link_items = []
    for pkg_ref in pkg_refs:
        link_items.append(
                LinkItem(
                        href=f'{pkg_ref.package}.{pkg_ref.ext}#sha256={pkg_ref.sha256}',
                        text=f'{pkg_ref.package}.{pkg_ref.ext}',
                ))
    return PAGE_TEMPLATE.render(
            title=f'Links for {distrib}',
            link_items=link_items,
    )


def workflow_get_pkg_repo_index(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
        check_auth_read: bool = True,
) -> Tuple[Optional[PkgRepoIndex], str, int]:
    pkg_repo, err_msg = pkg_repo_secret_is_authenticated(
            wstat,
            name,
            pkg_repo_secret,
            check_auth_read=check_auth_read,
    )
    if pkg_repo is None:
        return None, err_msg, 401

    passed_index, err_msg = keep_pkg_repo_index_up_to_date(wstat, name)
    if not passed_index:
        return None, err_msg, 404

    pkg_repo_index, err_msg = get_pkg_repo_index(wstat, name)
    if pkg_repo_index is None:
        return None, err_msg, 404

    return pkg_repo_index, '', -1


def workflow_api_simple(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
) -> Tuple[str, int]:
    pkg_repo_index, err_msg, status_code = workflow_get_pkg_repo_index(
            wstat,
            name,
            pkg_repo_secret,
    )
    if pkg_repo_index is None:
        return err_msg, status_code
    return build_page_api_simple(pkg_repo_index), 200


def workflow_api_simple_distrib(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
        distrib: str,
) -> Tuple[str, int]:
    pkg_repo_index, err_msg, status_code = workflow_get_pkg_repo_index(
            wstat,
            name,
            pkg_repo_secret,
    )
    if pkg_repo_index is None:
        return err_msg, status_code

    pkg_refs = pkg_repo_index.get_pkg_refs(distrib)
    if not pkg_refs:
        return f'distrib={distrib} not found.', 404

    return build_page_api_simple_distrib(distrib, pkg_refs), 200


def workflow_api_redirect_package_download_url(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
        distrib: str,
        package: str,
        ext: str,
) -> Tuple[Optional[str], str, int]:
    pkg_repo_index, err_msg, status_code = workflow_get_pkg_repo_index(
            wstat,
            name,
            pkg_repo_secret,
    )
    if pkg_repo_index is None:
        return None, err_msg, status_code

    pkg_ref = pkg_repo_index.get_single_pkg_ref(distrib, package)
    if pkg_ref is None:
        return None, f'Package "{distrib}, {package}.{ext}" not exists.', 404
    elif pkg_ref.ext != ext:
        return None, f'Package "{distrib}, {package}.{ext}" extention not match (query="{ext}")', 404

    try:
        auth_url = pkg_ref.auth_url(wstat.name_to_pkg_repo_config[name], pkg_repo_secret)
        return auth_url, '', -1

    except Exception:  # pylint: disable=broad-except
        return None, 'Failed to get resource.\n' + traceback.format_exc(), 401


def workflow_api_upload_package(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
        filename: str,
        meta: Dict[str, str],
        path: str,
) -> Tuple[str, int]:
    pkg_repo, err_msg = pkg_repo_secret_is_authenticated(
            wstat,
            name,
            pkg_repo_secret,
            check_auth_read=False,
    )
    if pkg_repo is None:
        return err_msg, 401

    result = pkg_repo.upload_package(filename, meta, path)
    if result.status == UploadPackageStatus.FAILED:
        status_code = 401
    elif result.status == UploadPackageStatus.SUCCEEDED:
        status_code = 200
    else:
        raise ValueError('Invalid UploadPackageStatus')

    return result.message, status_code


def workflow_index_mtime(
        wstat: WorkflowStat,
        name: str,
        pkg_repo_secret: PkgRepoSecret,
) -> Tuple[str, int]:
    pkg_repo_index, err_msg, status_code = workflow_get_pkg_repo_index(
            wstat,
            name,
            pkg_repo_secret,
    )
    if pkg_repo_index is None:
        return err_msg, status_code
    return str(pkg_repo_index.mtime), 200


def update_index(
        type: str,  # pylint: disable=redefined-builtin
        name: str,
        secret: Optional[str] = None,
        secret_env: Optional[str] = None,
        **config_kwargs: Any,
):
    bim = BackendInstanceManager()

    root_tmp_dir = str(tempfile.mkdtemp())
    pkg_repo = bim.create_pkg_repo(
            type=type,
            config=bim.create_pkg_repo_config(
                    type=type,
                    name=name,
                    **config_kwargs,
            ),
            secret=bim.create_pkg_repo_secret(
                    type=type,
                    name=name,
                    raw=secret,
                    env=secret_env,
            ),
            local_paths=LocalPaths(
                    index=str(tempfile.mkdtemp(dir=root_tmp_dir)),
                    log=str(tempfile.mkdtemp(dir=root_tmp_dir)),
                    lock=str(tempfile.mkdtemp(dir=root_tmp_dir)),
                    job=str(tempfile.mkdtemp(dir=root_tmp_dir)),
                    cache=str(tempfile.mkdtemp(dir=root_tmp_dir)),
            ),
    )
    print('pkg_repo_config:', pkg_repo.config.dict())

    # Collect published packages.
    published_pkg_refs = pkg_repo.collect_all_published_packages()
    print(f'{len(published_pkg_refs)} published packages collected.')

    # Collect indexed packages.
    with tempfile.NamedTemporaryFile(dir=pkg_repo.local_paths.cache) as ntf:
        result = pkg_repo.download_index(ntf.name)
        if result.status != DownloadIndexStatus.SUCCEEDED:
            print(f'[ERROR] "{name}" failed to download index:\n' + result.message)

        indexed_pkg_refs, _ = bim.load_pkg_refs_and_mtime(ntf.name)
        print(f'{len(indexed_pkg_refs)} indexed packages collected')

    # Check if update is needed.
    if published_pkg_refs == indexed_pkg_refs:
        print("No change, skip update.")

    else:
        print("Uploading...")
        with tempfile.NamedTemporaryFile(dir=pkg_repo.local_paths.cache) as ntf:
            bim.dump_pkg_refs_and_mtime(ntf.name, published_pkg_refs)
            result = pkg_repo.upload_index(ntf.name)
            if result.status != UploadIndexStatus.SUCCEEDED:
                raise RuntimeError(result.message)


update_index_cli = lambda: fire.Fire(update_index)  # pylint: disable=invalid-name
