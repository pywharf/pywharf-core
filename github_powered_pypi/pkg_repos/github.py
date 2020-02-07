import contextlib
from dataclasses import asdict, dataclass
from enum import Enum, auto
import hashlib
import logging
import os
import os.path
import re
import subprocess
import traceback
from urllib.parse import urlparse
from typing import Callable, Dict, List, Optional, TextIO, Tuple

from filelock import FileLock
import fire
import github
import requests
import shortuuid
import toml

from github_powered_pypi.pkg_repos.pkg_repo import (
        LocalPaths,
        PkgRef,
        PkgRepo,
        PkgRepoConfig,
        PkgRepoSecret,
        UploadPackageResult,
        UploadPackageStatus,
)


@dataclass
class GitHubConfig(PkgRepoConfig):
    owner: str
    repo: str
    large_package_bytes: int = 1024**2


@dataclass
class GitHubAuthToken(PkgRepoSecret):
    token: Optional[str] = None

    def __post_init__(self):
        self.token = self.raw


class TaskType(Enum):
    UPLOAD_PACKAGE = auto()
    DOWNLOAD_PACKAGE = auto()


@dataclass
class TaskPath:
    config_name: str
    local_path_stat: str
    task_type_name: str
    filename: str
    task_id: Optional[str] = None

    def _path_join_stat(self, filename: str):
        return os.path.join(self.local_path_stat, filename)

    # <task_type>-<distribution>
    @property
    def _task_name(self):
        return f'{self.config_name}-{self.task_type_name}-{self.filename}'

    @property
    def lock(self):
        return self._path_join_stat(f'{self._task_name}.lock')

    # runstat: metadata of the running task like task id.
    @property
    def runstat_lock(self):
        return self._path_join_stat(f'{self._task_name}.runstat.lock')

    @property
    def runstat(self):
        return self._path_join_stat(f'{self._task_name}.runstat')

    # <task_type>-<distribution>-<task_id>
    @property
    def _task_name_id(self):
        assert self.task_id
        return f'{self._task_name}-{self.task_id}'

    # args: the input of task.
    @property
    def args(self):
        return self._path_join_stat(f'{self._task_name_id}.args')

    # logging: the logging of task.
    @property
    def logging_lock(self):
        return self._path_join_stat(f'{self._task_name_id}.log.lock')

    @property
    def logging(self):
        return self._path_join_stat(f'{self._task_name_id}.log')

    # final: metadata of the final result.
    @property
    def finalstat_lock(self):
        return self._path_join_stat(f'{self._task_name_id}.finalstat.lock')

    @property
    def finalstat(self):
        return self._path_join_stat(f'{self._task_name_id}.finalstat')


@dataclass
class UploadAndDownloadPackageContext:
    filename: str
    path: str
    meta: Optional[Dict[str, str]] = None
    release: github.GitRelease.GitRelease = None
    failed: bool = False
    message: str = ''


@dataclass
class GitHubPkgRef(PkgRef):
    url: str

    def auth_url(self, config: GitHubConfig, secret: GitHubAuthToken) -> str:
        headers = {
                'Accept': 'application/octet-stream',
                'Authorization': f'token {secret.token}',
        }
        retry = 3
        response = None
        while retry > 0:
            try:
                response = requests.get(
                        self.url,
                        headers=headers,
                        allow_redirects=False,
                        timeout=1.0,
                )
                break
            except requests.Timeout:
                retry -= 1
                response = None
                continue

        assert retry > 0
        response.raise_for_status()
        assert response.status_code == 302

        parsed = urlparse(response.next.url)
        assert not parsed.fragment

        return parsed._replace(fragment=f'sha256={self.sha256}').geturl()


def write_args(path, args):
    with open(path, 'w') as fout:
        fout.write(toml.dumps(args))


def read_args(path):
    with open(path) as fin:
        return toml.loads(fin.read())


def file_lock_is_busy(lock_path):
    flock = FileLock(lock_path)
    busy = False
    try:
        flock.acquire(timeout=0.1, poll_intervall=0.05)
    except TimeoutError:
        busy = True
    finally:
        flock.release()
    return busy


def locked_read_file(lock_path, file_path, timeout=-1):
    try:
        with FileLock(lock_path, timeout=timeout):
            if not os.path.exists(file_path):
                return True, None
            with open(file_path) as fin:
                return True, fin.read()
    except TimeoutError:
        return False, ''


def locked_read_toml(lock_path, file_path, timeout=-1):
    status, text = locked_read_file(lock_path, file_path, timeout=timeout)
    struct = None
    if status and text is not None:
        struct = toml.loads(text)
    return status, struct


def locked_write_file(lock_path, file_path, text, timeout=-1):
    try:
        with FileLock(lock_path, timeout=timeout):
            with open(file_path, 'w') as fout:
                fout.write(text)
            return True
    except TimeoutError:
        return False


def locked_write_toml(lock_path, file_path, struct, timeout=-1):
    return locked_write_file(lock_path, file_path, toml.dumps(struct), timeout=timeout)


LOCK_TIMEOUT = 0.5


@dataclass
class GitHubPkgRepo(PkgRepo):
    config: GitHubConfig
    secret: GitHubAuthToken

    def __post_init__(self):
        # pylint: disable=attribute-defined-outside-init
        try:
            self._gh_client: github.Github = github.Github(self.secret.token)
            self._gh_fullname = f'{self.config.owner}/{self.config.repo}'
            self._gh_repo: github.Repository.Repository = \
                    self._gh_client.get_repo(self._gh_fullname)
            self._gh_username: str = self._gh_client.get_user().login
            self._gh_permission: str = self._gh_repo.get_collaborator_permission(self._gh_username)

            self._ready = True
            self._init_msg = ''

        except:  # pylint: disable=bare-except
            self._ready = False
            self._init_msg = traceback.format_exc()

    def ready(self) -> Tuple[bool, str]:
        return self._ready, self._init_msg

    def auth_read(self) -> bool:
        return self._gh_permission != 'none'

    def auth_write(self) -> bool:
        return self._gh_permission in ('admin', 'write')

    def _check_published_release_not_exists(self, ctx: UploadAndDownloadPackageContext):
        try:
            self._gh_repo.get_release(ctx.filename)
            ctx.failed = True
            ctx.message = f'package={ctx.filename} has already exists.'

        except github.UnknownObjectException:
            # Release not exists, do nothing.
            return

        except github.BadCredentialsException:
            ctx.failed = True
            ctx.message = f'cannot get package={ctx.filename} due to invalid credential.'

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in conflict validation.\n' + str(ex.data)

    def _create_draft_release(self, ctx: UploadAndDownloadPackageContext):
        try:
            ctx.release = self._gh_repo.create_git_release(
                    tag=ctx.filename,
                    name=ctx.filename,
                    message='',
                    draft=True,
            )

        except github.BadCredentialsException:
            ctx.failed = True
            ctx.message = f'cannot upload package={ctx.filename} due to invalid credential.'

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in draft release creation.\n' + str(ex.data)

    def _upload_package_as_release_asset(self, ctx: UploadAndDownloadPackageContext):  # pylint: disable=no-self-use
        # Upload as release asset.
        try:
            ctx.release.upload_asset(
                    ctx.path,
                    content_type='application/zip',
                    name=ctx.filename,
            )

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in asset upload.\n' + str(ex.data)

    def _fill_meta_and_publish_release(self, ctx: UploadAndDownloadPackageContext):  # pylint: disable=no-self-use
        # Fill distribution name.
        # https://www.python.org/dev/peps/pep-0503/#normalized-names
        if not ctx.meta.get('distrib'):
            name = ctx.meta.get('name')
            if name:
                ctx.meta['distrib'] = re.sub(r"[-_.]+", "-", name).lower()

        # SHA256 checksum, also suggested by PEP-503.
        if not ctx.meta.get('sha256'):
            sha256_algo = hashlib.sha256()
            with open(ctx.path, 'rb') as fin:
                # 64KB block.
                for block in iter(lambda: fin.read(65536), b''):
                    sha256_algo.update(block)

            ctx.meta['sha256'] = sha256_algo.hexdigest()

        body = toml.dumps(ctx.meta)
        try:
            ctx.release.update_release(
                    tag_name=ctx.filename,
                    name=ctx.filename,
                    message=body,
                    draft=False,
            )

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in release publishing.\n' + str(ex.data)

    def upload_package_task(self, filename: str, meta: Dict[str, str], path: str):
        ctx = UploadAndDownloadPackageContext(filename=filename, meta=meta, path=path)

        for action in (
                self._check_published_release_not_exists,
                self._create_draft_release,
                self._upload_package_as_release_asset,
                self._fill_meta_and_publish_release,
        ):
            action(ctx)
            if ctx.failed:
                break

        return ctx

    def upload_package(self, filename: str, meta: Dict[str, str], path: str) -> UploadPackageResult:
        if not self.local_paths.stat:
            return UploadPackageResult(
                    status=UploadPackageStatus.FAILED,
                    message='stat path not set.',
            )

        task_path = TaskPath(
                config_name=self.config.name,
                local_path_stat=self.local_paths.stat,
                task_type_name=TaskType.UPLOAD_PACKAGE.name.lower(),
                filename=filename,
                task_id=None,
        )

        if file_lock_is_busy(task_path.lock):
            runstat_status, runstat = locked_read_toml(
                    task_path.runstat_lock,
                    task_path.runstat,
                    timeout=LOCK_TIMEOUT,
            )
            if runstat_status and runstat is not None:
                message = 'upload task is running.'
                task_id = runstat['task_id']
            else:
                message = 'upload task is running but cannot get task_id, please try later.'
                task_id = None

            return UploadPackageResult(
                    status=UploadPackageStatus.TASK_CREATED,
                    message=message,
                    task_id=task_id,
            )

        if os.path.getsize(path) < self.config.large_package_bytes:
            # Small package.
            ctx = self.upload_package_task(filename, meta, path)
            status = UploadPackageStatus.SUCCEEDED if not ctx.failed else UploadPackageStatus.FAILED
            return UploadPackageResult(
                    status=status,
                    message=ctx.message,
            )

        else:
            # Large package.
            task_id = shortuuid.ShortUUID().random(length=6)
            task_path.task_id = task_id

            # TODO: dataclass.
            task_dict = {
                    'filename': filename,
                    'meta': meta,
                    'path': path,
                    'task_id': task_id,
            }

            write_args(
                    task_path.args,
                    {
                            'repo_dict': asdict(self),
                            'task_dict': task_dict,
                            'task_path_dict': asdict(task_path),
                    },
            )
            subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
                    ['github_upload_package', task_path.args, '--remove_args_path'],
                    # Share env for resolving `github_upload_package`.
                    env=dict(os.environ),
                    # Add to the current process group.
                    preexec_fn=os.setpgrp,
                    # Suppress stdout or stderr.
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
            )

            return UploadPackageResult(
                    status=UploadPackageStatus.TASK_CREATED,
                    task_id=task_id,
                    message=f'Upload task created with task_id={task_id}',
            )

    def view_task_upload_package(self, filename: str, task_id: str) -> UploadPackageResult:
        task_path = TaskPath(
                config_name=self.config.name,
                local_path_stat=self.local_paths.stat or '',
                task_type_name=TaskType.UPLOAD_PACKAGE.name.lower(),
                filename=filename,
                task_id=task_id,
        )

        if not self.local_paths.stat:
            task_path = None
            status = UploadPackageStatus.FAILED
            message = 'stat path not set.'

        elif file_lock_is_busy(task_path.lock):
            logging_message_status, logging_message = locked_read_file(
                    task_path.logging_lock,
                    task_path.logging,
                    timeout=LOCK_TIMEOUT,
            )

            if logging_message_status:
                if logging_message is None:
                    status = UploadPackageStatus.FAILED
                    message = 'Task is running but cannot find the log.'
                else:
                    status = UploadPackageStatus.TASK_CREATED
                    message = logging_message

            else:
                status = UploadPackageStatus.TASK_CREATED
                message = 'Busy lock, try later.'

        else:
            finalstat_status, finalstat = locked_read_toml(
                    task_path.finalstat_lock,
                    task_path.finalstat,
                    timeout=LOCK_TIMEOUT,
            )
            if finalstat_status:
                if finalstat is not None:
                    # Succeeded.
                    status = UploadPackageStatus.SUCCEEDED \
                            if not finalstat['failed'] else UploadPackageStatus.FAILED
                    message = finalstat['logging_message']
                else:
                    # No final state.
                    status = UploadPackageStatus.FAILED
                    message = ('Task is not runnng and there\'s no final result'
                               f'(filename={filename}, task_id={task_id}) should be incorrect.')
            else:
                # Corrupted lock.
                status = UploadPackageStatus.FAILED
                message = 'Lock corrupted (lock not busy, finalstat_lock busy). Please help report this bug.'

        return UploadPackageResult(status=status, task_id=task_id, message=message)

    def _get_published_release(self, ctx: UploadAndDownloadPackageContext):
        try:
            ctx.release = self._gh_repo.get_release(ctx.filename)

        except github.UnknownObjectException:
            ctx.failed = True
            ctx.message = f'package={ctx.filename} not exists.'

        except github.BadCredentialsException:
            ctx.failed = True
            ctx.message = f'cannot get package={ctx.filename} due to invalid credential.'

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in get release.\n' + str(ex.data)

    def _load_meta_from_release(self, ctx: UploadAndDownloadPackageContext):  # pylint: disable=no-self-use
        try:
            ctx.meta = toml.loads(ctx.release.body)

        except toml.TomlDecodeError:
            ctx.failed = True
            ctx.message = f'cannot decode body={ctx.release.body}'

    def _download_release_asset(self, ctx: UploadAndDownloadPackageContext):
        pass

    def download_package(self, filename: str, output: str):
        raise NotImplementedError()

    def view_task_download_package(self, filename: str, task_id: str):
        raise NotImplementedError()

    def collect_all_published_packages(self) -> List[GitHubPkgRef]:
        pkg_refs: List[GitHubPkgRef] = []

        for release in self._gh_repo.get_releases():
            if release.draft:
                continue

            try:
                meta: Dict[str, str] = toml.loads(release.body)
            except toml.TomlDecodeError:
                continue

            distrib = meta.get('distrib')
            sha256 = meta.get('sha256')
            if not distrib or not sha256:
                continue

            package, _, _ = release.tag_name.rpartition('.')
            if not package:
                continue

            raw_assets = release._rawData.get('assets')  # pylint: disable=protected-access
            if not raw_assets:
                continue
            url = None
            for raw_asset in raw_assets:
                if raw_asset.get('name') == release.tag_name:
                    url = raw_asset.get('url')
                    if url:
                        break
            if not url:
                continue

            pkg_ref = GitHubPkgRef(
                    distrib=distrib,
                    package=package,
                    sha256=sha256,
                    meta=meta,
                    url=url,
            )
            pkg_refs.append(pkg_ref)

        return pkg_refs

    def upload_index(self, path: str):
        raise NotImplementedError()

    def download_index(self, output: str):
        raise NotImplementedError()


@dataclass
class LockedFileLikeObject(TextIO):  # pylint: disable=abstract-method
    lock_path: str
    write_func: Callable

    def write(self, s: str) -> int:
        with FileLock(self.lock_path):
            self.write_func(s)
        return 0


def github_upload_package(args_path: str, remove_args_path: bool = False):
    args = read_args(args_path)

    if remove_args_path:
        os.remove(args_path)

    repo_dict = args['repo_dict']
    task_dict = args['task_dict']

    task_path = TaskPath(**args['task_path_dict'])

    logging.basicConfig(level=logging.INFO, filename=task_path.logging)
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger_stdout = logging.getLogger('stdout')
    lfl_stdout = LockedFileLikeObject(task_path.logging_lock, logger_stdout.info)

    logger_stderr = logging.getLogger('stderr')
    lfl_stderr = LockedFileLikeObject(task_path.logging_lock, logger_stderr.error)

    flock = FileLock(task_path.lock)
    flock.acquire()

    failed = False

    try:
        with contextlib.redirect_stdout(lfl_stdout), contextlib.redirect_stderr(lfl_stderr):
            repo = GitHubPkgRepo(
                    config=GitHubConfig(**repo_dict['config']),
                    secret=GitHubAuthToken(**repo_dict['secret']),
                    local_paths=LocalPaths(**repo_dict['local_paths']),
            )

            if not locked_write_toml(
                    task_path.runstat_lock,
                    task_path.runstat,
                    task_dict,
                    timeout=LOCK_TIMEOUT,
            ):
                logger_stderr.error('blocked for writing to runstat.')
                return 1

            lfl_stdout.write('Task={} created'.format(task_dict['task_id']))

            ctx = repo.upload_package_task(
                    task_dict['filename'],
                    task_dict['meta'],
                    task_dict['path'],
            )
            failed = ctx.failed

            lfl_stdout.write('Task failed: {}'.format(ctx.failed))
            lfl_stdout.write('Task message: {}'.format(ctx.message))
            lfl_stdout.write('Task={} finished'.format(task_dict['task_id']))

    except:  # pylint: disable=bare-except
        lfl_stderr.write(traceback.format_exc())
        failed = True
        return 1

    finally:
        _, logging_message = locked_read_file(
                task_path.logging_lock,
                task_path.logging,
        )
        if logging_message is None:
            logging_message = 'logging file not exits.'

        locked_write_toml(
                task_path.finalstat_lock,
                task_path.finalstat,
                {
                        'failed': failed,
                        'logging_message': logging_message,
                },
                timeout=LOCK_TIMEOUT,
        )

        flock.release()

    return 0


github_upload_package_cli = lambda: fire.Fire(github_upload_package)  # pylint: disable=invalid-name
