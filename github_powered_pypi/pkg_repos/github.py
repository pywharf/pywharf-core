import contextlib
from dataclasses import asdict, dataclass
from enum import Enum, auto
import logging
import os
import os.path
import subprocess
import traceback
from typing import Callable, Dict, Optional, TextIO

from filelock import FileLock
import fire
import github
import shortuuid
import toml

from github_powered_pypi.pkg_repos.pkg_repo import (
        LocalPaths,
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
class UploadAndDownloadPackageContext:
    name: str
    meta: Optional[Dict[str, str]] = None
    path: Optional[str] = None
    release: github.GitRelease.GitRelease = None
    failed: bool = False
    message: str = ''


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
    if status:
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


@dataclass
class GitHubPkgRepo(PkgRepo):
    config: GitHubConfig
    secret: GitHubAuthToken

    def __post_init__(self):
        # pylint: disable=attribute-defined-outside-init
        self._gh_client: github.Github = github.Github(self.secret.token)
        self._gh_fullname = f'{self.config.owner}/{self.config.repo}'
        self._gh_repo: github.Repository.Repository = self._gh_client.get_repo(self._gh_fullname)
        self._gh_username: str = self._gh_client.get_user().login
        self._gh_permission: str = self._gh_repo.get_collaborator_permission(self._gh_username)

    def auth_read(self):
        return self._gh_permission != 'none'

    def auth_write(self):
        return self._gh_permission in ('admin', 'write')

    def _check_published_release_not_exists(self, ctx: UploadAndDownloadPackageContext):
        try:
            self._gh_repo.get_release(ctx.name)
            ctx.failed = True
            ctx.message = f'package={ctx.name} has already exists.'

        except github.UnknownObjectException:
            # Release not exists, do nothing.
            return

        except github.BadCredentialsException:
            ctx.failed = True
            ctx.message = f'cannot get package={ctx.name} due to invalid credential.'

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in conflict validation.\n' + str(ex.data)

    def _create_draft_release(self, ctx: UploadAndDownloadPackageContext):
        try:
            ctx.release = self._gh_repo.create_git_release(
                    tag=ctx.name,
                    name=ctx.name,
                    message='',
                    draft=True,
            )

        except github.BadCredentialsException:
            ctx.failed = True
            ctx.message = f'cannot upload package={ctx.name} due to invalid credential.'

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in draft release creation.\n' + str(ex.data)

    def _upload_package_as_release_asset(self, ctx: UploadAndDownloadPackageContext):  # pylint: disable=no-self-use
        # Upload as release asset.
        try:
            ctx.release.upload_asset(
                    ctx.path,
                    content_type='application/zip',
                    name=ctx.name,
            )

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in asset upload.\n' + str(ex.data)

    def _fill_meta_and_publish_release(self, ctx: UploadAndDownloadPackageContext):  # pylint: disable=no-self-use
        body = toml.dumps(ctx.meta)
        try:
            ctx.release.update_release(
                    tag_name=ctx.name,
                    name=ctx.name,
                    message=body,
                    draft=False,
            )

        except github.GithubException as ex:
            ctx.failed = True
            ctx.message = 'github exception in release publishing.\n' + str(ex.data)

    def _path_join_stat(self, fname: str):
        assert isinstance(self.local_paths.stat, str)
        return os.path.join(self.local_paths.stat, fname)

    # <task_type>-<distribution>
    def _task_name(self, task_type: TaskType, name: str):
        return f'{self.config.name}-{task_type.name.lower()}-{name}'

    def task_lock_path(self, task_type: TaskType, name: str):
        return self._path_join_stat(f'{self._task_name(task_type, name)}.lock')

    # task_runstat: metadata of the running task like task id.
    def task_runstat_lock_path(self, task_type: TaskType, name: str):
        return self._path_join_stat(f'{self._task_name(task_type, name)}.runstat.lock')

    def task_runstat_path(self, task_type: TaskType, name: str):
        return self._path_join_stat(f'{self._task_name(task_type, name)}.runstat')

    # <task_type>-<distribution>-<task_id>
    def _task_name_id(self, task_type: TaskType, name: str, task_id: str):
        return f'{self._task_name(task_type, name)}-{task_id}'

    # task_args: the input of task.
    def task_args_path(self, task_type: TaskType, name: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, name, task_id)}.args')

    # task_logging: the logging of task.
    def task_logging_path(self, task_type: TaskType, name: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, name, task_id)}.log')

    def task_logging_exists(self, task_type: TaskType, name: str, task_id: str):
        return os.path.exists(self.task_logging_path(task_type, name, task_id))

    # task_final: metadata of the final result.
    def task_finalstat_lock_path(self, task_type: TaskType, name: str, task_id: str):
        return self._path_join_stat(
                f'{self._task_name_id(task_type, name, task_id)}.finalstat.lock')

    def task_finalstat_path(self, task_type: TaskType, name: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, name, task_id)}.finalstat')

    def upload_package_task(self, name: str, meta: Dict[str, str], path: str):
        ctx = UploadAndDownloadPackageContext(name=name, meta=meta, path=path)

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

    def upload_package(self, name: str, meta: Dict[str, str], path: str):
        if not self.local_paths.stat:
            return UploadPackageResult(
                    status=UploadPackageStatus.FAILED,
                    message='stat path not set.',
            )

        if file_lock_is_busy(self.task_lock_path(TaskType.UPLOAD_PACKAGE, name)):
            return UploadPackageResult(
                    status=UploadPackageStatus.TASK_CREATED,
                    message='upload task is running.',
            )

        if os.path.getsize(path) < self.config.large_package_bytes:
            # Small package.
            ctx = self.upload_package_task(name, meta, path)
            status = UploadPackageStatus.FINISHED if not ctx.failed else UploadPackageStatus.FAILED
            return UploadPackageResult(
                    status=status,
                    message=ctx.message,
            )

        else:
            # Large package.
            task_id = shortuuid.ShortUUID().random(length=6)
            args_path = self.task_args_path(TaskType.UPLOAD_PACKAGE, name, task_id)

            repo_dict = asdict(self)
            task_dict = {
                    'name': name,
                    'meta': meta,
                    'path': path,
                    'task_id': task_id,
            }
            task_paths = {
                    'lock':
                            self.task_lock_path(TaskType.UPLOAD_PACKAGE, name),
                    'runstat_lock':
                            self.task_runstat_lock_path(TaskType.UPLOAD_PACKAGE, name),
                    'runstat':
                            self.task_runstat_path(TaskType.UPLOAD_PACKAGE, name),
                    'logging':
                            self.task_logging_path(TaskType.UPLOAD_PACKAGE, name, task_id),
                    'finalstat_lock':
                            self.task_finalstat_lock_path(TaskType.UPLOAD_PACKAGE, name, task_id),
                    'finalstat':
                            self.task_finalstat_path(TaskType.UPLOAD_PACKAGE, name, task_id),
            }

            write_args(
                    args_path,
                    {
                            'repo_dict': repo_dict,
                            'task_dict': task_dict,
                            'task_paths': task_paths,
                    },
            )
            subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
                    ['github_upload_package', args_path, '--remove_args_path'],
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

    def show_task_upload_package(self, name: str, task_id: str):
        raise NotImplementedError()

    def _get_published_release(self, ctx: UploadAndDownloadPackageContext):
        try:
            ctx.release = self._gh_repo.get_release(ctx.name)

        except github.UnknownObjectException:
            ctx.failed = True
            ctx.message = f'package={ctx.name} not exists.'

        except github.BadCredentialsException:
            ctx.failed = True
            ctx.message = f'cannot get package={ctx.name} due to invalid credential.'

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


@dataclass
class FileLikeObject(TextIO):  # pylint: disable=abstract-method
    write_func: Callable

    def write(self, s: str) -> int:
        self.write_func(s)
        return 0


def github_upload_package(args_path: str, remove_args_path: bool = False):
    args = read_args(args_path)

    if remove_args_path:
        os.remove(args_path)

    repo_dict = args['repo_dict']
    task_dict = args['task_dict']

    logging.basicConfig(level=logging.INFO, filename=args['task_paths']['logging'])

    logger_stdout = logging.getLogger('stdout')
    file_like_stdout = FileLikeObject(logger_stdout.info)

    logger_stderr = logging.getLogger('stderr')
    file_like_stderr = FileLikeObject(logger_stderr.error)

    flock = FileLock(args['task_paths']['lock'])
    flock.acquire()

    failed = False

    try:
        with contextlib.redirect_stdout(file_like_stdout), \
                contextlib.redirect_stderr(file_like_stderr):
            repo = GitHubPkgRepo(
                    config=GitHubConfig(**repo_dict['config']),
                    secret=GitHubAuthToken(**repo_dict['secret']),
                    local_paths=LocalPaths(**repo_dict['local_paths']),
            )

            if not locked_write_toml(
                    args['task_paths']['runstat_lock'],
                    args['task_paths']['runstat'],
                    task_dict,
                    timeout=1.0,
            ):
                logger_stderr.error('blocked for writing to runstat.')
                return 1

            logger_stdout.info('Task=%s created', task_dict['task_id'])

            ctx = repo.upload_package_task(task_dict['name'], task_dict['meta'], task_dict['path'])
            failed = ctx.failed

            logger_stdout.info('Task failed: %s', ctx.failed)
            logger_stdout.info('Task message: %s', ctx.message)

            logger_stdout.info('Task=%s finished', task_dict['task_id'])

    except:  # pylint: disable=bare-except
        logger_stderr.error(traceback.format_exc())
        failed = True
        return 1

    finally:
        with open(args['task_paths']['logging']) as fin:
            logging_message = fin.read()

        locked_write_toml(
                args['task_paths']['finalstat_lock'],
                args['task_paths']['finalstat'],
                {
                        'failed': failed,
                        'logging_message': logging_message,
                },
                timeout=1.0,
        )

        flock.release()

    return 0


github_upload_package_cli = lambda: fire.Fire(github_upload_package)  # pylint: disable=invalid-name
