import contextlib
from dataclasses import asdict, dataclass
from enum import Enum, auto
import logging
import os
import os.path
import subprocess
import traceback
from typing import Callable, Dict, Optional, TextIO, Tuple, List

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
        PkgRef,
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
    filename: str
    meta: Optional[Dict[str, str]] = None
    path: Optional[str] = None
    release: github.GitRelease.GitRelease = None
    failed: bool = False
    message: str = ''


@dataclass
class GitHubPkgRef(PkgRef):
    browser_download_url: str

    def __post_init__(self):
        pass

    def auth_url(self, config: GitHubConfig, secret: GitHubAuthToken) -> str:
        return ''


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

    def _path_join_stat(self, filename: str):
        assert isinstance(self.local_paths.stat, str)
        return os.path.join(self.local_paths.stat, filename)

    # <task_type>-<distribution>
    def _task_name(self, task_type: TaskType, filename: str):
        return f'{self.config.name}-{task_type.name.lower()}-{filename}'

    def task_lock_path(self, task_type: TaskType, filename: str):
        return self._path_join_stat(f'{self._task_name(task_type, filename)}.lock')

    # task_runstat: metadata of the running task like task id.
    def task_runstat_lock_path(self, task_type: TaskType, filename: str):
        return self._path_join_stat(f'{self._task_name(task_type, filename)}.runstat.lock')

    def task_runstat_path(self, task_type: TaskType, filename: str):
        return self._path_join_stat(f'{self._task_name(task_type, filename)}.runstat')

    # <task_type>-<distribution>-<task_id>
    def _task_name_id(self, task_type: TaskType, filename: str, task_id: str):
        return f'{self._task_name(task_type, filename)}-{task_id}'

    # task_args: the input of task.
    def task_args_path(self, task_type: TaskType, filename: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, filename, task_id)}.args')

    # task_logging: the logging of task.
    def task_logging_lock_path(self, task_type: TaskType, filename: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, filename, task_id)}.log.lock')

    def task_logging_path(self, task_type: TaskType, filename: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, filename, task_id)}.log')

    # task_final: metadata of the final result.
    def task_finalstat_lock_path(self, task_type: TaskType, filename: str, task_id: str):
        return self._path_join_stat(
                f'{self._task_name_id(task_type, filename, task_id)}.finalstat.lock')

    def task_finalstat_path(self, task_type: TaskType, filename: str, task_id: str):
        return self._path_join_stat(f'{self._task_name_id(task_type, filename, task_id)}.finalstat')

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

        if file_lock_is_busy(self.task_lock_path(TaskType.UPLOAD_PACKAGE, filename)):
            runstat_status, runstat = locked_read_toml(
                    self.task_runstat_lock_path(TaskType.UPLOAD_PACKAGE, filename),
                    self.task_runstat_path(TaskType.UPLOAD_PACKAGE, filename),
                    timeout=LOCK_TIMEOUT,
            )
            return UploadPackageResult(
                    status=UploadPackageStatus.TASK_CREATED,
                    message='upload task is running.',
                    task_id=None if not runstat_status else runstat['task_id'],
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
            args_path = self.task_args_path(TaskType.UPLOAD_PACKAGE, filename, task_id)

            repo_dict = asdict(self)
            # TODO: dataclass.
            task_dict = {
                    'filename': filename,
                    'meta': meta,
                    'path': path,
                    'task_id': task_id,
            }
            task_paths = {
                    'lock':
                            self.task_lock_path(TaskType.UPLOAD_PACKAGE, filename),
                    'runstat_lock':
                            self.task_runstat_lock_path(TaskType.UPLOAD_PACKAGE, filename),
                    'runstat':
                            self.task_runstat_path(TaskType.UPLOAD_PACKAGE, filename),
                    'logging_lock':
                            self.task_logging_lock_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
                    'logging':
                            self.task_logging_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
                    'finalstat_lock':
                            self.task_finalstat_lock_path(TaskType.UPLOAD_PACKAGE, filename,
                                                          task_id),
                    'finalstat':
                            self.task_finalstat_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
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

    def view_task_upload_package(self, filename: str, task_id: str) -> UploadPackageResult:
        if not self.local_paths.stat:
            status = UploadPackageStatus.FAILED
            message = 'stat path not set.'

        elif file_lock_is_busy(self.task_lock_path(TaskType.UPLOAD_PACKAGE, filename)):
            logging_message_status, logging_message = locked_read_file(
                    self.task_logging_lock_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
                    self.task_logging_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
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
                    self.task_finalstat_lock_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
                    self.task_finalstat_path(TaskType.UPLOAD_PACKAGE, filename, task_id),
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
        raise NotImplementedError()

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

    logging.basicConfig(level=logging.INFO, filename=args['task_paths']['logging'])
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger_stdout = logging.getLogger('stdout')
    lfl_stdout = LockedFileLikeObject(args['task_paths']['logging_lock'], logger_stdout.info)

    logger_stderr = logging.getLogger('stderr')
    lfl_stderr = LockedFileLikeObject(args['task_paths']['logging_lock'], logger_stderr.error)

    flock = FileLock(args['task_paths']['lock'])
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
                    args['task_paths']['runstat_lock'],
                    args['task_paths']['runstat'],
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
                args['task_paths']['logging_lock'],
                args['task_paths']['logging'],
        )
        if logging_message is None:
            logging_message = 'logging file not exits.'

        locked_write_toml(
                args['task_paths']['finalstat_lock'],
                args['task_paths']['finalstat'],
                {
                        'failed': failed,
                        'logging_message': logging_message,
                },
                timeout=LOCK_TIMEOUT,
        )

        flock.release()

    return 0


github_upload_package_cli = lambda: fire.Fire(github_upload_package)  # pylint: disable=invalid-name
