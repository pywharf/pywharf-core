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

    def _task_name(self, task_type: TaskType, name: str):
        return f'{self.config.name}-{task_type.name.lower()}-{name}'

    def task_lock_path(self, task_type: TaskType, name: str):
        assert isinstance(self.local_paths.stat, str)
        return os.path.join(self.local_paths.stat, f'{self._task_name(task_type, name)}.lock')

    def task_lock_busy(self, task_type: TaskType, name: str):
        flock = FileLock(self.task_lock_path(task_type, name))
        busy = False
        try:
            flock.acquire(timeout=0.5)
        except TimeoutError:
            busy = True
        finally:
            flock.release()
        return busy

    def task_logging_path(self, task_type: TaskType, name: str, task_id: str):
        assert isinstance(self.local_paths.stat, str)
        return os.path.join(self.local_paths.stat,
                            f'{self._task_name(task_type, name)}-{task_id}.log')

    def task_logging_exists(self, task_type: TaskType, name: str, task_id: str):
        return os.path.exists(self.task_logging_path(task_type, name, task_id))

    def task_args_path(self, task_type: TaskType, name: str, task_id: str):
        assert isinstance(self.local_paths.stat, str)
        return os.path.join(self.local_paths.stat,
                            f'{self._task_name(task_type, name)}-{task_id}.args')

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

        if self.task_lock_busy(TaskType.UPLOAD_PACKAGE, name):
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
            write_args(
                    args_path,
                    {
                            'repo_dict':
                                    asdict(self),
                            'task_dict': {
                                    'name': name,
                                    'meta': meta,
                                    'path': path,
                                    'task_id': task_id,
                            },
                            'lock_path':
                                    self.task_lock_path(TaskType.UPLOAD_PACKAGE, name),
                            'logging_path':
                                    self.task_logging_path(TaskType.UPLOAD_PACKAGE, name, task_id),
                    },
            )
            subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
                    ['github_upload_package', args_path, '--remove_args_path'],
                    env=dict(os.environ),
                    preexec_fn=os.setpgrp,
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

    logging.basicConfig(level=logging.INFO, filename=args['logging_path'])

    logger_stdout = logging.getLogger('stdout')
    file_like_stdout = FileLikeObject(logger_stdout.info)

    logger_stderr = logging.getLogger('stderr')
    file_like_stderr = FileLikeObject(logger_stderr.error)

    flock = FileLock(args['lock_path'])
    flock.acquire()

    try:
        with contextlib.redirect_stdout(file_like_stdout), \
                contextlib.redirect_stderr(file_like_stderr):
            repo = GitHubPkgRepo(
                    config=GitHubConfig(**repo_dict['config']),
                    secret=GitHubAuthToken(**repo_dict['secret']),
                    local_paths=LocalPaths(**repo_dict['local_paths']),
            )

            logger_stdout.info('Task=%s created', task_dict['task_id'])

            ctx = repo.upload_package_task(task_dict['name'], task_dict['meta'], task_dict['path'])
            logger_stdout.info('Task failed: %s', ctx.failed)
            logger_stdout.info('Task message: %s', ctx.message)

            logger_stdout.info('Task=%s finished', task_dict['task_id'])

    except:  # pylint: disable=bare-except
        logger_stderr.error(traceback.format_exc())

    finally:
        flock.release()


github_upload_package_cli = lambda: fire.Fire(github_upload_package)  # pylint: disable=invalid-name
