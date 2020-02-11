import contextlib
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum, auto
import hashlib
import logging
import os
import os.path
import subprocess
import traceback
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from filelock import FileLock
import fire
import github
import requests
import shortuuid
import toml

import private_pypi
from private_pypi.pkg_repos.pkg_repo import (
        LocalPaths,
        PkgRef,
        PkgRepo,
        PkgRepoConfig,
        PkgRepoSecret,
        UploadPackageStatus,
        UploadPackageResult,
        UploadIndexStatus,
        UploadIndexResult,
        DownloadIndexStatus,
        DownloadIndexResult,
        record_error_if_raises,
)
from private_pypi.utils import (
        LockedFileLikeObject,
        file_lock_is_busy,
        locked_read_file,
        locked_read_toml,
        locked_write_toml,
        normalize_distribution_name,
        read_toml,
        write_toml,
)

GITHUB_TYPE = 'github'


@dataclass
class GitHubConfig(PkgRepoConfig):
    owner: str = ''
    repo: str = ''
    branch: str = 'master'
    index_filename: str = 'index.toml'
    large_package_bytes: int = 1024**2

    def __post_init__(self):
        assert self.owner and self.repo
        self.type = GITHUB_TYPE
        # https://help.github.com/en/github/managing-large-files/distributing-large-binaries
        self.max_file_bytes = 2 * 1024**3 - 1


@dataclass
class GitHubAuthToken(PkgRepoSecret):
    token: Optional[str] = None

    def __post_init__(self):
        self.token = self.raw
        self.type = GITHUB_TYPE

    def secret_hash(self) -> str:
        sha256_algo = hashlib.sha256()
        sha256_algo.update(self.token.encode())
        return f'github-{sha256_algo.hexdigest()}'


@dataclass
class GitHubPkgRef(PkgRef):
    url: str = ''

    def __post_init__(self):
        assert self.url
        self.type = GITHUB_TYPE

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


LOCK_TIMEOUT = 0.5


@dataclass
class GitHubPkgRepo(PkgRepo):
    config: GitHubConfig
    secret: GitHubAuthToken

    def __post_init__(self):
        # pylint: disable=attribute-defined-outside-init
        self._ready = True
        self._err_msg = ''

        try:
            self._gh_client: github.Github = github.Github(self.secret.token)
            self._gh_fullname = f'{self.config.owner}/{self.config.repo}'
            self._gh_repo: github.Repository.Repository = \
                    self._gh_client.get_repo(self._gh_fullname)
            self._gh_username: str = self._gh_client.get_user().login
            self._gh_permission: str = self._gh_repo.get_collaborator_permission(self._gh_username)

        except:  # pylint: disable=bare-except
            self.record_error(traceback.format_exc())

    def record_error(self, error_message: str) -> None:
        # pylint: disable=attribute-defined-outside-init
        self._ready = False
        self._err_msg = error_message

    def ready(self) -> Tuple[bool, str]:
        return self._ready, self._err_msg

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
        if not ctx.meta.get('distrib'):
            name = ctx.meta.get('name')
            if name:
                ctx.meta['distrib'] = normalize_distribution_name(name)

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

    @record_error_if_raises
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
                    'task_created_time': datetime.now(),
            }

            write_toml(
                    task_path.args,
                    {
                            'repo_dict': asdict(self),
                            'task_dict': task_dict,
                            'task_path_dict': asdict(task_path),
                    },
            )
            subprocess.Popen(  # pylint: disable=subprocess-popen-preexec-fn
                    ['private_pypi_github_upload_package', task_path.args, '--remove_args_path'],
                    # Share env for resolving `private_pypi_github_upload_package`.
                    env=dict(os.environ),
                    # Add to the current process group.
                    preexec_fn=os.setpgrp,
                    # Suppress stdout and stderr.
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
            )

            return UploadPackageResult(
                    status=UploadPackageStatus.TASK_CREATED,
                    task_id=task_id,
                    message=f'Upload task created with task_id={task_id}',
            )

    @record_error_if_raises
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

                elif not os.path.exists(task_path.args):
                    # No final state and no args file.
                    status = UploadPackageStatus.FAILED
                    message = 'Args file not found. Please help report this bug.'

                else:
                    # No final state, check the task created time.
                    args = read_toml(task_path.args)
                    delta = datetime.now() - args['task_dict']['task_created_time']
                    if delta.total_seconds() < 10:
                        status = UploadPackageStatus.TASK_CREATED
                        message = 'Task was just created and is not runnng.'

                    else:
                        status = UploadPackageStatus.FAILED
                        message = ('Task is not runnng'
                                   f'incorrect (filename={filename}, task_id={task_id}).')

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

    @record_error_if_raises
    def download_package(self, filename: str, output: str):
        raise NotImplementedError()

    @record_error_if_raises
    def view_task_download_package(self, filename: str, task_id: str):
        raise NotImplementedError()

    @record_error_if_raises
    def delete_package(self, filename: str) -> bool:
        raise NotImplementedError()

    @record_error_if_raises
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

            package, ext = os.path.splitext(release.tag_name)
            ext = ext.lstrip('.')
            if not package or not ext:
                continue
            if len(ext) > len('tar.gz'):
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
                    ext=ext,
                    sha256=sha256,
                    meta=meta,
                    url=url,
            )
            pkg_refs.append(pkg_ref)

        return pkg_refs

    def upload_index(self, path: str) -> UploadIndexResult:
        try:
            # Check if the index exists in the remote.
            root_tree = self._gh_repo.get_git_tree(self.config.branch, recursive=False)
            index_sha = None
            for tree_element in root_tree.tree:
                if tree_element.path == self.config.index_filename:
                    index_sha = tree_element.sha
                    break

            with open(path, 'rb') as fin:
                content = fin.read()

            if index_sha is None:
                # Index file not exists, create file.
                self._gh_repo.create_file(
                        path=self.config.index_filename,
                        message='Index file created.',
                        branch=self.config.branch,
                        content=content,
                )

            else:
                # Index file exists, update file.
                self._gh_repo.update_file(
                        path=self.config.index_filename,
                        message='Index file updated.',
                        branch=self.config.branch,
                        sha=index_sha,
                        content=content,
                )

            return UploadIndexResult(status=UploadIndexStatus.SUCCEEDED)

        except:  # pylint: disable=bare-except
            error_message = traceback.format_exc()
            self.record_error(error_message)
            return UploadIndexResult(status=UploadIndexStatus.FAILED, message=error_message)

    @record_error_if_raises
    def download_index(self, output: str) -> DownloadIndexResult:
        try:
            content_file = self._gh_repo.get_contents(
                    self.config.index_filename,
                    ref=self.config.branch,
            )
            with open(output, 'wb') as fout:
                fout.write(content_file.decoded_content)

            return DownloadIndexResult(status=DownloadIndexStatus.SUCCEEDED)

        except:  # pylint: disable=bare-except
            error_message = traceback.format_exc()
            self.record_error(error_message)
            return DownloadIndexResult(status=DownloadIndexStatus.FAILED, message=error_message)


def github_upload_package(args_path: str, remove_args_path: bool = False):
    args = read_toml(args_path)

    if remove_args_path:
        try:
            os.remove(args_path)
        except IOError:
            pass

    task_path = TaskPath(**args['task_path_dict'])

    # Setup logging.
    logging.basicConfig(level=logging.INFO, filename=task_path.logging)
    logging.getLogger("filelock").setLevel(logging.WARNING)

    logger_stdout = logging.getLogger('stdout')
    lfl_stdout = LockedFileLikeObject(task_path.logging_lock, logger_stdout.info)

    logger_stderr = logging.getLogger('stderr')
    lfl_stderr = LockedFileLikeObject(task_path.logging_lock, logger_stderr.error)

    repo_dict = args['repo_dict']
    task_dict = args['task_dict']

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


def github_create_package_repo(
        name: str,
        repo: str,
        token: str,
        owner: Optional[str] = None,
        branch: str = GitHubConfig.branch,
        index_filename: str = GitHubConfig.index_filename,
):
    gh_client = github.Github(token)
    gh_user = gh_client.get_user()

    if owner is None or owner == gh_user.login:
        gh_entity = gh_user
    else:
        gh_entity = gh_client.get_organization(owner)

    # Create repo.
    description = (
            'Autogen package repository of python-best-practices/private-pypi '
            f'({private_pypi.__doc__} homepage https://github.com/python-best-practices/private-pypi), '
            f'created by user {gh_user.login}. ')
    gh_repo = gh_entity.create_repo(
            name=repo,
            description=description,
            homepage='https://github.com/python-best-practices/private-pypi',
            has_issues=False,
            has_wiki=False,
            has_downloads=False,
            has_projects=False,
            auto_init=True,
    )

    # Default branch setup.
    master_ref = gh_repo.get_git_ref('heads/master')
    master_ref_sha = master_ref._rawData['object']['sha']  # pylint: disable=protected-access
    if branch != 'master':
        gh_repo.create_git_ref(f'refs/heads/{branch}', master_ref_sha)
        gh_repo.edit(default_branch=branch)

    # Create empty index. If not, `download_index` will not succeed.
    gh_repo.create_file(
            path=index_filename,
            message='Empty index created.',
            branch=branch,
            content='',
    )

    # Workflow setup in the default branch.
    main_yaml_content_with = '\n'
    # For compatibility, don't add the `with` statement if default values are used.
    if branch != GitHubConfig.branch or index_filename != GitHubConfig.index_filename:
        main_yaml_content_with = f'''\
     with:
       github_branch: {branch}
       index_filename: {index_filename}
'''
    # Body.
    main_yaml_content = f'''\
name: sync-index
on:
 push:
 schedule:
  - cron: "* * * * *"
jobs:
 build:
  runs-on: ubuntu-latest
  steps:
   - uses: python-best-practices/private-pypi-sync-index@master
'''
    gh_repo.create_file(
            path='.github/workflows/main.yml',
            message='Workflow sync-index created.',
            branch=branch,
            content=main_yaml_content + main_yaml_content_with,
    )

    # Print config.
    github_config = GitHubConfig(
            name=name,
            owner=owner or gh_user.login,
            repo=repo,
            branch=branch,
            index_filename=index_filename,
    )

    github_config_dict = asdict(github_config)
    github_config_dict.pop('name')
    # Remove the default settings.
    github_config_dict.pop('large_package_bytes')
    github_config_dict.pop('max_file_bytes')
    if branch == GitHubConfig.branch:
        github_config_dict.pop('branch')
    if index_filename == GitHubConfig.index_filename:
        github_config_dict.pop('index_filename')

    print('Package repository TOML config (please add to your private-pypi config file):\n')
    print(toml.dumps({name: github_config_dict}))


github_create_package_repo_cli = lambda: fire.Fire(github_create_package_repo)  # pylint: disable=invalid-name
github_upload_package_cli = lambda: fire.Fire(github_upload_package)  # pylint: disable=invalid-name
