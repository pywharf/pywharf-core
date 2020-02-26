from enum import Enum, auto
from dataclasses import dataclass
import hashlib
import os
import os.path
import traceback
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import fire
import github
import requests
import toml

import private_pypi
from private_pypi.backends.backend import (
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
        basic_model_get_default,
)
from private_pypi.utils import (
        normalize_distribution_name,
        update_hash_algo_with_file,
        git_hash_sha,
)

GITHUB_TYPE = 'github'


class GitHubConfig(PkgRepoConfig):
    # Override.
    type: str = GITHUB_TYPE
    max_file_bytes: int = 2 * 1024**3 - 1
    # GitHub specific.
    owner: str
    repo: str
    branch: str = 'master'
    index_filename: str = 'index.toml'

    def __init__(self, **data):
        super().__init__(**data)

        if not self.owner or not self.repo:
            raise ValueError('owner or repo is empty.')
        if self.type != GITHUB_TYPE:
            raise ValueError(f'type != {GITHUB_TYPE}')


class GitHubAuthToken(PkgRepoSecret):
    # Override.
    type: str = GITHUB_TYPE

    @property
    def token(self) -> str:
        # pylint: disable=no-member
        return self.raw

    def secret_hash(self) -> str:
        sha256_algo = hashlib.sha256()
        sha256_algo.update(self.token.encode())
        return f'github-{sha256_algo.hexdigest()}'


class GitHubPkgRef(PkgRef):
    # Override.
    type: str = GITHUB_TYPE
    # GitHub specific.
    url: str

    def auth_url(self, config: GitHubConfig, secret: GitHubAuthToken) -> str:
        # pylint: disable=no-member
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


class JobType(Enum):
    UPLOAD_PACKAGE = auto()
    DOWNLOAD_PACKAGE = auto()


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
class GitHubPkgRepoPrivateFields:
    ready: bool
    err_msg: str
    client: Optional[github.Github] = None
    fullname: Optional[str] = None
    repo: Optional[github.Repository.Repository] = None
    username: Optional[str] = None
    permission: Optional[str] = None


class GitHubPkgRepo(PkgRepo):
    # Override.
    type: str = GITHUB_TYPE
    # GitHub specific.
    config: GitHubConfig
    secret: GitHubAuthToken

    __slots__ = ('_private_fields',)

    @property
    def _pvt(self) -> GitHubPkgRepoPrivateFields:
        return object.__getattribute__(self, '_private_fields')

    def __init__(self, **data):
        super().__init__(**data)
        object.__setattr__(
                self,
                '_private_fields',
                GitHubPkgRepoPrivateFields(ready=True, err_msg=''),
        )

        try:
            self._pvt.client = github.Github(self.secret.token)
            self._pvt.fullname = f'{self.config.owner}/{self.config.repo}'
            self._pvt.repo = self._pvt.client.get_repo(self._pvt.fullname)
            self._pvt.username = self._pvt.client.get_user().login
            self._pvt.permission = self._pvt.repo.get_collaborator_permission(self._pvt.username)

        except:  # pylint: disable=bare-except
            self.record_error(traceback.format_exc())

    def record_error(self, error_message: str) -> None:
        self._pvt.ready = False
        self._pvt.err_msg = error_message

    def ready(self) -> Tuple[bool, str]:
        return self._pvt.ready, self._pvt.err_msg

    def auth_read(self) -> bool:
        return self._pvt.permission != 'none'

    def auth_write(self) -> bool:
        return self._pvt.permission in ('admin', 'write')

    def _check_published_release_not_exists(self, ctx: UploadAndDownloadPackageContext):
        try:
            self._pvt.repo.get_release(ctx.filename)
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
            ctx.release = self._pvt.repo.create_git_release(
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
            update_hash_algo_with_file(ctx.path, sha256_algo)
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

    def upload_package_job(self, filename: str, meta: Dict[str, str], path: str):
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
        ctx = self.upload_package_job(filename, meta, path)
        status = UploadPackageStatus.SUCCEEDED if not ctx.failed else UploadPackageStatus.FAILED
        return UploadPackageResult(
                status=status,
                message=ctx.message,
        )

    @record_error_if_raises
    def collect_all_published_packages(self) -> List[GitHubPkgRef]:
        pkg_refs: List[GitHubPkgRef] = []

        for release in self._pvt.repo.get_releases():
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

    def _get_index_sha(self) -> Optional[str]:
        root_tree = self._pvt.repo.get_git_tree(self.config.branch, recursive=False)
        for tree_element in root_tree.tree:
            if tree_element.path == self.config.index_filename:
                return tree_element.sha
        return None

    def upload_index(self, path: str) -> UploadIndexResult:
        try:
            index_sha = self._get_index_sha()
            if index_sha is None:
                with open(path, 'rb') as fin:
                    content = fin.read()
                # Index file not exists, create file.
                self._pvt.repo.create_file(
                        path=self.config.index_filename,
                        message='Index file created.',
                        branch=self.config.branch,
                        content=content,
                )

            elif git_hash_sha(path) != index_sha:
                with open(path, 'rb') as fin:
                    content = fin.read()
                # Index file exists, and need to update.
                self._pvt.repo.update_file(
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

    # This function could raise exception.
    def local_index_is_up_to_date(self, path: str) -> bool:
        if not os.path.exists(path):
            raise FileNotFoundError(f'{path} not exists.')

        index_sha = self._get_index_sha()
        return index_sha is not None and index_sha == git_hash_sha(path)

    @record_error_if_raises
    def download_index(self, path: str) -> DownloadIndexResult:
        try:
            if os.path.exists(path) and self.local_index_is_up_to_date(path):
                # Same file, no need to download.
                return DownloadIndexResult(status=DownloadIndexStatus.SUCCEEDED)

            content_file = self._pvt.repo.get_contents(
                    self.config.index_filename,
                    ref=self.config.branch,
            )
            with open(path, 'wb') as fout:
                fout.write(content_file.decoded_content)

            return DownloadIndexResult(status=DownloadIndexStatus.SUCCEEDED)

        except:  # pylint: disable=bare-except
            error_message = traceback.format_exc()
            self.record_error(error_message)
            return DownloadIndexResult(status=DownloadIndexStatus.FAILED, message=error_message)


def github_create_package_repo(
        name: str,
        repo: str,
        token: str,
        owner: Optional[str] = None,
        branch: str = basic_model_get_default(GitHubConfig, 'branch'),
        index_filename: str = basic_model_get_default(GitHubConfig, 'index_filename'),
        sync_index_interval: int = basic_model_get_default(GitHubConfig, 'sync_index_interval'),
):
    gh_client = github.Github(token)
    gh_user = gh_client.get_user()

    if owner is None or owner == gh_user.login:
        gh_entity = gh_user
    else:
        gh_entity = gh_client.get_organization(owner)

    # Create repo.
    description = (
            'Autogen package repository of private-pypi/private-pypi '
            f'({private_pypi.__doc__} homepage https://github.com/private-pypi/private-pypi), '
            f'created by user {gh_user.login}. ')
    gh_repo = gh_entity.create_repo(
            name=repo,
            description=description,
            homepage='https://github.com/private-pypi/private-pypi',
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
    if branch != basic_model_get_default(GitHubConfig, 'branch') \
            or index_filename != basic_model_get_default(GitHubConfig, 'index_filename'):
        main_yaml_content_with = f'''\
     with:
       github_branch: {branch}
       index_filename: {index_filename}
'''
    # Body.
    main_yaml_content = f'''\
name: update-index-job
on:
 push:
 schedule:
  - cron: "* * * * *"
jobs:
 build:
  runs-on: ubuntu-latest
  steps:
   - uses: private-pypi/private-pypi-github-update-index@master
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

    github_config_dict = github_config.dict()
    github_config_dict.pop('name')

    # Pop the default settings.
    github_config_dict.pop('max_file_bytes')
    if branch == basic_model_get_default(GitHubConfig, 'branch'):
        github_config_dict.pop('branch')
    if index_filename == basic_model_get_default(GitHubConfig, 'index_filename'):
        github_config_dict.pop('index_filename')
    if sync_index_interval == basic_model_get_default(GitHubConfig, 'sync_index_interval'):
        github_config_dict.pop('sync_index_interval')

    print('Package repository TOML config (please add to your private-pypi config file):\n')
    print(toml.dumps({name: github_config_dict}))


github_create_package_repo_cli = lambda: fire.Fire(github_create_package_repo)  # pylint: disable=invalid-name
