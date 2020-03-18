from abc import abstractmethod
from dataclasses import dataclass
import os
from typing import Optional, Tuple
import inspect

import pytest
from _pytest.monkeypatch import MonkeyPatch
import shortuuid

from private_pypi_core.backend import (
        BackendInstanceManager,
        PkgRepoConfig,
        PkgRepoSecret,
)
from private_pypi_core.workflow import (
        WorkflowStat,
        initialize_task_worker,
        build_workflow_stat,
        sync_local_index,
        workflow_api_simple_distrib,
        workflow_api_upload_package,
)


@dataclass
class RepoInfoForTest:
    pkg_repo_config_file: str
    admin_pkg_repo_secret_file: str
    root_folder: str
    name: str
    wstat: WorkflowStat
    read_secret: PkgRepoSecret
    write_secret: PkgRepoSecret


def create_random_file(path, size):
    with open(path, 'wb') as fout:
        fout.write(os.urandom(size))
    return path


def test_admin_secret_as_env(function_repo_admin_secret_as_env):
    assert function_repo_admin_secret_as_env


def test_upload_with_write_secret(session_repo, tmpdir, update_repo_index):
    distrib = shortuuid.uuid()
    filename = f'{distrib}-1.0-py3-none-any.whl'
    path = str(tmpdir.join(filename))
    create_random_file(path, 128)

    # Upload.
    _, status_code = workflow_api_upload_package(
            wstat=session_repo.wstat,
            name=session_repo.name,
            pkg_repo_secret=session_repo.write_secret,
            filename=filename,
            meta={'name': distrib},
            path=path,
    )
    assert status_code == 200

    # Update index in remote.
    assert update_repo_index(session_repo)

    # Sync local index.
    passed, _ = sync_local_index(session_repo.wstat)
    assert passed

    # Check if package exists.
    _, status_code = workflow_api_simple_distrib(
            wstat=session_repo.wstat,
            name=session_repo.name,
            pkg_repo_secret=session_repo.write_secret,
            distrib=distrib,
    )
    assert status_code == 200


def test_upload_with_read_secret(session_repo, tmpdir):
    distrib = shortuuid.uuid()
    filename = f'{distrib}-1.0-py3-none-any.whl'
    path = str(tmpdir.join(filename))
    create_random_file(path, 128)

    _, status_code = workflow_api_upload_package(
            wstat=session_repo.wstat,
            name=session_repo.name,
            pkg_repo_secret=session_repo.read_secret,
            filename=filename,
            meta={'name': distrib},
            path=path,
    )
    assert status_code == 401


class TestKit:

    @classmethod
    @abstractmethod
    def setup_pkg_repo(cls) -> Tuple[PkgRepoConfig, PkgRepoSecret, PkgRepoSecret]:
        pass

    @classmethod
    @abstractmethod
    def update_repo_index(cls, repo: RepoInfoForTest) -> bool:
        return False

    @classmethod
    def pytest_injection(cls):
        _caller_frame = inspect.currentframe().f_back

        def inject_to_caller(func):
            caller_globals = _caller_frame.f_globals
            caller_globals[func.__name__] = func
            return func

        def _create_repo_for_test(create_tmpdir, set_env, admin_secret_as_env=False):
            config_folder = create_tmpdir('config')

            pkg_repo_config, read_secret, write_secret = cls.setup_pkg_repo()
            pkg_repo_config_file = str(config_folder.join('config.toml'))
            admin_pkg_repo_secret_file = str(config_folder.join('admin_secret.toml'))

            BackendInstanceManager.dump_pkg_repo_configs(pkg_repo_config_file, [pkg_repo_config])

            if not admin_secret_as_env:
                BackendInstanceManager.dump_pkg_repo_secrets(
                        admin_pkg_repo_secret_file,
                        [read_secret],
                )
            else:
                env = shortuuid.uuid()
                BackendInstanceManager.dump_pkg_repo_secrets(
                        admin_pkg_repo_secret_file,
                        [read_secret],
                        {pkg_repo_config.name.lower(): env},
                )
                set_env(env, read_secret.raw)

            root_folder = str(create_tmpdir('root'))

            wstat = build_workflow_stat(
                    pkg_repo_config_file=pkg_repo_config_file,
                    admin_pkg_repo_secret_file=admin_pkg_repo_secret_file,
                    root_folder=root_folder,
                    auth_read_expires=0,
                    auth_write_expires=0,
            )

            return RepoInfoForTest(
                    name=pkg_repo_config.name.lower(),
                    pkg_repo_config_file=pkg_repo_config_file,
                    admin_pkg_repo_secret_file=admin_pkg_repo_secret_file,
                    root_folder=root_folder,
                    read_secret=read_secret,
                    write_secret=write_secret,
                    wstat=wstat,
            )

        @inject_to_caller
        @pytest.fixture(scope='session')
        def session_repo(tmpdir_factory):  # pylint: disable=unused-variable
            monkeypatch = MonkeyPatch()

            yield _create_repo_for_test(
                    tmpdir_factory.mktemp,
                    monkeypatch.setenv,
                    admin_secret_as_env=False,
            )

            monkeypatch.undo()

        @inject_to_caller
        @pytest.fixture(scope='function')
        def function_repo(tmpdir, monkeypatch):  # pylint: disable=unused-variable
            yield _create_repo_for_test(
                    tmpdir.mkdir,
                    monkeypatch.setenv,
                    admin_secret_as_env=False,
            )

        @inject_to_caller
        @pytest.fixture(scope='function')
        def function_repo_admin_secret_as_env(tmpdir, monkeypatch):  # pylint: disable=unused-variable
            yield _create_repo_for_test(
                    tmpdir.mkdir,
                    monkeypatch.setenv,
                    admin_secret_as_env=True,
            )

        @inject_to_caller
        @pytest.fixture(scope='function')
        def update_repo_index():  # pylint: disable=unused-variable
            yield cls.update_repo_index

        inject_to_caller(test_admin_secret_as_env)
        inject_to_caller(test_upload_with_write_secret)
        inject_to_caller(test_upload_with_read_secret)

        initialize_task_worker()
