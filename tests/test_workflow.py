from dataclasses import asdict
from timeit import default_timer
import time

from private_pypi.pkg_repos import (
        GitHubConfig,
        load_pkg_repo_configs,
        dump_pkg_repo_configs,
)
from private_pypi.workflow import (
        build_workflow_stat,
        pkg_repo_is_expired,
        pkg_repo_secret_is_authenticated,
)
from tests.conftest import create_github_auth_token


class Timer:

    def __enter__(self):
        self.start = default_timer()
        return self

    def __exit__(self, *args):
        self.delta = default_timer() - self.start


def test_load_pkg_repo_configs(tmp_path):
    gh_config = GitHubConfig(
            name='foo',
            owner='bar',
            repo='baz',
    )
    dump_path = str(tmp_path / 'config.toml')
    dump_pkg_repo_configs(dump_path, [gh_config])
    name_to_configs = load_pkg_repo_configs(dump_path)
    assert name_to_configs[gh_config.name] == gh_config


def test_pkg_repo_secret_is_authenticated(preset_workflow_args):
    args = dict(preset_workflow_args)
    args['auth_read_expires'] = 1
    args['auth_write_expires'] = 1

    wstat = build_workflow_stat(**args)
    secret = create_github_auth_token()

    # Read.
    with Timer() as t:
        succeeded, _ = pkg_repo_secret_is_authenticated(
                wstat,
                'preset_github_test',
                secret,
                True,
        )
        assert succeeded
    auth_read_delta = t.delta

    with Timer() as t:
        for _ in range(100):
            succeeded, _ = pkg_repo_secret_is_authenticated(
                    wstat,
                    'preset_github_test',
                    secret,
                    True,
            )
            assert succeeded
    cached_read_delta = t.delta
    assert auth_read_delta > 100 * cached_read_delta

    time.sleep(1.0)
    with Timer() as t:
        succeeded, _ = pkg_repo_secret_is_authenticated(
                wstat,
                'preset_github_test',
                secret,
                True,
        )
        assert succeeded
    expired_read_delta = t.delta
    assert expired_read_delta > 100 * cached_read_delta

    # Write.
    with Timer() as t:
        succeeded, _ = pkg_repo_secret_is_authenticated(
                wstat,
                'preset_github_test',
                secret,
                False,
        )
        assert succeeded
    auth_write_delta = t.delta

    with Timer() as t:
        for _ in range(100):
            succeeded, _ = pkg_repo_secret_is_authenticated(
                    wstat,
                    'preset_github_test',
                    secret,
                    False,
            )
            assert succeeded
    cached_write_delta = t.delta
    assert auth_write_delta > 100 * cached_write_delta

    time.sleep(1.0)
    with Timer() as t:
        succeeded, _ = pkg_repo_secret_is_authenticated(
                wstat,
                'preset_github_test',
                secret,
                False,
        )
        assert succeeded
    expired_write_delta = t.delta
    assert expired_write_delta > 100 * cached_write_delta
