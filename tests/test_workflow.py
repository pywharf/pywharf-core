from dataclasses import asdict

from private_pypi.pkg_repos import (
    GitHubConfig,
    load_pkg_repo_configs,
    dump_pkg_repo_configs,
)
from private_pypi.utils import write_toml


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
