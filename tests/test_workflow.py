from dataclasses import asdict

from private_pypi.pkg_repos import GitHubConfig
from private_pypi.utils import write_toml
from private_pypi.workflow import load_pkg_repo_configs


def test_load_pkg_repo_configs(tmp_path):
    gh_config = GitHubConfig(
            name='foo',
            owner='bar',
            repo='baz',
    )

    gh_config_dict = asdict(gh_config)
    name = gh_config_dict.pop('name')

    dump_path = str(tmp_path / 'config.toml')
    write_toml(dump_path, {name: gh_config_dict})

    name_to_configs = load_pkg_repo_configs(dump_path)
    assert name_to_configs[name] == gh_config
