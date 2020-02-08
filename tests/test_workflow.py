from dataclasses import asdict
from github_powered_pypi.pkg_repos import GitHubConfig, PkgRepoType, pkg_repo_type_to_text
from github_powered_pypi.utils import write_toml
from github_powered_pypi.workflow import load_pkg_repo_configs


def test_load_pkg_repo_configs(tmp_path):
    gh_config = GitHubConfig(
            name='foo',
            owner='bar',
            repo='baz',
    )

    gh_config_dict = asdict(gh_config)
    gh_config_dict['type'] = pkg_repo_type_to_text(PkgRepoType.GITHUB)
    name = gh_config_dict.pop('name')

    dump_path = str(tmp_path / 'config.toml')
    write_toml(dump_path, {name: gh_config_dict})

    name_to_configs = load_pkg_repo_configs(dump_path)[1]
    assert name_to_configs[name] == gh_config
