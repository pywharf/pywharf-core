import tempfile
import random
import fire
from private_pypi.pkg_repos import (
        GitHubPkgRepo,
        UploadPackageStatus,
        UploadIndexStatus,
        build_pkg_repo_index_from_pkg_refs,
        dump_pkg_repo_index,
        dump_pkg_repo_configs,
)
from tests.conftest import create_github_pkg_repo_for_test, create_random_file


def main(config, index):
    repo: GitHubPkgRepo = create_github_pkg_repo_for_test('preset_github_test')

    for idx in range(100):
        with tempfile.NamedTemporaryFile() as ntf:
            create_random_file(ntf.name, random.randint(50, 100))

            print('Uploading pkg', idx)
            result = repo.upload_package(
                    f'pkg_{idx}-1.0-py3-none-any.whl',
                    {'name': f'pkg_{idx}'},
                    ntf.name,
            )
            assert result.status == UploadPackageStatus.SUCCEEDED

    pkg_refs = repo.collect_all_published_packages()
    pkg_repo_index = build_pkg_repo_index_from_pkg_refs(pkg_refs)
    dump_pkg_repo_index(index, pkg_repo_index)

    print('Uploading index')
    result = repo.upload_index(index)
    assert result.status == UploadIndexStatus.SUCCEEDED

    dump_pkg_repo_configs(config, [repo.config])


fire.Fire(main)
