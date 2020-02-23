import tempfile
import random
import time
import fire
from private_pypi.backends.backend import (
        UploadPackageStatus,
        UploadIndexStatus,
        BackendInstanceManager,
)
from tests.conftest import create_github_pkg_repo_for_test, create_random_file


def main(config, index):
    bim = BackendInstanceManager()
    repo = create_github_pkg_repo_for_test('preset_github_test_20200223')

    for idx in range(20):
        with tempfile.NamedTemporaryFile() as ntf:
            create_random_file(ntf.name, random.randint(50, 100))

            print('Uploading pkg', idx)
            result = repo.upload_package(
                    f'pkg_{idx}-1.0-py3-none-any.whl',
                    {'name': f'pkg_{idx}'},
                    ntf.name,
            )
            print(result.message)
            assert result.status == UploadPackageStatus.SUCCEEDED

    pkg_refs = repo.collect_all_published_packages()
    bim.dump_pkg_refs(index, pkg_refs)

    print('Uploading index')
    result = repo.upload_index(index)
    assert result.status == UploadIndexStatus.SUCCEEDED

    bim.dump_pkg_repo_configs(config, [repo.config])


fire.Fire(main)
