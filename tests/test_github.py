import time
from tests.conftest import create_random_file
from private_pypi.pkg_repos import GitHubPkgRepo, UploadPackageStatus


def test_upload_small_package(dirty_github_pkg_repo, tmp_path):
    repo: GitHubPkgRepo = dirty_github_pkg_repo
    result = repo.upload_package(
            'small-1.0-py3-none-any.whl',
            {'name': 'small'},
            create_random_file(str(tmp_path / 'small-1.0-py3-none-any.whl'), 128),
    )
    assert result.status == UploadPackageStatus.SUCCEEDED


def test_upload_large_package(dirty_github_pkg_repo, tmp_path):
    repo: GitHubPkgRepo = dirty_github_pkg_repo
    result = repo.upload_package(
            'large-1.0-py3-none-any.whl',
            {'name': 'large'},
            create_random_file(str(tmp_path / 'large-1.0-py3-none-any.whl'), 1024),
    )
    assert result.status == UploadPackageStatus.TASK_CREATED

    task_id = result.task_id
    assert task_id

    while True:
        result = repo.view_task_upload_package('large-1.0-py3-none-any.whl', task_id)
        assert result.status != UploadPackageStatus.FAILED
        if result.status == UploadPackageStatus.SUCCEEDED:
            break
        time.sleep(0.1)
        continue
