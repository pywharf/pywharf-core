import time
from tests.conftest import create_random_file
from private_pypi.backends.backend import (
        UploadPackageStatus,
        UploadIndexStatus,
        DownloadIndexStatus,
)
from private_pypi.utils import read_toml, write_toml


def test_upload_small_package(dirty_github_pkg_repo, tmp_path):
    repo = dirty_github_pkg_repo
    result = repo.upload_package(
            'small-1.0-py3-none-any.whl',
            {'name': 'small'},
            create_random_file(str(tmp_path / 'small-1.0-py3-none-any.whl'), 128),
    )
    assert result.status == UploadPackageStatus.SUCCEEDED


def test_upload_and_download_index_file(empty_github_pkg_repo, tmp_path):
    repo = empty_github_pkg_repo

    # Create.
    index_path = str(tmp_path / 'index.toml')
    data = {'foo': 'bar'}
    write_toml(index_path, data)

    result = repo.upload_index(index_path)
    assert result.status == UploadIndexStatus.SUCCEEDED

    download_index_path = str(tmp_path / 'download-index.toml')
    result = repo.download_index(download_index_path)
    assert result.status == DownloadIndexStatus.SUCCEEDED
    assert read_toml(download_index_path) == data

    # Update.
    index_path = str(tmp_path / 'index-2.toml')
    data = {'foo': 'baz', 'bar': 'qux'}
    write_toml(index_path, data)

    result = repo.upload_index(index_path)
    assert result.status == UploadIndexStatus.SUCCEEDED

    download_index_path = str(tmp_path / 'download-index-2.toml')
    result = repo.download_index(download_index_path)
    assert result.status == DownloadIndexStatus.SUCCEEDED
    assert read_toml(download_index_path) == data
