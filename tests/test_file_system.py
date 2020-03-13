from typing import Tuple

import shortuuid

from private_pypi_testkit import TestKit, RepoInfoForTest
from private_pypi_backends.file_system.impl import (
        FileSystemConfig,
        FileSystemSecret,
)


class FileSystemTestKit(TestKit):

    @classmethod
    def setup_pkg_repo(cls) -> Tuple[FileSystemConfig, FileSystemSecret, FileSystemSecret]:
        name = f'fs-{shortuuid.uuid()}'
        raw_read_secret = 'foo'
        raw_write_secret = 'bar'

        pkg_repo_config = FileSystemConfig(
                name=name,
                read_secret=raw_read_secret,
                write_secret=raw_write_secret,
        )
        read_secret = FileSystemSecret(
                name=name,
                raw=raw_read_secret,
        )
        write_secret = FileSystemSecret(
                name=name,
                raw=raw_write_secret,
        )
        return pkg_repo_config, read_secret, write_secret

    @classmethod
    def update_repo_index(cls, repo: RepoInfoForTest) -> bool:
        # No need to update.
        return True


FileSystemTestKit.pytest_injection()
