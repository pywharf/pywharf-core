from private_pypi_core.backend import BackendRegistration
from private_pypi_backends.file_system.impl import (
        FILE_SYSTEM_TYPE,
        FileSystemConfig,
        FileSystemSecret,
        FileSystemPkgRepo,
        FileSystemPkgRef,
)


class FileSystemRegistration(BackendRegistration):
    type = FILE_SYSTEM_TYPE
    pkg_repo_config_cls = FileSystemConfig
    pkg_repo_secret_cls = FileSystemSecret
    pkg_repo_cls = FileSystemPkgRepo
    pkg_ref_cls = FileSystemPkgRef
