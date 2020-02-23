from private_pypi.backends.backend import BackendRegistration
from private_pypi.backends.github.impl import (
        GITHUB_TYPE,
        GitHubConfig,
        GitHubAuthToken,
        GitHubPkgRepo,
        GitHubPkgRef,
)


class GitHubRegistration(BackendRegistration):
    type = GITHUB_TYPE
    pkg_repo_config_cls = GitHubConfig
    pkg_repo_secret_cls = GitHubAuthToken
    pkg_repo_cls = GitHubPkgRepo
    pkg_ref_cls = GitHubPkgRef
