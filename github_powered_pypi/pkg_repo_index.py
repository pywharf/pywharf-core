from typing import Dict, Iterable, List, Optional, Type
from dataclasses import asdict
from itertools import chain

from github_powered_pypi.pkg_repos import PkgRef
from github_powered_pypi.utils import normalize_distribution_name, write_toml, read_toml


class PkgRepoIndex:

    def __init__(self) -> None:
        self._distrib_to_pkg_refs: Dict[str, List[PkgRef]] = {}
        self._package_to_pkg_ref: Dict[str, PkgRef] = {}

    def add_pkg_ref(self, pkg_ref: PkgRef) -> None:
        if pkg_ref.package in self._package_to_pkg_ref:
            raise KeyError(f'package={pkg_ref.package} duplicated.')

        if pkg_ref.distrib not in self._distrib_to_pkg_refs:
            self._distrib_to_pkg_refs[pkg_ref.distrib] = []

        self._distrib_to_pkg_refs[pkg_ref.distrib].append(pkg_ref)
        self._package_to_pkg_ref[pkg_ref.package] = pkg_ref

    @property
    def all_distributions(self) -> Iterable[str]:
        return self._distrib_to_pkg_refs.keys()

    def get_pkg_refs(self, query_distrib: str) -> Optional[List[PkgRef]]:
        distrib = normalize_distribution_name(query_distrib)
        return self._distrib_to_pkg_refs.get(distrib)

    def get_single_pkg_ref(self, query_distrib: str, query_package: str) -> Optional[PkgRef]:
        distrib = normalize_distribution_name(query_distrib)
        pkg_ref = self._package_to_pkg_ref.get(query_package)
        if pkg_ref is None or distrib != pkg_ref.distrib:
            return None
        return pkg_ref


def build_pkg_repo_index_from_pkg_refs(pkg_refs: List[PkgRef]) -> PkgRepoIndex:
    pkg_repo_index = PkgRepoIndex()
    for pkg_ref in pkg_refs:
        pkg_repo_index.add_pkg_ref(pkg_ref)
    return pkg_repo_index


def dump_pkg_repo_index(path: str, pkg_repo_index: PkgRepoIndex):
    struct = {}
    for distrib in pkg_repo_index.all_distributions:
        struct_pkg_refs = [asdict(pkg_ref) for pkg_ref in pkg_repo_index.get_pkg_refs(distrib)]
        struct[distrib] = struct_pkg_refs
    write_toml(path, struct)


def load_pkg_repo_index(path: str, pkg_ref_cls: Type[PkgRef]) -> PkgRepoIndex:
    struct = read_toml(path)
    pkg_refs = [pkg_ref_cls(**kwargs) for kwargs in chain.from_iterable(struct.values())]
    return build_pkg_repo_index_from_pkg_refs(pkg_refs)
