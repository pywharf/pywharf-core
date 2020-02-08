from dataclasses import dataclass
from typing import List

from jinja2 import Template

from github_powered_pypi.pkg_repos import PkgRef
from github_powered_pypi.pkg_repo_index import PkgRepoIndex


@dataclass
class LinkItem:
    href: str
    text: str


# PEP 503 -- Simple Repository API
# https://www.python.org/dev/peps/pep-0503/
PAGE_TEMPLATE = Template('''<!DOCTYPE html>
<html>
<head><title>{{ title }}</title></head>
<body>
<h1>{{ title }}</h1>

{% for link_item in link_items %}
    <a href="{{ link_item.href }}">{{ link_item.text }}</a>
{% endfor %}

</body>
</html>
''')


def build_root_page(pkg_repo_index: PkgRepoIndex) -> str:
    link_items = [
            LinkItem(href=f'{distrib}/', text=distrib)
            for distrib in pkg_repo_index.all_distributions
    ]
    return PAGE_TEMPLATE.render(
            title='Links for all distributions',
            link_items=link_items,
    )


def build_distribution_page(distrib: str, pkg_refs: List[PkgRef]) -> str:
    link_items = []
    for pkg_ref in pkg_refs:
        link_items.append(
                LinkItem(
                        href=f'{pkg_ref.package}.{pkg_ref.ext}#sha256={pkg_ref.sha256}',
                        text=f'{pkg_ref.package}.{pkg_ref.ext}',
                ))
    return PAGE_TEMPLATE.render(
            title=f'Links for {distrib}',
            link_items=link_items,
    )
