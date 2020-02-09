from dataclasses import dataclass
from typing import List

from flask import Flask, current_app
from jinja2 import Template

from private_pypi.pkg_repos import PkgRef, PkgRepoIndex
from private_pypi.workflow import build_workflow_stat


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


app = Flask(__name__)  # pylint: disable=invalid-name


def run_server(
        pkg_repo_config,
        index,
        stat=None,
        upload=None,
        cache=None,
        host='localhost',
        port=80,
        auth_read_expires=3600,
        auth_write_expires=300,
        cert=None,
        pkey=None,
):

    with app.app_context():
        # Init.
        current_app.workflow_stat = build_workflow_stat(
                pkg_repo_config=pkg_repo_config,
                index_folder=index,
                stat_folder=stat,
                upload_folder=upload,
                cache_folder=cache,
                auth_read_expires=auth_read_expires,
                auth_write_expires=auth_write_expires,
        )

    ssl_context = None
    if cert and pkey:
        ssl_context = (cert, pkey)

    app.run(
            host=host,
            port=port,
            load_dotenv=False,
            # Must be threaded for the current design.
            threaded=True,
            # SSL.
            # https://werkzeug.palletsprojects.com/en/0.16.x/serving/#werkzeug.serving.run_simple
            # https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https,
            ssl_context=ssl_context,
    )
