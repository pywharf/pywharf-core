from dataclasses import dataclass
from typing import Optional, Tuple
import os.path

from flask import Flask, current_app, request, session, redirect
from flask_login import LoginManager, UserMixin, login_required, current_user
import fire

from private_pypi.pkg_repos import PkgRepoSecret, create_pkg_repo_secret
from private_pypi.workflow import (
        WorkflowStat,
        build_workflow_stat,
        workflow_api_simple,
        workflow_api_simple_distrib,
        workflow_api_redirect_package_download_url,
)
from private_pypi.web_page import LOGIN_HTML

app = Flask(__name__)  # pylint: disable=invalid-name
app.secret_key = 'MY_FRIEND_THIS_IS_NOT_SECURE'

login_manager = LoginManager()  # pylint: disable=invalid-name
login_manager.init_app(app)
login_manager.login_view = 'browser_login'


@dataclass
class MockUser(UserMixin):
    pkg_repo_name: str
    pkg_repo_secret_raw: str


SESSION_KEY_PKG_REPO_NAME = '_private_pypi_pkg_repo_name'
SESSION_KEY_PKG_REPO_SECRET_RAW = '_private_pypi_pkg_repo_secret_raw'


# https://github.com/maxcountryman/flask-login/blob/d4fa75305fdfb73bb55386d95bc09664bca8f902/flask_login/login_manager.py#L330-L331
@login_manager.request_loader
def load_user_from_request(_):
    if request.user_agent.browser is not None:
        # Is browser.
        pkg_repo_name = session.get(SESSION_KEY_PKG_REPO_NAME)
        pkg_repo_secret_raw = session.get(SESSION_KEY_PKG_REPO_SECRET_RAW)
        if not pkg_repo_name or not pkg_repo_secret_raw:
            return None
        return MockUser(pkg_repo_name=pkg_repo_name, pkg_repo_secret_raw=pkg_repo_secret_raw)

    else:
        # In CLI, always returns a mock user to defer authentication.
        if request.authorization is None:
            username = ''
            password = ''
        else:
            username = request.authorization['username']
            password = request.authorization['password']
        return MockUser(pkg_repo_name=username, pkg_repo_secret_raw=password)


@app.route("/browser_login/", methods=["GET", "POST"])
def browser_login():
    if request.method == 'GET':
        return LOGIN_HTML

    pkg_repo_name = request.form.get('pkg_repo_name')
    pkg_repo_secret_raw = request.form.get('pkg_repo_secret_raw')

    if not pkg_repo_name or not pkg_repo_secret_raw:
        return 'Repository name or secret is empty, please refresh this page and submit.', 401

    session[SESSION_KEY_PKG_REPO_NAME] = pkg_repo_name
    session[SESSION_KEY_PKG_REPO_SECRET_RAW] = pkg_repo_secret_raw

    return redirect(request.args.get("next") or '/simple/')


@app.route("/browser_logout/", methods=["GET"])
def browser_logout():
    session[SESSION_KEY_PKG_REPO_NAME] = None
    session[SESSION_KEY_PKG_REPO_SECRET_RAW] = None
    return redirect('/browser_login/')


def load_name_from_request() -> str:
    return current_user.pkg_repo_name.lower()


def load_secret_from_request(wstat: WorkflowStat) -> Tuple[Optional[PkgRepoSecret], str]:
    name = load_name_from_request()
    if not name:
        return None, 'Empty package pepository name.'

    pkg_repo_config = wstat.name_to_pkg_repo_config.get(name)
    if pkg_repo_config is None:
        return None, f'Package repository name "{name}" not exists.'

    if not current_user.pkg_repo_secret_raw:
        return None, f'Secret of the package repository "{name}" is empty.'

    pkg_repo_secret = create_pkg_repo_secret(
            type=pkg_repo_config.type,
            raw=current_user.pkg_repo_secret_raw,
    )
    return pkg_repo_secret, ''


@app.route('/simple/', methods=['GET'])
@login_required
def api_simple():
    pkg_repo_secret, err_msg = load_secret_from_request(current_app.workflow_stat)
    if pkg_repo_secret is None:
        return err_msg, 401

    name = load_name_from_request()
    body, status_code = workflow_api_simple(current_app.workflow_stat, name, pkg_repo_secret)
    return body, status_code


@app.route('/simple/<distrib>/', methods=['GET'])
@login_required
def api_simple_distrib(distrib):
    pkg_repo_secret, err_msg = load_secret_from_request(current_app.workflow_stat)
    if pkg_repo_secret is None:
        return err_msg, 401

    name = load_name_from_request()
    body, status_code = workflow_api_simple_distrib(
            current_app.workflow_stat,
            name,
            pkg_repo_secret,
            distrib,
    )
    return body, status_code


@app.route('/simple/<distrib>/<filename>', methods=['GET'])
@login_required
def api_redirect_package_download_url(distrib, filename):
    package, ext = os.path.splitext(filename)
    ext = ext.lstrip('.')
    if not ext:
        return 'Empty extension.', 404
    if len(ext) > len('tar.gz'):
        return f'Invalid entension "{ext}"', 404

    pkg_repo_secret, err_msg = load_secret_from_request(current_app.workflow_stat)
    if pkg_repo_secret is None:
        return err_msg, 401

    name = load_name_from_request()
    auth_url, err_msg, status_code = workflow_api_redirect_package_download_url(
            current_app.workflow_stat,
            name,
            pkg_repo_secret,
            distrib,
            package,
            ext,
    )
    if auth_url is None:
        return err_msg, status_code
    return redirect(auth_url)


@app.route('/simple/', methods=['POST'])
@login_required
def api_upload_package():
    pass


def run_server(
        config,
        index,
        config_secret=None,
        stat=None,
        upload=None,
        cache=None,
        host='localhost',
        port=8080,
        auth_read_expires=3600,
        auth_write_expires=300,
        cert=None,
        pkey=None,
):

    with app.app_context():
        # Init.
        current_app.workflow_stat = build_workflow_stat(
                pkg_repo_config_file=config,
                index_folder=index,
                stat_folder=stat,
                cache_folder=cache,
                upload_folder=upload,
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


run_server_cli = lambda: fire.Fire(run_server)  # pylint: disable=invalid-name
