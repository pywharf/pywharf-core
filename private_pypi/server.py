import atexit
from dataclasses import dataclass
import os
from os.path import isdir, join, splitext
from typing import Optional, Tuple
import uuid

import fire
from flask import Flask, current_app, redirect, request, session
from flask_login import LoginManager, UserMixin, current_user, login_required
import psutil

from private_pypi.pkg_repos import PkgRepoSecret, create_pkg_repo_secret
from private_pypi.web_ui import LOGIN_HTML
from private_pypi.workflow import (
        WorkflowStat,
        build_workflow_stat_and_run_daemon,
        workflow_api_redirect_package_download_url,
        workflow_api_simple,
        workflow_api_simple_distrib,
        workflow_api_upload_package,
)

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
            name=name,
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
    package, ext = splitext(filename)
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


# https://warehouse.pypa.io/api-reference/legacy/#upload-api
@app.route('/simple/', methods=['POST'])
@login_required
def api_upload_package():  # pylint: disable=too-many-return-statements
    cache_folder = current_app.workflow_stat.local_paths.cache
    if not cache_folder:
        return 'Cache folder --cache not set.', 405
    if not isdir(cache_folder):
        return f'Cache folder --cache={cache_folder} path invalid.', 405

    stat_folder = current_app.workflow_stat.local_paths.stat
    if not stat_folder:
        return 'State folder --stat not set.', 405
    if not isdir(stat_folder):
        return f'State folder --stat={stat_folder} path invalid.', 405

    pkg_repo_secret, err_msg = load_secret_from_request(current_app.workflow_stat)
    if pkg_repo_secret is None:
        return err_msg, 401

    name = load_name_from_request()

    if 'multipart/form-data' not in request.content_type:
        return 'Please post content-type=multipart/form-data.', 405
    if 'content' not in request.files:
        return 'File not found.', 405

    # Save to the cache folder.
    content_file = request.files['content']
    cache_path = join(cache_folder, f'upload-{str(uuid.uuid1())}')
    content_file.save(cache_path)

    # Build meta.
    meta = {str(key): str(val) for key, val in request.form.items()}

    # Upload file.
    body, status_code = workflow_api_upload_package(
            current_app.workflow_stat,
            name,
            pkg_repo_secret,
            content_file.filename,
            meta,
            cache_path,
    )
    return body, status_code


def stop_all_children_processes():
    procs = psutil.Process().children()
    for proc in procs:
        proc.terminate()

    _, alive = psutil.wait_procs(procs, timeout=10)
    for proc in alive:
        proc.kill()


def run_server(
        config: str,
        index: str,
        admin_secret: Optional[str] = None,
        stat: Optional[str] = None,
        cache: Optional[str] = None,
        host: str = 'localhost',
        port: int = 8888,
        auth_read_expires: int = 3600,
        auth_write_expires: int = 300,
        cert: Optional[str] = None,
        pkey: Optional[str] = None,
        debug: bool = False,
):
    """Run the private-pypi server.

    Args:
        config (str): \
Path to the package repositories config.
        index (str): \
Path to the index folder. \
The folder could be empty if --admin_secret is provided.
        admin_secret (Optional[str], optional): \
Path to the admin secrets config with read/write permission. \
This field is required for index synchronization on-the-fly. \
Defaults to None.
        stat (Optional[str], optional): \
Path to the state folder. \
This field is required for the upload API. \
Defaults to None.
        cache (Optional[str], optional): \
Path to the cache folder for the file upload and download. \
This field is required for the upload API and local cache feature. \
Defaults to None.
        host (str, optional): \
The interface to bind to. Defaults to 'localhost'.
        port (int, optional): \
The port to bind to. Defaults to 8080.
        auth_read_expires (int, optional): \
The expiration time in seconds for read authentication. \
Defaults to 3600.
        auth_write_expires (int, optional): \
The expiration time in seconds for read authentication. \
Defaults to 300.
        cert (Optional[str], optional): \
Specify a certificate file to use HTTPS. \
Defaults to None.
        pkey (Optional[str], optional): \
The key file to use when specifying a certificate. \
Defaults to None.
    """
    # All processes in the current process group will be terminated
    # with the lead process.
    os.setpgrp()
    atexit.register(stop_all_children_processes)

    with app.app_context():
        # Init.
        current_app.workflow_stat = build_workflow_stat_and_run_daemon(
                pkg_repo_config_file=config,
                admin_pkg_repo_secret_file=admin_secret,
                index_folder=index,
                stat_folder=stat,
                cache_folder=cache,
                auth_read_expires=auth_read_expires,
                auth_write_expires=auth_write_expires,
        )

    ssl_context = None
    if cert and pkey:
        ssl_context = (cert, pkey)

    if debug:

        def print_response(response):
            print(str(response.headers).strip())
            print(response.get_data())
            return response

        app.after_request(print_response)

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

    else:
        # https://docs.pylonsproject.org/projects/waitress/en/stable/arguments.html#arguments
        raise NotImplementedError('TODO: waitress.serve')


run_server_cli = lambda: fire.Fire(run_server)  # pylint: disable=invalid-name
