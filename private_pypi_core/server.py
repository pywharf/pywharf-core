from dataclasses import dataclass
from os.path import join
from typing import Any, Optional, Tuple
import uuid
import logging

import fire
from flask import Flask, current_app, redirect, request, session, send_file
from flask_login import LoginManager, UserMixin, current_user, login_required
import waitress
from paste.translogger import TransLogger

from private_pypi_core.backend import PkgRepoSecret
from private_pypi_core.workflow import (
        WorkflowStat,
        initialize_workflow,
        workflow_api_redirect_package_download_url,
        workflow_api_simple,
        workflow_api_simple_distrib,
        workflow_api_upload_package,
        workflow_index_mtime,
)
from private_pypi_core.utils import get_secret_key, decrypt_local_file_ref, split_package_ext
from private_pypi_core.web import LOGIN_HTML

app = Flask(__name__)  # pylint: disable=invalid-name
app.secret_key = get_secret_key()

login_manager = LoginManager()  # pylint: disable=invalid-name
login_manager.init_app(app)
login_manager.login_view = 'login'


@dataclass
class MockUser(UserMixin):
    pkg_repo_name: str
    pkg_repo_secret_raw: str


SESSION_KEY_PKG_REPO_NAME = '_private_pypi_pkg_repo_name'
SESSION_KEY_PKG_REPO_SECRET_RAW = '_private_pypi_pkg_repo_secret_raw'


# https://github.com/maxcountryman/flask-login/blob/d4fa75305fdfb73bb55386d95bc09664bca8f902/flask_login/login_manager.py#L330-L331
@login_manager.request_loader
def load_user_from_request(_):
    # UA of pip and poetry:
    # https://github.com/pypa/pip/blob/7420629800b10d117d3af3b668dbe99b475fcbc0/src/pip/_internal/network/session.py#L99
    # https://github.com/python-poetry/poetry/blob/5050362f0b4c41d4637dcaa74eb2ba188bd858a9/get-poetry.py#L906
    if 'python' not in request.user_agent.string.lower():
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


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return LOGIN_HTML

    pkg_repo_name = request.form.get('pkg_repo_name')
    pkg_repo_secret_raw = request.form.get('pkg_repo_secret_raw')

    if not pkg_repo_name or not pkg_repo_secret_raw:
        return 'Repository name or secret is empty, please refresh this page and submit.', 401

    session[SESSION_KEY_PKG_REPO_NAME] = pkg_repo_name
    session[SESSION_KEY_PKG_REPO_SECRET_RAW] = pkg_repo_secret_raw

    return redirect(request.args.get('next') or '/simple/')


@app.route('/logout/', methods=['GET'])
def logout():
    session[SESSION_KEY_PKG_REPO_NAME] = None
    session[SESSION_KEY_PKG_REPO_SECRET_RAW] = None
    return redirect('/login/')


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

    pkg_repo_secret = wstat.backend_instance_manager.create_pkg_repo_secret(
            name=name,
            type=pkg_repo_config.type,
            raw=current_user.pkg_repo_secret_raw,
    )
    return pkg_repo_secret, ''


@app.route('/simple/', methods=['GET'])
@login_required
def pep503_api_simple():
    pkg_repo_secret, err_msg = load_secret_from_request(current_app.workflow_stat)
    if pkg_repo_secret is None:
        return err_msg, 401

    name = load_name_from_request()
    body, status_code = workflow_api_simple(current_app.workflow_stat, name, pkg_repo_secret)
    return body, status_code


@app.route('/simple/<distrib>/', methods=['GET'])
@login_required
def pep503_api_simple_distrib(distrib):
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

    if status_code == 404 and app.config['EXTRA_INDEX_URL'] != '/':
        # Redirect to extra index if not found.
        return redirect(app.config['EXTRA_INDEX_URL'] + f'{distrib}/')

    return body, status_code


@app.route('/simple/<distrib>/<filename>', methods=['GET'])
@login_required
def pep503_api_redirect_package_download_url(distrib, filename):
    package, ext = split_package_ext(filename)
    if not ext:
        return 'Extension not supported.', 404

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


@app.route('/local_file/<encrypted_ref>', methods=['GET'])
def local_file(encrypted_ref):
    passed, path, filename = decrypt_local_file_ref(encrypted_ref)
    if not passed:
        return 'Expired or invalid encrypted_ref.', 401

    rsp = send_file(path, as_attachment=True, attachment_filename=filename)
    rsp.direct_passthrough = False
    return rsp


# https://warehouse.pypa.io/api-reference/legacy/#upload-api
@app.route('/simple/', methods=['POST'])
@login_required
def legacy_api_upload_package():  # pylint: disable=too-many-return-statements
    cache_folder = current_app.workflow_stat.root_local_paths.cache

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


@app.route('/index_mtime/', methods=['GET'])
@login_required
def index_mtime():
    pkg_repo_secret, err_msg = load_secret_from_request(current_app.workflow_stat)
    if pkg_repo_secret is None:
        return err_msg, 401

    name = load_name_from_request()
    mtime, status_code = workflow_index_mtime(current_app.workflow_stat, name, pkg_repo_secret)
    return mtime, status_code, {'Content-Type': 'text/plain'}


def _load_file_content_for_initialization(key) -> Tuple[bool, str]:
    if key in request.form and key in request.files:
        return False, f'{key} in both form and files.'
    elif key not in request.form and key not in request.files:
        return False, f'{key} not in form and files.'

    if key in request.form:
        return True, request.form[key]
    else:
        return True, request.files[key].read()


@app.route('/initialize/', methods=['POST'])
def initialize():
    if 'multipart/form-data' not in request.content_type \
            and 'application/x-www-form-urlencoded' not in request.content_type:
        return 'content_type should be content-type=multipart/form-data or application/x-www-form-urlencoded.', 405

    passed, config_text = _load_file_content_for_initialization('config')
    if not passed:
        return config_text, 405

    passed, admin_secret_text = _load_file_content_for_initialization('admin_secret')
    if not passed:
        return admin_secret_text, 405

    pre_wstat = current_app.workflow_stat
    current_app.workflow_stat = initialize_workflow(
            root_folder=pre_wstat.root_folder,
            pkg_repo_config_file_or_text=config_text,
            admin_pkg_repo_secret_file_or_text=admin_secret_text,
            auth_read_expires=pre_wstat.auth_read_expires,
            auth_write_expires=pre_wstat.auth_write_expires,
            config_or_admin_secret_can_be_text=True,
            enable_task_worker_initialization=False,
    )
    return 'Done', 200


def run_server(
        root: str,
        config: Optional[str] = None,
        admin_secret: Optional[str] = None,
        config_or_admin_secret_can_be_text: bool = False,
        auth_read_expires: int = 3600,
        auth_write_expires: int = 300,
        extra_index_url: str = 'https://pypi.org/simple/',
        debug: bool = False,
        host: str = 'localhost',
        port: int = 8888,
        **waitress_options: Any,
):
    # Make sure EXTRA_INDEX_URL ends with slash.
    # NOTE: EXTRA_INDEX_URL will be set as '/' if --extra_index_url=''.
    app.config['EXTRA_INDEX_URL'] = extra_index_url.rstrip('/') + '/'

    with app.app_context():
        # Init.
        current_app.workflow_stat = initialize_workflow(
                root_folder=root,
                pkg_repo_config_file_or_text=config,
                admin_pkg_repo_secret_file_or_text=admin_secret,
                auth_read_expires=auth_read_expires,
                auth_write_expires=auth_write_expires,
                config_or_admin_secret_can_be_text=config_or_admin_secret_can_be_text,
                enable_task_worker_initialization=True,
        )
        server_logging_path = join(
                current_app.workflow_stat.root_local_paths.log,
                'private_pypi_server.log',
        )

    # Setup logging.
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('filelock').setLevel(logging.WARNING)
    logging.getLogger('apscheduler').setLevel(logging.WARNING)
    logging.getLogger().addHandler(logging.FileHandler(server_logging_path))

    if debug:
        if waitress_options:
            raise RuntimeError(
                    f'--waitress_options={waitress_options} should be empty in debug mode.')

        def print_request():
            print('==== REQUEST URL ====')
            print(request.url)
            print('==== REQUEST HEADERS ====')
            print(str(request.headers).strip())
            print()

        def print_response(response):
            print('==== RESPONSE HEADERS ====')
            print(str(response.headers).strip())
            print('==== RESPONSE DATA ====')
            print(response.get_data())
            print()
            return response

        app.before_request(print_request)
        app.after_request(print_response)

        app.run(
                host=host,
                port=port,
                load_dotenv=False,
                # Must be threaded for the current design.
                threaded=True,
        )

    else:
        print(f'waitress.serve host={host}, port={port}, waitress_options={waitress_options}')

        # https://docs.pylonsproject.org/projects/waitress/en/stable/logging.html
        trans_logger_wrapped_app = TransLogger(app, setup_console_handler=False)

        # https://docs.pylonsproject.org/projects/waitress/en/stable/arguments.html
        waitress.serve(
                trans_logger_wrapped_app,
                host=host,
                port=port,
                **waitress_options,
        )


run_server_cli = lambda: fire.Fire(run_server)  # pylint: disable=invalid-name
