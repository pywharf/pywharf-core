# Private-PyPI: A private PyPI server powered by backend(s) like GitHub

## CLI

`private_pypi_run_server`:

```txt
Run the private-pypi server.

SYNOPSIS
    private_pypi_run_server CONFIG INDEX <flags>

POSITIONAL ARGUMENTS
    CONFIG (str):
        Path to the package repositories config.
    INDEX (str):
        Path to the index folder.
        The folder could be empty if --admin_secret is provided.

FLAGS
    --admin_secret (Optional[str]):
        Path to the admin secrets config with read/write permission.
        This field is required for local index synchronization.
        Defaults to None.
    --stat (Optional[str]):
        Path to the state folder.
        This field is required for the upload API.
        Defaults to None.
    --cache (Optional[str]):
        Path to the cache folder for file upload and download.
        This field is required for the upload API and local cache feature.
        Defaults to None.
    --auth_read_expires (int):
        The expiration time in seconds for read authentication.
        Defaults to 3600.
    --auth_write_expires (int):
        he expiration time in seconds for read authentication.
        Defaults to 300.
    --extra_index_url (str):
        Extra index url for redirection in case package not found.
        If set to empty string explicitly redirection will be suppressed.
        Defaults to 'https://pypi.org/simple/'.
    --debug (bool):
        Enable debug mode.
    --host (str):
        The interface to bind to.
        Defaults to 'localhost'.
    --port (int):
        The port to bind to.
        Defaults to 8080.
    **waitress_options (Dict[str, Any]):
        Optional arguments that `waitress.serve` takes.
        Details in https://docs.pylonsproject.org/projects/waitress/en/stable/arguments.html.
        Defaults to {}.
```
