# private-pypi-core

## CLI

`private_pypi_server`:

```txt
Run the private-pypi server.

SYNOPSIS
    private_pypi_server CONFIG ROOT <flags>

POSITIONAL ARGUMENTS
    CONFIG (str):
        Path to the package repositories config.
    ROOT (str):
        Path to the root folder.

FLAGS
    --admin_secret (Optional[str]):
        Path to the admin secrets config with read/write permission.
        This field is required for local index synchronization.
        Defaults to None.
    --auth_read_expires (int):
        The expiration time (in seconds) for read authentication.
        Defaults to 3600.
    --auth_write_expires (int):
        The expiration time (in seconds) for write authentication.
        Defaults to 300.
    --extra_index_url (str):
        Extra index url for redirection in case package not found.
        If set to empty string explicitly redirection will be suppressed.
        Defaults to 'https://pypi.org/simple/'.
    --debug (bool):
        Enable debug mode.
        Defaults to False.
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
