TODO

Tmp:

```
yapf -i -r --style='{based_on_style: google, continuation_indent_width: 8, dedent_closing_brackets: false, column_limit: 100}' private_pypi
pylint private_pypi

# type check: pyright

python dev/build_console_scripts.py ./pyproject.toml /Users/huntzhan/.pyenv/versions/private-pypi/bin
```
