# Releasing a new version on PyPI

Read More: https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/

## Setup

```bash
python3 -m pip install --upgrade build
python3 -m pip install --upgrade twine
```

## Bump version

```bash
# File: evil_winrm_py/__init__.py
__version__ = "X.Y.Z" # update this to the new version
```

## Build

```bash
python3 -m build
```

# Sceenshot

Creating screenshots for the README using the [freeze](https://github.com/charmbracelet/freeze) tool.

```bash
freeze --execute "evil-winrm-py -h" -o assets/terminal.png --padding 5 --wrap 120 --border.radius 4
```

## Upload

```bash
python3 -m twine upload dist/evil_winrm_py-$VERSION*
# example: python3 -m twine upload dist/evil_winrm_py-0.0.2*
```
