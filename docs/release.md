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

## Sceenshot

Creating screenshots for the README using the [freeze](https://github.com/charmbracelet/freeze) tool.

```bash
freeze --execute "evil-winrm-py -h" -o assets/terminal.png --padding 5 --border.radius 4 # --wrap 120
```

Update the screenshot tag in the README file.

```diff
# File: evil_winrm_py/README.md
-![](https://raw.githubusercontent.com/adityatelange/evil-winrm-py/refs/tags/v1.4.0/assets/terminal.png)
+![](https://raw.githubusercontent.com/adityatelange/evil-winrm-py/refs/tags/v1.4.1/assets/terminal.png)
```

## Build

```bash
python3 -m build
```

## Upload

```bash
python3 -m twine upload dist/evil_winrm_py-$VERSION*
# example: python3 -m twine upload dist/evil_winrm_py-0.0.2*
```
