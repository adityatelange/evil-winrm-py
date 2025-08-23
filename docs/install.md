# Installation Guide

`evil-winrm-py` is available on:

- PyPI - https://pypi.org/project/evil-winrm-py/
- Github - https://github.com/adityatelange/evil-winrm-py

### Installation of Kerberos Dependencies on Linux

```bash
sudo apt install gcc python3-dev libkrb5-dev krb5-pkinit
# Optional: krb5-user
```

## Using `pip`

You can install the package directly from PyPI using pip:

```bash
pip install evil-winrm-py
```

Installing latest development version directly from GitHub:

```bash
pip install git+https://github.com/adityatelange/evil-winrm-py[kerberos]
```

## Using `pipx`

For a more isolated installation, you can use pipx:

```bash
pipx install evil-winrm-py
```

Installing latest development version directly from GitHub:

```bash
pipx install git+https://github.com/adityatelange/evil-winrm-py[kerberos]
```

## Using `uv`

If you prefer using `uv`, you can install the package with the following command:

```bash
uv tool install evil-winrm-py
```

Installing latest development version directly from GitHub:

```bash
uv tool git+https://github.com/adityatelange/evil-winrm-py[kerberos]
```
