# Installation Guide

`evil-winrm-py` is available on:

- PyPI - https://pypi.org/project/evil-winrm-py/
- Github - https://github.com/adityatelange/evil-winrm-py
- Kali Linux - https://pkg.kali.org/pkg/evil-winrm-py
- Parrot OS - https://gitlab.com/parrotsec/packages/evil-winrm-py

## For Kali Linux and Parrot OS Users

If you are using Kali Linux or Parrot OS, you can install `evil-winrm-py` directly from the package manager:

```bash
sudo apt update
sudo apt install evil-winrm-py
```

---

## Installation of Kerberos Dependencies on Linux

```bash
sudo apt install gcc python3-dev libkrb5-dev krb5-pkinit
# Optional: krb5-user
```

> [!NOTE]
> `[kerberos]` is an optional dependency that includes the necessary packages for Kerberos authentication support. If you do not require Kerberos authentication, you can install `evil-winrm-py` without this extra.

## Using `pip`

You can install the package directly from PyPI using pip:

```bash
pip install evil-winrm-py[kerberos]
```

Installing latest development version directly from GitHub:

```bash
pip install 'evil-winrm-py[kerberos] @ git+https://github.com/adityatelange/evil-winrm-py'
```

## Using `pipx`

For a more isolated installation, you can use pipx:

```bash
pipx install evil-winrm-py[kerberos]
```

Installing latest development version directly from GitHub:

```bash
pipx install 'evil-winrm-py[kerberos] @ git+https://github.com/adityatelange/evil-winrm-py'
```

## Using `uv`

If you prefer using `uv`, you can install the package with the following command:

```bash
uv tool install evil-winrm-py[kerberos]
```

Installing latest development version directly from GitHub:

```bash
uv tool install git+https://github.com/adityatelange/evil-winrm-py[kerberos]
```
