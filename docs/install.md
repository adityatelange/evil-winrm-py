# Installation Guide

`evil-winrm-py` requires **Python 3.10 or higher** and is available on:

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

## Optional Extras

`evil-winrm-py` has two **optional extras**. Neither is required for the base tool (NTLM/Pass-the-Hash/Certificate authentication over WinRM), but many users want one or both:

| Extra        | Adds                                                |
| ------------ | --------------------------------------------------- |
| `[kerberos]` | Kerberos authentication support (`-k`/`--kerberos`) |
| `[mcp]`      | MCP server mode (`--mcp`)                           |

Install both together with `evil-winrm-py[kerberos,mcp]`.

### Installation of Kerberos Dependencies on Linux

The `[kerberos]` extra needs some system packages to build `gssapi`/`krb5` before it can be installed:

```bash
sudo apt install gcc python3-dev libkrb5-dev krb5-pkinit
# Optional: krb5-user
```

> [!NOTE]
> If you do not require Kerberos authentication, you can install `evil-winrm-py` without this extra and skip this step.

### MCP Server Support

The `[mcp]` extra enables MCP server mode (see [`--mcp`](usage.md#mcp-server-mode)). Install it like any other extra:

```bash
uv tool install evil-winrm-py[mcp]
```

If you do not need MCP server support, you can install `evil-winrm-py` without this extra.

## Using `uv` (recommended)

[`uv`](https://docs.astral.sh/uv/) is the recommended way to install `evil-winrm-py`. It installs Python applications into isolated environments (avoiding dependency conflicts with your system Python) and is significantly faster than pip/pipx.

Install `uv` itself if you don't already have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then install `evil-winrm-py`:

```bash
uv tool install evil-winrm-py
uv tool install evil-winrm-py[kerberos] # with Kerberos support
```

Installing latest development version directly from GitHub:

```bash
uv tool install git+https://github.com/adityatelange/evil-winrm-py
uv tool install 'git+https://github.com/adityatelange/evil-winrm-py[kerberos]'
```

Update:

```bash
uv tool upgrade evil-winrm-py
```

Uninstall:

```bash
uv tool uninstall evil-winrm-py
```

## Using `pipx`

For a more isolated installation without `uv`, you can use pipx:

```bash
pipx install evil-winrm-py
pipx install evil-winrm-py[kerberos] # with Kerberos support
```

Installing latest development version directly from GitHub:

```bash
pipx install 'evil-winrm-py[kerberos] @ git+https://github.com/adityatelange/evil-winrm-py'
```

Update:

```bash
pipx upgrade evil-winrm-py
```

Uninstall:

```bash
pipx uninstall evil-winrm-py
```

## Using `pip`

You can install the package directly from PyPI using pip:

```bash
pip install evil-winrm-py
pip install evil-winrm-py[kerberos] # with Kerberos support
```

Installing latest development version directly from GitHub:

```bash
pip install 'evil-winrm-py[kerberos] @ git+https://github.com/adityatelange/evil-winrm-py'
```

Update:

```bash
pip install --upgrade evil-winrm-py
```

Uninstall:

```bash
pip uninstall evil-winrm-py
```
