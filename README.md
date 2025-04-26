# evil-winrm-py

Evil-WinRM-Py is a Python-based tool for Windows Remote Management (WinRM) that allows users to execute commands on remote Windows machines.

![](https://raw.githubusercontent.com/adityatelange/evil-winrm-py/refs/tags/v0.0.5/assets/terminal.png)

> [!NOTE]
> This tool is designed strictly for educational, ethical use, and authorized penetration testing. Always ensure you have explicit authorization before accessing any system. Unauthorized access or misuse of this tool is both illegal and unethical.

## Motivation

The original evil-winrm is written in Ruby, which can be a hurdle for some users. Rewriting it in Python makes it more accessible and easier to use, while also allowing us to leverage Python’s rich ecosystem for added features and flexibility.

I also wanted to learn more about winrm and its internals, so this project will also serve as a learning experience for me.

## Features

- Execute commands on remote Windows machines via an interactive shell.
- Enable logging and debugging for better traceability.
- Navigate command history using up/down arrow keys.
- Display colorized output for improved readability.
- Support for Pass-the-Hash authentication.
- Auto-complete remote file and directory paths.
- Lightweight and Python-based for ease of use.
- Keyboard Interrupt (Ctrl+C) support to terminate long-running commands gracefully.
- Support for SSL to secure communication with the remote host.

## Installation (Windows/Linux)

> You may use [pipx](https://pipx.pypa.io/stable/) instead of pip to install evil-winrm-py. `pipx` is a tool to install and run Python applications in isolated environments.

```bash
pip install evil-winrm-py
```

or if you want to install with latest commit from the main branch you can do so by cloning the repository and installing it with pipx:

```bash
git clone https://github.com/adityatelange/evil-winrm-py
cd evil-winrm-py
pip install .
```

### Update

```bash
pip upgrade evil-winrm-py
```

### Uninstall

```bash
pip uninstall evil-winrm-py
```

## Usage

```bash
usage: evil-winrm-py [-h] -i IP -u USER [-p PASSWORD] [-H HASH] [--ssl] [--port PORT] [--log] [--version]

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        remote host IP or hostname
  -u USER, --user USER  username
  -p PASSWORD, --password PASSWORD
                        password
  -H HASH, --hash HASH  nthash
  --ssl                 use ssl
  --port PORT           remote host port (default 5985)
  --log                 log session to file
  --version             show version
```

## Credits

- Original evil-winrm project - https://github.com/Hackplayers/evil-winrm
- PowerShell Remoting Protocol for Python - https://github.com/jborean93/pypsrp
- Prompt Toolkit - https://github.com/prompt-toolkit/python-prompt-toolkit
