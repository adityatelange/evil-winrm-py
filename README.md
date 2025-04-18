# evil-winrm-py

Rewrite of popular tool evil-winrm in python

![](https://raw.githubusercontent.com/adityatelange/evil-winrm-py/refs/heads/main/assets/terminal.png)

## Motivation

The original evil-winrm is written in Ruby, which can be a hurdle for some users. Rewriting it in Python makes it more accessible and easier to use, while also allowing us to leverage Python’s rich ecosystem for added features and flexibility.

I also wanted to learn more about winrm and its internals, so this project will also serve as a learning experience for me.

## Installation (on Linux)

```bash
pipx install evil-winrm-py
```

or if you want to install with latest commit from the main branch you can do so by cloning the repository and installing it with pipx:

```bash
git clone https://github.com/adityatelange/evil-winrm-py
cd evil-winrm-py
pipx install .
```

## Features

- Run commands on remote Windows machines.
- Upload and download files.
- Interactive shell.

## Usage

```bash
usage: evil-winrm-py [-h] -i IP -u USER [-p PASSWORD] [--port PORT] [--version]

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        remote host IP or hostname
  -u USER, --user USER  username
  -p PASSWORD, --password PASSWORD
                        password
  --port PORT           remote host port (default 5985)
  --version             show version
```

## Credits

- Original evil-winrm project - https://github.com/Hackplayers/evil-winrm
- PowerShell Remoting Protocol for Python - https://github.com/jborean93/pypsrp
