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
import shutil
import signal
import sys
import tempfile
import time
from importlib import resources
from pathlib import Path

from prompt_toolkit import PromptSession, prompt
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import clear
from pypsrp.complex_objects import PSInvocationState
from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
from pypsrp.powershell import DEFAULT_CONFIGURATION_NAME, PowerShell, RunspacePool
from pypsrp.wsman import WSMan, requests
from spnego.exceptions import NoCredentialError, OperationNotAvailableError
from tqdm import tqdm

# check if kerberos is installed
try:
    from krb5._exceptions import Krb5Error

    is_kerb_available = True
except ImportError:
    is_kerb_available = False

    # If kerberos is not available, define a dummy exception
    class Krb5Error(Exception):
        pass


from evil_winrm_py import __version__

# --- Constants ---
LOG_PATH = Path.cwd().joinpath("evil_winrm_py.log")
HISTORY_FILE = Path.home().joinpath(".evil_winrm_py_history")
HISTORY_LENGTH = 1000
MENU_COMMANDS = [
    "upload",
    "download",
    "menu",
    "clear",
    "exit",
]

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


def run_ps(r_pool: RunspacePool, command: str) -> tuple[str, list, bool]:
    """Runs a PowerShell command and returns the output, streams, and error status."""
    log.info("Executing command: {}".format(command))
    ps = PowerShell(r_pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return "\n".join(ps.output), ps.streams, ps.had_errors


def get_prompt(r_pool: RunspacePool) -> str:
    """Returns the prompt string for the interactive shell."""
    output, streams, had_errors = run_ps(
        r_pool, "$pwd.Path"
    )  # Get current working directory
    if not had_errors:
        return f"{RED}evil-winrm-py{RESET} {YELLOW}{BOLD}PS{RESET} {output}> "
    return "PS ?> "  # Fallback prompt


def show_menu() -> None:
    """Displays the help menu for interactive commands."""
    print(BOLD + "\nMenu:" + RESET)
    commands = [
        # ("command", "description")
        ("upload <local_path> <remote_path>", "Upload a file"),
        ("download <remote_path> <local_path>", "Download a file"),
        ("menu", "Show this menu"),
        ("clear, cls", "Clear the screen"),
        ("exit", "Exit the shell"),
    ]

    for command, description in commands:
        print(f"{CYAN}[+] {command:<55} - {description}{RESET}")
    print("Note: Use absolute paths for upload/download for reliability.\n")


def get_directory_and_partial_name(text: str) -> tuple[str, str]:
    """
    Parses the input text to find the directory prefix and the partial name.
    """
    # Find the last unquoted slash or backslash
    last_sep_index = text.rfind("\\")
    if last_sep_index == -1:
        # No separator found, the whole text is the partial name in the current directory
        directory_prefix = ""
        partial_name = text
    else:
        split_at = last_sep_index + 1
        directory_prefix = text[:split_at]
        partial_name = text[split_at:]
    return directory_prefix, partial_name


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
        pwd, streams, had_errors = run_ps(
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
            for cmd_sugg in MENU_COMMANDS:
                yield Completion(cmd_sugg, start_position=0, display=cmd_sugg)
            return

        command_typed_part = tokens[0]

        # Case 1: Completing the command name itself
        # There's only one token and no trailing space.
        if len(tokens) == 1 and not text_before_cursor.endswith(" "):
            # User is typing the command, -> "downl"
            for cmd_sugg in MENU_COMMANDS:
                if cmd_sugg.startswith(command_typed_part):
                    yield Completion(
                        cmd_sugg,  # Full suggested command
                        start_position=-len(
                            command_typed_part
                        ),  # Replace the typed part
                        display=cmd_sugg,
                    )
            return

        # Case 2: Completing a path argument
        #   a) There are two tokens (command + start of argument) -> "download C:\Pr"
        #   b) There's one token & a trailing space (command + space), -> "download "

        path_typed_segment = ""  # What the user has typed for the current path argument
        if len(tokens) == 2:
            path_typed_segment = tokens[1]
        # If len(tokens) == 1 and text_before_cursor.endswith(" "),
        # path_typed_segment remains "" (correct for completing a new, empty argument).

        actual_command_name = command_typed_part.strip().lower()

        # Unquote the typed quotes
        path_for_query = path_typed_segment.strip('"')

        if actual_command_name == "cd":
            dirs_only = True

        directory_prefix, partial_name = get_directory_and_partial_name(path_for_query)

        remote_suggestions = get_remote_path_suggestions(
            self.r_pool, directory_prefix, partial_name, dirs_only
        )

        for sugg_path in remote_suggestions:
            # sugg_path is the clean suggested path string from PowerShell
            # "C:\Program Files" or "My Document.docx"

            # path_typed_segment is what the user typed for this path argument
            # "C:\Pr", or "My D", or "" (if completing after a space)

            # If the path doesn't start with a drive letter, prepend the directory_prefix
            if (
                not re.match(r"^[a-zA-Z]:", directory_prefix)
                and directory_prefix
                and directory_prefix.endswith("\\")
            ):
                sugg_path = f"{directory_prefix}{sugg_path}"

            text_to_insert_in_prompt = sugg_path

            if " " in sugg_path:  # If the suggestion itself contains a space
                # Enclose the entire suggested path in quotes
                text_to_insert_in_prompt = f'"{sugg_path}"'

            yield Completion(
                text_to_insert_in_prompt,  # The text to insert (possibly quoted)
                start_position=-len(
                    path_typed_segment
                ),  # Replace the segment typed by the user
                display=sugg_path,  # Show the clean (unquoted) path in the completion menu
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
    pattern = r'"([^"]+)"|(\S+)'
    matches = re.findall(pattern, command)
    return [m[0] or m[1] for m in matches if m[0] or m[1]]


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
                    # The first line contains metadata
                    metadata = json.loads(output[0])
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

                if i == 0:
                    chunk_type = 0  # First chunk, tells PS script to create file
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
                        return
                if ps.had_errors:
                    if ps.streams.error:
                        for error in ps.streams.error:
                            print(error)

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


def interactive_shell(
    wsman: WSMan, configuration_name: str = DEFAULT_CONFIGURATION_NAME
) -> None:
    """Runs the interactive pseudo-shell."""
    log.info("Starting interactive PowerShell session...")

    # Set up history file
    if not HISTORY_FILE.exists():
        Path(HISTORY_FILE).touch()
    prompt_history = FileHistory(HISTORY_FILE)
    prompt_session = PromptSession(history=prompt_history)

    with wsman, RunspacePool(wsman, configuration_name=configuration_name) as r_pool:
        completer = CommandPathCompleter(r_pool)

        while True:
            try:
                prompt_text = ANSI(get_prompt(r_pool))
                command = prompt_session.prompt(
                    prompt_text,
                    completer=completer,
                    complete_while_typing=False,
                )

                if not command:
                    continue

                command = command.strip()  # Remove leading/trailing whitespace
                command_lower = command.lower()

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
                            RED
                            + "[-] Usage: download <remote_path> <local_path>"
                            + RESET
                        )
                        continue
                    remote_path = command_parts[1]
                    local_path = command_parts[2]

                    remote_file, streams, had_errors = run_ps(
                        r_pool, f"(Resolve-Path -Path {remote_path}).Path"
                    )
                    if not remote_file:
                        print(
                            RED
                            + f"[-] Remote file {remote_path} does not exist."
                            + RESET
                        )
                        continue

                    file_name = remote_file.split("\\")[-1]

                    if Path(local_path).is_dir() or local_path.endswith(os.sep):
                        local_path = Path(local_path).resolve().joinpath(file_name)
                    else:
                        local_path = Path(local_path).resolve()

                    download_file(r_pool, remote_file, str(local_path))
                    continue
                elif command_lower.startswith("upload"):
                    command_parts = quoted_command_split(command)
                    if len(command_parts) < 3:
                        print(
                            RED + "[-] Usage: upload <local_path> <remote_path>" + RESET
                        )
                        continue
                    local_path = command_parts[1]
                    remote_path = command_parts[2]

                    if not Path(local_path).exists():
                        print(
                            RED + f"[-] Local file {local_path} does not exist." + RESET
                        )
                        continue

                    file_name = local_path.split("\\")[-1]

                    if not re.match(r"^[a-zA-Z]:", remote_path):
                        # If the path doesn't start with a drive letter, prepend the current directory
                        pwd, streams, had_errors = run_ps(r_pool, "$pwd.Path")
                        if remote_path == ".":
                            remote_path = f"{pwd}\\{file_name}"
                        else:
                            remote_path = f"{pwd}\\{remote_path}"

                    if remote_path.endswith("\\"):
                        remote_path = f"{remote_path}{file_name}"

                    upload_file(r_pool, str(Path(local_path).resolve()), remote_path)
                    continue
                else:
                    try:
                        ps = PowerShell(r_pool)
                        ps.add_cmdlet("Invoke-Expression").add_parameter(
                            "Command", command
                        )
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

                        if ps.had_errors:
                            if ps.streams.error:
                                for error in ps.streams.error:
                                    print(error)
                                    log.error("Error: {}".format(error))
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
        """        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v{}""".format(
            __version__
        )
    )
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        help="remote host IP or hostname",
    )
    parser.add_argument("-u", "--user", required=True, help="username")
    parser.add_argument("-p", "--password", help="password")
    parser.add_argument("-H", "--hash", help="nthash")
    parser.add_argument(
        "--no-pass", action="store_true", help="do not prompt for password"
    )
    if is_kerb_available:
        parser.add_argument(
            "-k", "--kerberos", action="store_true", help="use kerberos authentication"
        )
        parser.add_argument(
            "--spn-prefix",
            help="specify spn prefix",
        )
        parser.add_argument(
            "--spn-hostname",
            help="specify spn hostname",
        )
    parser.add_argument(
        "--priv-key-pem",
        help="local path to private key PEM file",
    )
    parser.add_argument(
        "--cert-pem",
        help="local path to certificate PEM file",
    )
    parser.add_argument("--uri", default="wsman", help="wsman URI (default: /wsman)")
    parser.add_argument("--ssl", action="store_true", help="use ssl")
    parser.add_argument(
        "--port", type=int, default=5985, help="remote host port (default 5985)"
    )
    parser.add_argument("--log", action="store_true", help="log session to file")
    parser.add_argument("--no-colors", action="store_true", help="disable colors")
    parser.add_argument(
        "--version", action="version", version=__version__, help="show version"
    )

    args = parser.parse_args()

    # Set Default values
    auth = "ntlm"  # this can be 'negotiate'
    encryption = "auto"

    # --- Run checks on provided arguments ---
    if args.no_colors:
        global RESET, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, BOLD
        RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = ""

    if is_kerb_available:
        if args.kerberos:
            auth = "kerberos"
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

    if args.no_pass:
        args.password = None
    elif not args.password:
        args.password = prompt("Password: ", is_password=True)
        if not args.password:
            args.password = None

    if args.uri:
        if args.uri.startswith("/"):
            args.uri = args.uri.lstrip("/")

    if args.ssl and (args.port == 5985):
        args.port = 5986

    if args.log:
        # Disable all loggers except the root logger
        for name in logging.root.manager.loggerDict:
            if not name.startswith("evil_winrm_py"):
                logging.getLogger(name).disabled = True
        # Set up logging to a file
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
            filename=LOG_PATH,
        )
        print(BLUE + "[*] Logging session to {}".format(LOG_PATH) + RESET)
    else:
        log.disabled = True

    # --- Initialize WinRM Session ---
    log.info("--- Evil-WinRM-Py v{} started ---".format(__version__))
    try:
        log.info("Connecting to {}:{} as {}".format(args.ip, args.port, args.user))
        print(
            BLUE
            + "[*] Connecting to {}:{} as {}".format(args.ip, args.port, args.user)
            + RESET
        )

        with WSMan(
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
        ) as wsman:
            interactive_shell(wsman)
    except WinRMTransportError as wte:
        print(RED + "[-] WinRM transport error: {}".format(wte) + RESET)
        log.error("WinRM transport error: {}".format(wte))
    except requests.exceptions.ConnectionError as ce:
        print(RED + "[-] Connection error: {}".format(ce) + RESET)
        log.error("Connection error: {}".format(ce))
    except AuthenticationError as ae:
        print(RED + "[-] Authentication failed: {}".format(ae) + RESET)
        log.error("Authentication failed: {}".format(ae))
    except WSManFaultError as wfe:
        print(RED + "[-] WSMan fault error: {}".format(wfe) + RESET)
        log.error("WSMan fault error: {}".format(wfe))
    except Krb5Error as ke:
        print(RED + "[-] Kerberos error: {}".format(ke) + RESET)
        log.error("Kerberos error: {}".format(ke))
    except (OperationNotAvailableError, NoCredentialError) as se:
        print(RED + "[-] SpnegoError error: {}".format(se) + RESET)
        log.error("SpnegoError error: {}".format(se))
    except Exception as e:
        print(e.__class__, e)
        log.exception("An unexpected error occurred: {}".format(e))
        sys.exit(1)
    finally:
        log.info("--- Evil-WinRM-Py v{} ended ---".format(__version__))
        sys.exit(0)
