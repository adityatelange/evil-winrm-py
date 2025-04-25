#!/usr/bin/env python3

import argparse
import logging
import re
import signal
import sys
from pathlib import Path

from prompt_toolkit import PromptSession, prompt
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from pypsrp.complex_objects import PSInvocationState
from pypsrp.exceptions import AuthenticationError, WinRMTransportError
from pypsrp.powershell import DEFAULT_CONFIGURATION_NAME, PowerShell, RunspacePool
from pypsrp.wsman import WSMan, requests

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
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    filename=LOG_PATH,
)


# --- Helper Functions ---
class DelayedKeyboardInterrupt:
    """Context manager to delay handling of KeyboardInterrupt."""

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


def run_ps(pool: RunspacePool, command: str) -> tuple:
    """Runs a PowerShell command and returns the output, streams, and error status."""
    log.info("Executing command: {}".format(command))
    ps = PowerShell(pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return "\n".join(ps.output), ps.streams, ps.had_errors


def get_prompt(pool: RunspacePool):
    output, streams, had_errors = run_ps(
        pool, "$pwd.Path"
    )  # Get current working directory
    if not had_errors:
        return f"{RED}evil-winrm-py{RESET} {YELLOW}{BOLD}PS{RESET} {output}> "
    return "PS ?> "  # Fallback prompt


def show_menu():
    """Displays the help menu for interactive commands."""
    print("[+] upload /path/to/local/file C:\\path\\to\\remote\\file\t- Upload a file")
    print(
        "[+] download C:\\path\\to\\remote\\file /path/to/local/file\t- Download a file"
    )
    print("[+] menu\t\t\t\t\t\t- Show this menu")
    print("[+] clear, cls\t\t\t\t\t\t- Clear the screen")
    print("[+] exit\t\t\t\t\t\t- Exit the shell")
    print("Note: Use absolute paths for upload/download for reliability.\n")


def get_directory_and_partial_name(text):
    """
    Parses the input text to find the directory prefix and the partial name.
    """
    if not re.match(r"^[a-zA-Z]:", text):
        directory_prefix = ""
        partial_name = text
    else:
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


class RemotePathCompleter(Completer):
    def __init__(self, r_pool: RunspacePool):
        self.r_pool = r_pool

    def get_completions(self, document: Document, complete_event):
        dirs_only = False
        word_to_complete = ""
        text_before_cursor = document.text_before_cursor
        tokens = text_before_cursor.split(maxsplit=1)

        if len(tokens) == 2:
            word_to_complete = tokens[1]
            directory_prefix, partial_name = get_directory_and_partial_name(
                word_to_complete
            )
            suggestions = get_remote_path_suggestions(
                self.r_pool, directory_prefix, partial_name
            )
        elif (len(tokens) == 1) and text_before_cursor.endswith(" "):
            # Check if the command is 'cd' to suggest directories only
            if tokens[0] == "cd":
                dirs_only = True
            directory_prefix, partial_name = get_directory_and_partial_name(
                word_to_complete
            )
            suggestions = get_remote_path_suggestions(
                self.r_pool, directory_prefix, partial_name, dirs_only
            )
        else:
            word_to_complete = text_before_cursor
            suggestions = MENU_COMMANDS

        # Yield completions from the suggestions
        for path in suggestions:
            if path.startswith(word_to_complete):
                text_to_insert = path[
                    len(word_to_complete) :
                ]  # Use original path for insertion
                text_to_insert = (
                    f'"{text_to_insert}"'
                    if text_to_insert.find(" ") != -1
                    else text_to_insert
                )

                yield Completion(
                    text_to_insert,
                    0,
                    display=path,
                )


def get_remote_path_suggestions(
    pool: RunspacePool,
    directory_prefix: str,
    partial_name: str,
    dirs_only: bool = False,
) -> list[str]:
    """Returns a list of suggested remote paths based on the partial path provided."""

    if not re.match(r"^[a-zA-Z]:", directory_prefix):
        # If the path doesn't start with a drive letter, prepend the current directory
        pwd, streams, had_errors = run_ps(
            pool, "$pwd.Path"
        )  # Get current working directory
        directory_prefix = f"{pwd}\\{directory_prefix}"
        exp = "Name"
    else:
        exp = "FullName"

    if dirs_only:
        attrs = "-Attributes Directory"
    else:
        attrs = ""

    command = f'Get-ChildItem -LiteralPath "{directory_prefix}" -Filter "{partial_name}*" {attrs} -Fo | select -Exp {exp}'
    ps = PowerShell(pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return ps.output


def interactive_shell(
    wsman: WSMan, configuration_name: str = DEFAULT_CONFIGURATION_NAME
):
    """Runs the interactive pseudo-shell."""
    log.info("Starting interactive PowerShell session...")

    # Set up history file
    if not HISTORY_FILE.exists():
        Path(HISTORY_FILE).touch()
    prompt_history = FileHistory(HISTORY_FILE)
    prompt_session = PromptSession(history=prompt_history)

    with wsman, RunspacePool(wsman, configuration_name=configuration_name) as r_pool:
        completer = RemotePathCompleter(r_pool)

        while True:
            try:
                prompt_text = ANSI(get_prompt(r_pool))
                command = prompt_session.prompt(
                    prompt_text,
                    completer=completer,
                    complete_while_typing=False,
                    auto_suggest=AutoSuggestFromHistory(),
                )

                if not command:
                    continue

                command = command.strip()  # Remove leading/trailing whitespace
                command_lower = command.lower()

                # Check for exit command
                if command_lower == "exit":
                    break
                elif command_lower in ["clear", "cls"]:
                    # Clear the screen
                    print("\033[H\033[J", end="")
                    continue
                elif command_lower == "menu":
                    show_menu()
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

                        if ps.had_errors:
                            if ps.streams.error:
                                for error in ps.streams.error:
                                    print(error)
                    except KeyboardInterrupt:
                        if ps.state == PSInvocationState.RUNNING:
                            ps.stop()
            except KeyboardInterrupt:
                print("\nCaught Ctrl+C. Type 'exit' or press Ctrl+D to exit.")
                continue  # Allow user to continue or type exit
            except EOFError:
                r_pool.close()
                print()
                break  # Exit on Ctrl+D


# --- Main Function ---
def main():
    log.info(
        "--- Evil-WinRM-Py v{} started ---".format(__version__)
    )  # Log the start of the program
    print(
        """        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v{}""".format(
            __version__
        )
    )  # Print the banner
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
        "--port", type=int, default=5985, help="remote host port (default 5985)"
    )
    parser.add_argument(
        "--version", action="version", version=__version__, help="show version"
    )

    args = parser.parse_args()

    # --- Ask for password if not provided ---
    if args.hash and args.password:
        print(RED + "[-] You cannot use both password and hash." + RESET)
        sys.exit(1)
    if args.hash:
        ntlm_hash_pattern = r"^[0-9a-fA-F]{32}$"
        if re.match(ntlm_hash_pattern, args.hash):
            args.password = "00000000000000000000000000000000:{}".format(args.hash)
        else:
            print(RED + "[-] Invalid NTLM hash format." + RESET)
    if not args.password:
        args.password = input("Password: ")

    # --- Initialize WinRM Session ---
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
            auth="ntlm",
            username=args.user,
            password=args.password,
            ssl=False,
            cert_validation=False,
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
    except Exception as e:
        print(e.__class__, e)
        log.exception("An unexpected error occurred: {}".format(e))
        sys.exit(1)
