#!/usr/bin/env python3

import argparse
import logging
import readline
import signal
import sys
from pathlib import Path

from pypsrp.complex_objects import PSInvocationState
from pypsrp.exceptions import AuthenticationError, WinRMTransportError
from pypsrp.powershell import DEFAULT_CONFIGURATION_NAME, PowerShell, RunspacePool
from pypsrp.wsman import WSMan, requests

from evil_winrm_py import __version__

# --- Constants ---
LOG_PATH = Path.cwd().joinpath("evil_winrm_py.log")
HISTORY_FILE = Path.home().joinpath(".evil_winrm_py_history")
HISTORY_LENGTH = 1000

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


def interactive_shell(
    wsman: WSMan, configuration_name: str = DEFAULT_CONFIGURATION_NAME
):
    """Runs the interactive pseudo-shell."""
    log.info("Starting interactive PowerShell session...")

    # Set up history file
    if not HISTORY_FILE.exists():
        Path(HISTORY_FILE).touch()
    readline.read_history_file(HISTORY_FILE)
    readline.set_history_length(HISTORY_LENGTH)

    MENU_COMMANDS = [
        "upload",
        "download",
        "menu",
        "clear",
        "exit",
    ]

    # Set up tab completion for menu commands
    def menu_completer(text, state):
        """Tab completion for commands."""
        options = [cmd for cmd in MENU_COMMANDS if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        else:
            return None

    readline.set_completer(menu_completer)
    readline.parse_and_bind("tab: complete")

    with wsman, RunspacePool(wsman, configuration_name=configuration_name) as r_pool:
        while True:
            try:
                prompt_text = get_prompt(r_pool)
                command = input(prompt_text)

                if not command:
                    continue

                command = command.strip()  # Remove leading/trailing whitespace
                command = command.strip('"').strip("'")  # Remove quotes
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
                print()
                break  # Exit on Ctrl+D
        # Save history to file
        readline.write_history_file(HISTORY_FILE)


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
    parser.add_argument(
        "--port", type=int, default=5985, help="remote host port (default 5985)"
    )
    parser.add_argument(
        "--version", action="version", version=__version__, help="show version"
    )

    args = parser.parse_args()

    # --- Ask for password if not provided ---
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
