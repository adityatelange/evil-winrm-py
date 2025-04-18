#!/usr/bin/env python3

import argparse
import logging
import readline
import sys
from pathlib import Path

from pypsrp.powershell import DEFAULT_CONFIGURATION_NAME, PowerShell, RunspacePool
from pypsrp.wsman import WSMan

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
def run_ps(pool: RunspacePool, command: str) -> tuple:
    """Runs a PowerShell command and returns the output, streams, and error status."""
    ps = PowerShell(pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return "\n".join(ps.output), ps.streams, ps.had_errors


def get_prompt(pool: RunspacePool):
    try:
        output, streams, had_errors = run_ps(
            pool, "$pwd.Path"
        )  # Get current working directory
        if not had_errors:
            return f"{RED}evil-winrm-py{RESET} {YELLOW}{BOLD}PS{RESET} {output}> "
    except Exception as e:
        log.error("Error in interactive shell loop: {}".format(e))
    return "PS ?> "  # Fallback prompt


def show_menu():
    """Displays the help menu for interactive commands."""
    print("[+] upload /path/to/local/file C:\\path\\to\\remote\\file\t- Upload a file")
    print(
        "[+] download C:\\path\\to\\remote\\file /path/to/local/file\t- Download a file"
    )
    print("[+] menu\t\t\t\t\t\t- Show this menu")
    print("[+] clear / cls\t\t\t\t\t- Clear the screen")
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

    # Set up tab completion
    readline.parse_and_bind("tab: complete")

    with RunspacePool(wsman, configuration_name=configuration_name) as r_pool:
        while True:
            try:
                prompt_text = get_prompt(r_pool)
                cmd_input = input(prompt_text).strip()  # Get user input

                if not cmd_input:
                    continue

                # Check for exit command
                if cmd_input.lower() == "exit":
                    break
                elif cmd_input.lower() in ["clear", "cls"]:
                    # Clear the screen
                    print("\033[H\033[J", end="")
                    continue
                elif cmd_input.lower() == "menu":
                    show_menu()
                    continue

                # Otherwise, execute the command
                log.info("Executing command: {}".format(cmd_input))
                output, streams, had_errors = run_ps(r_pool, cmd_input)
                if had_errors:
                    if streams.error:
                        for error in streams.error:
                            print(error)
                    # Uncomment the following lines to display different stream types
                    # if streams.warning:
                    #     for warn in streams.warning:
                    #         print("Warning: {}".format(warn))
                    # if streams.verbose:
                    #     for verb in streams.verbose:
                    #         print("Verbose: {}".format(verb))
                    # if streams.debug:
                    #     for deb in streams.debug:
                    #         print("Debug: {}".format(deb))
                    # if streams.progress:
                    #     for prog in streams.progress:
                    #         print("Progress: {}".format(prog))
                    # if streams.information:
                    #     for info in streams.information:
                    #         print("Information: {}".format(info))
                elif output:
                    print(output)
            except KeyboardInterrupt:
                print("\nCaught Ctrl+C. Type 'exit' or press Ctrl+D to exit.")
                continue  # Allow user to continue or type exit
            except EOFError:
                break  # Exit on Ctrl+D
            except Exception as e:
                print(f"Error in interactive shell loop: {e}")
                # Decide whether to break or continue
                break
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
    except Exception as e:
        log.exception("An unexpected error occurred: {}".format(e))
        sys.exit(1)
