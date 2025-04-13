#!/usr/bin/env python3

import argparse
import logging
import sys
from pathlib import Path

import pypsrp
import pypsrp.client

from evil_winrm_py import __version__

# --- Logging Setup ---
full_logging_path = Path.cwd().joinpath("evil_winrm_py.log")
log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    filename=full_logging_path,
)


# --- Helper Functions ---
def get_prompt(client: pypsrp.client.Client):
    try:
        output, streams, had_errors = client.execute_ps(
            "$pwd.Path"
        )  # Get current working directory
        if not had_errors:
            return f"PS {output}> "
    except Exception as e:
        log.error("Error in interactive shell loop: {}".format(e))
    return "PS ?> "  # Fallback prompt


def upload_file(client: pypsrp.client.Client, local_path: str, remote_path: str):
    """Uploads a file to the remote host."""
    print(local_path)
    if not Path(local_path).is_file():
        log.error("Local file not found: {}".format(local_path))
        return

    file_name = local_path.split("/")[-1]

    if remote_path == ".":
        remote_path = file_name

    log.info("Uploading '{}' to '{}'".format(local_path, remote_path))
    try:
        client.copy(src=local_path, dest=remote_path)
        log.info("Upload completed.")
    except Exception as e:
        log.error("Upload failed: {}".format(e))


def download_file(client: pypsrp.client.Client, remote_path: str, local_path: str):
    """Downloads a file from the remote host."""
    file_name = remote_path.split("\\")[-1]

    if local_path == ".":
        local_path = Path.cwd().joinpath(file_name)
    elif Path(local_path).is_dir():
        local_path = Path(local_path).joinpath(file_name)

    log.info("Downloading '{}' to '{}'".format(remote_path, local_path))
    try:
        client.fetch(src=remote_path, dest=local_path)
        log.info("Download completed.")
    except Exception as e:
        log.error("Download failed: {e}".format(e))


def show_menu():
    """Displays the help menu for interactive commands."""
    print("[+] upload /path/to/local/file C:\\path\\to\\remote\\file\t- Upload a file")
    print(
        "[+] download C:\\path\\to\\remote\\file /path/to/local/file\t- Download a file"
    )
    print("[+] menu\t\t\t\t\t\t- Show this menu")
    print("[+] exit\t\t\t\t\t\t- Exit the shell")
    print("Note: Use absolute paths for upload/download for reliability.\n")


def interactive_shell(client: pypsrp.client.Client):
    """Runs the interactive pseudo-shell."""
    log.info("Starting interactive PowerShell session...")
    while True:
        try:
            prompt_text = get_prompt(client)
            cmd_input = input(prompt_text).strip()  # Get user input

            if not cmd_input:
                continue

            # Check for exit command
            if cmd_input.lower() == "exit":
                break
            elif cmd_input.lower() == "menu":
                show_menu()
                continue
            elif cmd_input.lower().startswith("download"):
                parts = cmd_input.split(maxsplit=2)
                if len(parts) == 3:
                    remote_path = parts[1]
                    local_path = parts[2]
                    download_file(client, remote_path, local_path)
                else:
                    print(
                        "Usage: download C:\\path\\to\\remote\\file /path/to/local/file"
                    )
                continue  # Go to next cmd_input
            elif cmd_input.lower().startswith("upload"):
                parts = cmd_input.split(maxsplit=2)
                if len(parts) == 3:
                    local_path = parts[1]
                    remote_path = parts[2]
                    upload_file(client, local_path, remote_path)
                else:
                    print(
                        "Usage: upload /path/to/local/file C:\\path\\to\\remote\\file"
                    )
                continue  # Go to next cmd_input

            # Otherwise, execute the command
            output, streams, had_errors = client.execute_ps(cmd_input)
            if had_errors:
                print("ERROR: {}".format(output))
            else:
                print(output)
        except KeyboardInterrupt:
            print("\nCaught Ctrl+C. Type 'exit' to quit.")
            continue  # Allow user to continue or type exit
        except EOFError:
            print("\nEOF received, exiting.")
            break  # Exit on Ctrl+D
        except Exception as e:
            print(f"Error in interactive shell loop: {e}")
            # Decide whether to break or continue
            break


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

    # --- Initialize WinRM Session ---
    try:
        log.info("Connecting to {}:{} as {}".format(args.ip, args.port, args.user))
        # Create a client instance
        client = pypsrp.client.Client(
            server=args.ip,
            port=args.port,
            auth="ntlm",
            username=args.user,
            password=args.password,
            ssl=False,
            cert_validation=False,
        )

        # run the interactive shell
        interactive_shell(client)
    except Exception as e:
        log.exception("An unexpected error occurred: {}".format(e))
        sys.exit(1)
