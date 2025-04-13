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
def get_prompt(connection: pypsrp.client.Client):
    try:
        output, streams, had_errors = connection.execute_ps(
            "$pwd.Path"
        )  # Get current working directory
        if not had_errors:
            return f"PS {output}> "
    except Exception as e:
        log.error("Error in interactive shell loop: {}".format(e))
    return "PS ?> "  # Fallback prompt


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
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        help="Remote host IP or hostname",
    )
    parser.add_argument("-u", "--user", required=True, help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument(
        "--port", type=int, default=5985, help="Remote host port (default 5985)"
    )
    parser.add_argument(
        "--version", action="version", version=__version__, help="Show version"
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
