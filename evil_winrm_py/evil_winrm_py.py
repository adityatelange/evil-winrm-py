#!/usr/bin/env python3

import argparse
import sys

import pypsrp
import pypsrp.client

from evil_winrm_py import __version__


def main():
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
        # Create a connection
        client = pypsrp.client.Client(
            server=args.ip,
            port=args.port,
            auth="ntlm",
            username=args.user,
            password=args.password,
            ssl=False,
            cert_validation=False,
        )
        # Execute a ps command
        stdout, stderr, rc = client.execute_ps("$pwd.Path")
        # Print the output
        print(stdout)
        print(stderr)
        print(rc)

    except Exception as e:
        print(e)
        sys.exit(1)
