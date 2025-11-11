#!/usr/bin/env python3

# Built-in imports
import argparse
import re
import socket
import sys

# External library imports
from loguru import logger
from prompt_toolkit import prompt

from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
from pypsrp.powershell import RunspacePool
from requests.exceptions import ConnectionError
from spnego.exceptions import NoCredentialError, OperationNotAvailableError, SpnegoError


# Local library imports
from evil_winrm_py import __version__
from evil_winrm_py.src.utils import banner, logbook
from evil_winrm_py.src.utils import kerberos
from evil_winrm_py.src.pypsrp_ewp.wsman import WSManEWP
from evil_winrm_py.src.terminal import interactive_shell


def check_port(host: str, port: int, timeout: float = 4.0) -> bool:
    """Check if a port is open on the target host."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return True
    except (socket.timeout, socket.error, OSError):
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evil-winrm-py",
        add_help=True,
        description="Execute commands interactively on remote Windows machines using the WinRM protocol",
        epilog="For more information about this project, visit https://github.com/adityatelange/evil-winrm-py"
        "\nFor user guide, visit https://github.com/adityatelange/evil-winrm-py/blob/main/docs/usage.md",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version and exit.",
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
    parser.add_argument("--ssl", action="store_true", help="Use ssl")

    if kerberos.IS_KERBEROS_AVAILABLE:
        kerberos_group = parser.add_argument_group(
            "Kerberos Options", "Options related to Kerberos authentication."
        )
        kerberos_group.add_argument(
            "-k", "--kerberos", action="store_true", help="Use kerberos authentication"
        )
        kerberos_group.add_argument(
            "--spn-prefix",
            help="specify SPN prefix (default: HTTP, common: WSMAN, CIFS, LDAP, HOST)",
        )
        kerberos_group.add_argument(
            "--spn-hostname",
            help="specify SPN hostname (default: resolved FQDN of target IP)",
        )

    parser.add_argument(
        "--no-pass", action="store_true", help="do not prompt for password"
    )

    parser.add_argument(
        "--history",
        action="store_true",
        help="enable persistent command history (saved per target/user)",
    )

    advanced_group = parser.add_argument_group(
        "Advanced Options", "Additional advanced or debugging options."
    )

    advanced_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (shortcut for --log-level DEBUG).",
    )

    advanced_group.add_argument(
        "--trace",
        action="store_true",
        help="Enable TRACE logging (shortcut for --log-level TRACE).",
    )

    advanced_group.add_argument(
        "--log-level",
        type=str,
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None,
        help="Set the logging level explicitly.",
    )

    advanced_group.add_argument(
        "--no-colors", action="store_true", help="disable colors"
    )

    return parser


# --- Main Function ---
def main() -> int:
    print(banner.display_banner())

    parser = build_parser()
    args = parser.parse_args()

    # Show help if no cli args provided
    if len(sys.argv) <= 1:
        parser.print_help()
        return 1

    # Determine log level: --log-level takes precedence, then --debug, then --trace, then default INFO
    if args.log_level:
        log_level = args.log_level
    elif args.debug:
        log_level = "DEBUG"
    elif args.trace:
        log_level = "TRACE"
    else:
        log_level = "INFO"

    logbook.setup_logging(level=log_level, no_colors=args.no_colors)

    # Set Default values
    auth = "ntlm"  # this can be 'negotiate'
    encryption = "auto"
    username = args.user

    # Pass no_colors flag to terminal module
    if args.no_colors:
        from evil_winrm_py.src import terminal

        terminal.disable_colors()

    # Validate Kerberos configuration if Kerberos auth is requested
    if kerberos.IS_KERBEROS_AVAILABLE and args.kerberos:
        if not kerberos.validate_kerberos_config():
            return 1

    # --- Run checks on provided arguments ---
    if args.cert_pem or args.priv_key_pem:
        auth = "certificate"
        encryption = "never"
        args.ssl = True
        args.no_pass = True
        if not args.cert_pem or not args.priv_key_pem:
            logger.error(
                "Both cert.pem and priv-key.pem must be provided for certificate authentication."
            )
            return 1

    if args.hash and args.password:
        logger.error("You cannot use both password and hash.")
        return 1

    if args.hash:
        ntlm_hash_pattern = r"^[0-9a-fA-F]{32}$"
        if re.match(ntlm_hash_pattern, args.hash):
            args.password = "00000000000000000000000000000000:{}".format(args.hash)
        else:
            logger.error("Invalid NTLM hash format.")
            return 1

    if args.uri:
        if args.uri.startswith("/"):
            args.uri = args.uri.lstrip("/")

    # Intelligent port handling
    if not args.ssl and args.port == 5985:
        # User didn't specify SSL, default port 5985 (HTTP)
        logger.info("Using default WinRM HTTP port 5985")
    elif args.ssl and args.port == 5985:
        # User specified SSL but left default port, switch to HTTPS port
        args.port = 5986
        logger.info("SSL enabled, switching to WinRM HTTPS port 5986")

    # Smart port detection: check if target port is open, suggest alternatives
    # Skip port check if --debug/--trace (useful for Kerberos debugging when firewall blocks WinRM)
    should_skip_port_check = args.debug or args.trace

    if should_skip_port_check:
        logger.debug(f"Skipping port check due to debug/trace mode")
    else:
        logger.debug(f"Checking if port {args.port} is open on {args.ip}...")
        if not check_port(args.ip, args.port, timeout=3.0):
            logger.warning(f"Port {args.port} appears closed on {args.ip}")

            # Suggest alternative port
            alternative_port = 5986 if args.port == 5985 else 5985
            alternative_ssl = not args.ssl

            logger.debug(f"Checking alternative port {alternative_port}...")
            if check_port(args.ip, alternative_port, timeout=3.0):
                logger.success(f"Port {alternative_port} is open!")
                logger.info(
                    f"Hint: Try adding {'--ssl' if alternative_ssl else 'removing --ssl'} to use port {alternative_port}"
                )
            else:
                logger.warning(f"Port {alternative_port} is also closed")
                logger.warning("Both WinRM ports (5985, 5986) appear closed")

            return 1
        else:
            logger.debug(f"Port {args.port} is open on {args.ip}")

    try:
        if kerberos.IS_KERBEROS_AVAILABLE:
            if args.kerberos:
                auth = "kerberos"
                args.spn_prefix = (
                    args.spn_prefix or "HTTP"
                )  # can also be CIFS, LDAP, HOST, WSMAN

                # Normalize SPN prefix to uppercase (Kerberos convention)
                args.spn_prefix = args.spn_prefix.upper()

                # Resolve FQDN for SPN if not explicitly provided
                if args.spn_hostname:
                    spn_hostname = args.spn_hostname
                else:
                    try:
                        # Try to get FQDN from IP address
                        fqdn = socket.getfqdn(args.ip)
                        # Verify it's not just the IP back (failed reverse DNS)
                        if fqdn != args.ip:
                            spn_hostname = fqdn
                            logger.debug(f"Resolved FQDN: {fqdn}")
                        else:
                            logger.debug(
                                f"Could not resolve FQDN for {args.ip}, using IP"
                            )
                            spn_hostname = args.ip
                    except Exception as e:
                        logger.debug(f"FQDN resolution failed: {e}, using IP")
                        spn_hostname = args.ip

                # Construct and log the SPN being used
                spn_full = f"{args.spn_prefix}/{spn_hostname}"
                logger.info(f"Kerberos SPN: {spn_full}")

                if not args.user:
                    # Get username from credentials (already validated above)
                    username = kerberos.get_kerberos_username()
                    if not username:
                        logger.error("Failed to get Kerberos username")
                        return 1
                # User needs to set environment variables `KRB5CCNAME` and `KRB5_CONFIG` as per requirements
                # example: export KRB5CCNAME=/tmp/krb5cc_1000
                # example: export KRB5_CONFIG=/etc/krb5.conf
            elif args.spn_prefix or args.spn_hostname:
                args.spn_prefix = args.spn_hostname = None  # Reset to None
                logger.warning(
                    "SPN prefix/hostname is only used with Kerberos authentication."
                )
        else:
            args.spn_prefix = args.spn_hostname = None

        # Kerberos authentication doesn't use passwords - automatically set no_pass
        if kerberos.IS_KERBEROS_AVAILABLE and args.kerberos:
            args.no_pass = True
            # Update spn_hostname with the resolved FQDN for WSManEWP
            args.spn_hostname = spn_hostname

        if args.no_pass:
            args.password = None
        elif args.user and not args.password:
            args.password = prompt("Password: ", is_password=True)
            if not args.password:
                args.password = None

        if username:
            logger.info(
                f"Connecting to '{args.ip}:{args.port}' as '{username}' (auth: {auth})"
            )
        else:
            logger.info(f"Connecting to '{args.ip}:{args.port}'")

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
                interactive_shell(
                    r_pool,
                    target_ip=args.ip,
                    username=username,
                    history=args.history,
                )
        return 0
    except (KeyboardInterrupt, EOFError):
        logger.info("Session interrupted by user.")
        return 0
    except WinRMTransportError as wte:
        logger.error(f"WinRM transport error: {wte}")
        return 1
    except ConnectionError as ce:
        logger.error(f"Failed to connect to the remote host: {args.ip}:{args.port}")
        logger.debug(f"Connection error details: {ce}")
        return 1
    except AuthenticationError as ae:
        logger.error(f"Authentication failed: {ae}")
        return 1
    except WSManFaultError as wfe:
        logger.error(f"WSMan fault error: {wfe}")
        return 1
    except kerberos.Krb5Error as ke:
        logger.error(f"Kerberos error: {ke}")
        return 1
    except (OperationNotAvailableError, NoCredentialError) as se:
        logger.error(f"SPNEGO error: {se._context_message}")
        logger.error(f"Details: {se._BASE_MESSAGE}")
        return 1
    except SpnegoError as se:
        logger.error(f"SPNEGO error: {se._context_message}")
        logger.error(f"Message: {se.message}")
        return 1
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        return 1
