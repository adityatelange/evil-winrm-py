#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This script is part of evil-winrm-py project https://github.com/adityatelange/evil-winrm-py
# It implements the MCP server for evil-winrm-py, allowing clients to connect and execute WinRM commands remotely.


import asyncio
from importlib.util import find_spec
from typing import Optional

is_mcp_available = find_spec("mcp") is not None

if not is_mcp_available:
    pass  # MCP is an optional dependency.

from mcp.server.fastmcp import FastMCP
from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
from pypsrp.powershell import PowerShell, RunspacePool
from requests.exceptions import ConnectionError
from spnego.exceptions import NoCredentialError, OperationNotAvailableError, SpnegoError

from evil_winrm_py.pypsrp_ewp.wsman import SUPPORTED_AUTHS, WSManEWP

# --- FastMCP server instance ---
mcp = FastMCP(
    "evil-winrm-py",
    instructions=(
        "WinRM remote shell MCP server over streamable-http only. "
        "Call winrm_login first to authenticate, then use winrm_execute to run commands. "
        "winrm_execute already runs the command via Invoke-Expression, "
        "and winrm_logout closes the session when finished."
    ),
)

__all__ = ["mcp", "winrm_mcp"]


# --- WinRM Session Management for MCP Tools ---
class _WinRMSession:
    def __init__(self):
        self.wsman = None
        self.r_pool = None

    def login(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 5985,
        ssl: bool = False,
        uri: str = "wsman",
        auth: str = "negotiate",
        encryption: str = "auto",
        ua: str = "Microsoft WinRM Client",
        spn_prefix: Optional[str] = None,
        spn_hostname: Optional[str] = None,
        priv_key_pem: Optional[str] = None,
        cert_pem: Optional[str] = None,
    ) -> str:
        if self.r_pool is not None:
            self.logout()
        self._validate_auth(auth)
        self._validate_port(port)
        self._validate_ssl(ssl)
        self._validate_encryption(encryption)
        try:
            self.wsman = WSManEWP(
                server=ip,
                port=port,
                auth=auth,
                encryption=encryption,
                username=username,
                password=password,
                ssl=ssl,
                cert_validation=False,
                path=uri,
                negotiate_service=spn_prefix,
                negotiate_hostname_override=spn_hostname,
                certificate_key_pem=priv_key_pem,
                certificate_pem=cert_pem,
                user_agent=ua,
            )
            self.wsman.__enter__()  # WSManEWP does not support context manager, but we call __enter__ to establish the connection and authenticate
            self.r_pool = RunspacePool(self.wsman)
            self.r_pool.__enter__()  # RunspacePool does not support context manager, but we call __enter__ to create the runspace
            return f"Connected to {ip}:{port} as {username}."
        except (
            TypeError,
            ValueError,
            AuthenticationError,
            WinRMTransportError,
            WSManFaultError,
            ConnectionError,
            NoCredentialError,
            OperationNotAvailableError,
            SpnegoError,
        ) as exc:
            self._cleanup()
            raise RuntimeError(str(exc)) from exc
        except Exception as exc:
            self._cleanup()
            raise RuntimeError("Unexpected login error: %s" % exc) from exc

    def execute(self, command: str) -> str:
        if self.r_pool is None:
            raise RuntimeError("Not logged in. Call winrm_login first.")
        ps = PowerShell(self.r_pool)
        ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
        ps.add_cmdlet("Out-String").add_parameter("Stream")
        ps.invoke()
        stdout = "\n".join(ps.output)
        if ps.had_errors and ps.streams.error:
            stderr = "\n".join(e._to_string for e in ps.streams.error)
            raise RuntimeError(f"{stdout}\nSTDERR:\n{stderr}".strip())
        return stdout

    def logout(self) -> str:
        self._cleanup()
        return "WinRM session closed."

    def _cleanup(self) -> None:
        if self.r_pool is not None:
            try:
                self.r_pool.__exit__(None, None, None)
            except Exception:
                pass
            self.r_pool = None
        if self.wsman is not None:
            try:
                self.wsman.__exit__(None, None, None)
            except Exception:
                pass
            self.wsman = None

    def _validate_auth(self, auth: str) -> None:
        if not isinstance(auth, str):
            raise TypeError("auth must be a string")
        if auth not in SUPPORTED_AUTHS:
            raise ValueError(
                "The specified auth '%s' is not supported. Use one of: %s"
                % (auth, ", ".join(SUPPORTED_AUTHS))
            )

    def _validate_port(self, port: int) -> None:
        if not isinstance(port, int):
            raise TypeError("port must be an integer")
        if port <= 0 or port > 65535:
            raise ValueError("port must be between 1 and 65535")

    def _validate_ssl(self, ssl: bool) -> None:
        if not isinstance(ssl, bool):
            raise TypeError("ssl must be a boolean")

    def _validate_encryption(self, encryption: str) -> None:
        if not isinstance(encryption, str):
            raise TypeError("encryption must be a string")
        if encryption not in ["auto", "always", "never"]:
            raise ValueError(
                "The specified encryption '%s' is not supported. Use one of: auto, always, never"
                % encryption
            )


_session = _WinRMSession()


# --- MCP Tools ---
@mcp.tool()
def winrm_login(
    ip: str,
    username: str,
    password: str,
    port: int = 5985,
    ssl: bool = False,
    uri: str = "wsman",
    auth: str = "ntlm",
    encryption: str = "auto",
    ua: str = "Microsoft WinRM Client",
    spn_prefix: Optional[str] = None,
    spn_hostname: Optional[str] = None,
    priv_key_pem: Optional[str] = None,
    cert_pem: Optional[str] = None,
) -> str:
    """Authenticate to a remote Windows host over WinRM."""
    return _session.login(
        ip=ip,
        username=username,
        password=password,
        port=port,
        ssl=ssl,
        uri=uri,
        auth=auth,
        encryption=encryption,
        ua=ua,
        spn_prefix=spn_prefix,
        spn_hostname=spn_hostname,
        priv_key_pem=priv_key_pem,
        cert_pem=cert_pem,
    )


@mcp.tool()
def winrm_execute(command: str) -> str:
    """Run a command on the authenticated WinRM target and return its output."""
    return _session.execute(command)


@mcp.tool()
def winrm_logout() -> str:
    """Close the current WinRM session."""
    return _session.logout()


# --- MCP Server Main Function ---
def winrm_mcp(cli_args=None) -> int:
    """
    Start the FastMCP server for evil-winrm-py. This is the main entry point for running the MCP server.
    Args:
        cli_args: Optional command-line arguments to configure the MCP server. If None, defaults will be used.
    Returns:
        int: Exit code (0 for success, non-zero for errors).
    """
    args = vars(cli_args) if cli_args is not None else {}

    transport = "streamable-http"
    host = args.get("mcp_host") or "127.0.0.1"
    port = args.get("mcp_port") or 8000

    # FastMCP uses internal settings for network bind values.
    mcp.settings.host = host
    mcp.settings.port = port

    print(f"[evil-winrm-py MCP] Listening on http://{host}:{port}/mcp")
    print("[evil-winrm-py MCP] Add this URL to your MCP client to connect.")

    try:
        mcp.run(transport=transport)
    except (asyncio.exceptions.CancelledError, KeyboardInterrupt):
        print("\n[evil-winrm-py MCP] Shutting down...")
    except Exception as exc:
        print(f"[evil-winrm-py MCP] Error: {exc}")
        return 1
    return 0
