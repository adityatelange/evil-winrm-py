#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This script is part of evil-winrm-py project https://github.com/adityatelange/evil-winrm-py
# It implements the MCP server for evil-winrm-py, allowing clients to connect and execute WinRM commands remotely.


import asyncio
from typing import Optional

from mcp.server.mcpserver import MCPServer
from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError
from pypsrp.powershell import PowerShell, RunspacePool
from requests.exceptions import ConnectionError
from spnego.exceptions import NoCredentialError, OperationNotAvailableError, SpnegoError

from evil_winrm_py.pypsrp_ewp.wsman import SUPPORTED_AUTHS, WSManEWP

# --- MCPServer instance ---
mcp = MCPServer(
    "evil-winrm-py",
    instructions=(
        "WinRM remote shell MCP server over streamable-http only. "
        "Call winrm_login first to authenticate; it returns a session_id. "
        "Use winrm_execute to run commands (via Invoke-Expression) and "
        "winrm_logout to close a session when finished. "
        "session_id is optional while only one session is active; pass it "
        "explicitly once multiple sessions exist (see list_sessions)."
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
    ) -> bool:
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
            return True
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
        try:
            ps.invoke()
        except (WinRMTransportError, WSManFaultError, ConnectionError) as exc:
            self._cleanup()
            raise RuntimeError(str(exc)) from exc
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


# Registry of active WinRM sessions keyed by an incrementing session id.
_sessions: dict[int, _WinRMSession] = {}
_next_session_id = 1


def _resolve_session(session_id: Optional[int]) -> tuple[int, _WinRMSession]:
    """Resolve the session to act on.

    When ``session_id`` is omitted and exactly one session is active, that
    session is used. When multiple sessions are active an explicit id is
    required.
    """
    active = {sid: s for sid, s in _sessions.items() if s.r_pool is not None}
    if not active:
        raise RuntimeError("No active WinRM session. Call winrm_login first.")
    if session_id is None:
        if len(active) == 1:
            return next(iter(active.items()))
        raise RuntimeError(
            "Multiple sessions are active (%s). Pass session_id to choose one."
            % ", ".join(str(sid) for sid in active)
        )
    if session_id not in active:
        raise RuntimeError(
            "No active session with id %s. Active sessions: %s"
            % (session_id, ", ".join(str(sid) for sid in active) or "none")
        )
    return session_id, active[session_id]


# --- MCP Tools ---
@mcp.tool(annotations={"openWorldHint": True})
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
    """Authenticate to a remote Windows host over WinRM.

    Returns the session_id to pass to winrm_execute and winrm_logout.
    """
    global _next_session_id
    session = _WinRMSession()
    session.login(
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
    session_id = _next_session_id
    _next_session_id += 1
    _sessions[session_id] = session
    return f"Connected to {ip}:{port} as {username}. session_id={session_id}"


@mcp.tool(annotations={"openWorldHint": True, "readOnlyHint": True})
def list_sessions() -> str:
    """List all active WinRM sessions and their session_id."""
    lines = []
    for sid, session in _sessions.items():
        if session.r_pool is not None:
            t = session.wsman.transport
            lines.append(
                f"Session {sid}: connected to {t.server}:{t.port} as {t.username}"
            )
    if not lines:
        return "No active sessions."
    return "\n".join(lines)


@mcp.tool(annotations={"openWorldHint": True, "destructiveHint": True})
def winrm_execute(command: str, session_id: Optional[int] = None) -> str:
    """Run a command on an authenticated WinRM target and return its output.

    session_id is optional when only one session is active.
    """
    _, session = _resolve_session(session_id)
    return session.execute(command)


@mcp.tool(annotations={"openWorldHint": True})
def winrm_logout(session_id: Optional[int] = None) -> str:
    """Close a WinRM session.

    session_id is optional when only one session is active.
    """
    sid, session = _resolve_session(session_id)
    session.logout()
    _sessions.pop(sid, None)
    return f"WinRM session {sid} closed."


# --- MCP Server Main Function ---
def winrm_mcp(cli_args=None) -> int:
    """
    Start the MCP server for evil-winrm-py. This is the main entry point for running the MCP server.
    Args:
        cli_args: Optional command-line arguments to configure the MCP server. If None, defaults will be used.
    Returns:
        int: Exit code (0 for success, non-zero for errors).
    """
    args = vars(cli_args) if cli_args is not None else {}

    transport = "streamable-http"
    host = args.get("mcp_host") or "127.0.0.1"
    port = args.get("mcp_port") or 8000

    print(f"[evil-winrm-py MCP] Listening on http://{host}:{port}/mcp")
    print("[evil-winrm-py MCP] Add this URL to your MCP client to connect.")

    try:
        mcp.run(transport=transport, host=host, port=port)
    except (asyncio.exceptions.CancelledError, KeyboardInterrupt):
        print("\n[evil-winrm-py MCP] Shutting down...")
    except Exception as exc:
        print(f"[evil-winrm-py MCP] Error: {exc}")
        return 1
    return 0
