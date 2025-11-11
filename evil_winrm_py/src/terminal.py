# Built-in imports
import re
import os
from pathlib import Path

# External library imports
from loguru import logger

from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.complex_objects import PSInvocationState

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.auto_suggest import ThreadedAutoSuggest, AutoSuggestFromHistory
from prompt_toolkit.history import ThreadedHistory, InMemoryHistory, FileHistory
from prompt_toolkit.cursor_shapes import CursorShape
from prompt_toolkit.shortcuts import clear

from prompt_toolkit.styles import style_from_pygments_cls
from prompt_toolkit.lexers import PygmentsLexer

from pygments.lexers.shell import PowerShellLexer
from pygments.styles.monokai import MonokaiStyle

# Local library imports
from evil_winrm_py.src import commands
from evil_winrm_py.src.utils import completers

POWERSHELL_STYLE = style_from_pygments_cls(MonokaiStyle)

# --- Constants ---
HISTORY_FILE = Path.home().joinpath(".evil_winrm_py_history")
HISTORY_LENGTH = 1000
MENU_COMMANDS = {
    "upload": {
        "syntax": "upload <local_path> <remote_path>",
        "info": "Upload a file",
    },
    "download": {
        "syntax": "download <remote_path> <local_path>",
        "info": "Download a file",
    },
    "loadps": {
        "syntax": "loadps <local_path>.ps1",
        "info": "Load PowerShell functions from a local script",
    },
    "runps": {
        "syntax": "runps <local_path>.ps1",
        "info": "Run a local PowerShell script on the remote host",
    },
    "loaddll": {
        "syntax": "loaddll <local_path>.dll",
        "info": "Load a local DLL (in-memory) as a module on the remote host",
    },
    "runexe": {
        "syntax": "runexe <local_path>.exe [args]",
        "info": "Upload and execute (in-memory) a local EXE on the remote host",
    },
    "menu": {
        "syntax": "menu",
        "info": "Show this menu",
    },
    "clear": {
        "syntax": "clear, cls",
        "info": "Clear the screen",
    },
    "exit": {
        "syntax": "exit",
        "info": "Exit the shell",
    },
}
COMMAND_SUGGESTIONS = []

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


def disable_colors():
    """Disable all color codes by setting them to empty strings."""
    global RESET, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, BOLD
    RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = ""


# --- Helper Functions ---


def run_ps_cmd(r_pool: RunspacePool, command: str) -> tuple[str, list, bool]:
    """Runs a PowerShell command and returns the output, streams, and error status."""
    logger.debug("Executing command: {}".format(command))
    ps = PowerShell(r_pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return "\n".join(ps.output), ps.streams, ps.had_errors


def show_menu() -> None:
    """Displays the help menu for interactive commands."""
    print("Menu:")
    for command in MENU_COMMANDS.values():
        print(f"  {command['syntax']:<55} - {command['info']}")
    print("Note: Use absolute paths for upload/download for reliability.")


def get_prompt(r_pool: RunspacePool) -> str:
    """Returns the prompt string for the interactive shell."""
    output, streams, had_errors = run_ps_cmd(
        r_pool, "$pwd.Path"
    )  # Get current working directory
    if not had_errors:
        return f"{RED}evil-winrm-py{RESET} {YELLOW}{BOLD}PS{RESET} {output}> "
    return "PS ?> "  # Fallback prompt


def interactive_shell(
    r_pool: RunspacePool,
    target_ip: str = None,
    username: str = None,
    history: bool = False,
) -> None:
    """Runs the interactive pseudo-shell.

    Args:
        r_pool: The RunspacePool for executing PowerShell commands
        target_ip: Target hostname/IP for history file naming
        username: Username for history file naming
        history: Enable persistent history (default: False, in-memory only)
    """

    if history:
        # Create history directory in user's home (persistent across reboots)
        history_dir = Path.home() / ".evil_winrm_py"
        history_dir.mkdir(exist_ok=True)

        # Create unique history file using target and username
        if target_ip and username:
            # Sanitize filename (replace invalid chars with underscore)
            safe_target = re.sub(r"[^\w\-.]", "_", target_ip)
            safe_username = re.sub(r"[^\w\-.]", "_", username)
            history_filename = f"{safe_target}_{safe_username}_history"
        elif target_ip:
            safe_target = re.sub(r"[^\w\-.]", "_", target_ip)
            history_filename = f"{safe_target}_history"
        else:
            history_filename = "default_history"

        history_file = history_dir / history_filename
        history_file.touch(exist_ok=True)

        # Set permissions to 0600 (rw-------)
        try:
            os.chmod(history_file, 0o600)
            logger.debug(f"History file: {history_file}")
        except PermissionError as e:
            logger.warning(f"Could not set secure permissions on history file: {e}")

        history_backend = ThreadedHistory(FileHistory(str(history_file)))
        logger.info("💾 Persistent command history enabled.")
    else:
        logger.debug("🗑️ In-memory command history enabled.")
        history_backend = ThreadedHistory(InMemoryHistory())  # in-memory history

    prompt_session = PromptSession(
        cursor=CursorShape.BLINKING_BEAM,
        enable_history_search=True,
        auto_suggest=ThreadedAutoSuggest(auto_suggest=AutoSuggestFromHistory()),
        history=history_backend,
        completer=completers.CommandPathCompleter(
            r_pool, MENU_COMMANDS, COMMAND_SUGGESTIONS
        ),
        lexer=PygmentsLexer(PowerShellLexer),
        style=POWERSHELL_STYLE,
    )

    logger.info("Entering fake shell. Type 'menu' to see available commands.")

    while True:
        try:
            user_input = prompt_session.prompt(
                ANSI(get_prompt(r_pool)),
                complete_while_typing=False,
            )

            if not user_input:
                continue
        except EOFError:
            # Control-D pressed - normal exit
            return 0
        except KeyboardInterrupt:
            # Control-C pressed - check if buffer has text first
            if prompt_session.app.current_buffer.text:
                continue

            return 130  # SIGINT exit code

        else:
            # Normalize command input
            command = str(user_input).strip()
            command_lower = command.lower()

            # Check for exit command
            if command_lower == "exit":
                logger.info("Exiting interactive shell.")
                return

            if command_lower in ["clear", "cls"]:
                logger.info("Clearing the screen.")
                clear()  # Clear the screen
                continue

            if command_lower == "menu":
                logger.info("Displaying menu.")
                show_menu()
                continue

            command_parts = completers.quoted_command_split(command)

            if command_lower.startswith("download"):

                if len(command_parts) < 3:
                    logger.error("Usage: download <remote_path> <local_path>")
                    continue

                remote_path = command_parts[1].strip('"')
                local_path = command_parts[2].strip('"').strip("'")

                remote_file, streams, had_errors = run_ps_cmd(
                    r_pool, f"(Resolve-Path -Path '{remote_path}').Path"
                )
                if not remote_file:
                    logger.error(
                        f"Remote file '{remote_path}' does not exist or you do not have permission to access it."
                    )
                    continue

                file_name = remote_file.split("\\")[-1]

                if Path(local_path).expanduser().is_dir() or local_path.endswith(
                    os.sep
                ):
                    local_path = (
                        Path(local_path).expanduser().resolve().joinpath(file_name)
                    )
                else:
                    local_path = Path(local_path).expanduser().resolve()

                commands.download_file(r_pool, remote_file, str(local_path))
                continue

            if command_lower.startswith("upload"):
                if len(command_parts) < 3:
                    logger.error("Usage: upload <local_path> <remote_path>")
                    continue
                local_path = command_parts[1].strip('"').strip("'")
                remote_path = command_parts[2].strip('"')

                if not Path(local_path).expanduser().exists():
                    logger.error(f"Local file '{local_path}' does not exist.")
                    continue

                file_name = local_path.split(os.sep)[-1]

                if not re.match(r"^[a-zA-Z]:", remote_path):
                    # If the path doesn't start with a drive letter, prepend the current directory
                    pwd, streams, had_errors = run_ps_cmd(r_pool, "$pwd.Path")
                    if remote_path == ".":
                        remote_path = f"{pwd}\\{file_name}"
                    else:
                        remote_path = f"{pwd}\\{remote_path}"

                if remote_path.endswith("\\"):
                    remote_path = f"{remote_path}{file_name}"

                commands.upload_file(
                    r_pool, str(Path(local_path).expanduser().resolve()), remote_path
                )

                continue

            if command_lower.startswith("loadps"):
                if len(command_parts) < 2:
                    logger.error("Usage: loadps <local_path>")
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    logger.error(
                        f"Local PowerShell script '{local_path}' does not exist."
                    )
                    continue
                elif local_path.suffix.lower() != ".ps1":
                    logger.error(
                        "Please provide a valid PowerShell script file with .ps1 extension."
                    )
                    continue

                commands.load_ps(r_pool, local_path)
                continue

            if command_lower.startswith("runps"):
                if len(command_parts) < 2:
                    logger.error("Usage: runps <local_path>")
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    logger.error(
                        f"Local PowerShell script '{local_path}' does not exist."
                    )
                    continue
                elif local_path.suffix.lower() != ".ps1":
                    logger.error(
                        "Please provide a valid PowerShell script file with .ps1 extension."
                    )
                    continue

                commands.run_ps(r_pool, local_path)
                continue

            if command_lower.startswith("loaddll"):
                if len(command_parts) < 2:
                    logger.error("Usage: loaddll <local_path>")
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    logger.error(f"Local dll '{local_path}' does not exist.")
                    continue
                elif local_path.suffix.lower() != ".dll":
                    logger.error("Please provide a valid dll file with .dll extension.")
                    continue
                commands.load_dll(r_pool, local_path)
                continue

            if command_lower.startswith("runexe"):
                if len(command_parts) < 2:
                    logger.error("Usage: runexe <local_path> [args]")
                    continue
                local_path = command_parts[1].strip('"')
                local_path = Path(local_path).expanduser().resolve()

                if not local_path.exists():
                    logger.error(f"Local executable '{local_path}' does not exist.")
                    continue
                elif local_path.suffix.lower() != ".exe":
                    logger.error(
                        "Please provide a valid executable file with .exe extension."
                    )
                    continue

                args = " ".join(command_parts[2:]) if len(command_parts) > 2 else ""

                commands.run_exe(r_pool, local_path, args)
                continue

            try:
                ps = PowerShell(r_pool)
                ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
                ps.add_cmdlet("Out-String").add_parameter("Stream")
                ps.begin_invoke()
                logger.debug("Executing command: {}".format(command))

                cursor = 0
                while ps.state == PSInvocationState.RUNNING:
                    with commands.DelayedKeyboardInterrupt():
                        ps.poll_invoke()
                    output = ps.output
                    for line in output[cursor:]:
                        print(line)
                    cursor = len(output)
                logger.debug("Command execution completed.")

                if ps.streams.error:
                    for error in ps.streams.error:
                        print(RED + error._to_string + RESET)
                        logger.error("Error: {}".format(error._to_string))
                        logger.error("\tCategoryInfo: {}".format(error.message))
                        logger.error(
                            "\tFullyQualifiedErrorId: {}".format(error.fq_error)
                        )
            except KeyboardInterrupt:
                if ps.state == PSInvocationState.RUNNING:
                    logger.info("Stopping command execution.")
                    ps.stop()
