# Built-in imports
import os
import re
from pathlib import Path

# External library imports
from pypsrp.powershell import PowerShell, RunspacePool
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document


def get_directory_and_partial_name(text: str, sep: str) -> tuple[str, str]:
    """
    Parses the input text to find the directory prefix and the partial name.
    """
    if sep not in ["\\", "/"]:
        raise ValueError("Separator must be either '\\' or '/'")
    # Find the last unquoted slash or backslash
    last_sep_index = text.rfind(sep)
    if last_sep_index == -1:
        # No separator found, the whole text is the partial name in the current directory
        directory_prefix = ""
        partial_name = text
    else:
        split_at = last_sep_index + 1
        directory_prefix = text[:split_at]
        partial_name = text[split_at:]
    return directory_prefix, partial_name


def get_remote_path_suggestions(
    r_pool: RunspacePool,
    directory_prefix: str,
    partial_name: str,
    dirs_only: bool = False,
) -> list[str]:
    """
    Returns a list of remote path suggestions based on the current directory
    and the partial name entered by the user.
    """

    exp = "FullName"
    attrs = ""
    if not re.match(r"^[a-zA-Z]:", directory_prefix):
        # If the path doesn't start with a drive letter, prepend the current directory
        from evil_winrm_py.src.terminal import run_ps_cmd

        pwd, streams, had_errors = run_ps_cmd(
            r_pool, "$pwd.Path"
        )  # Get current working directory
        directory_prefix = f"{pwd}\\{directory_prefix}"
        exp = "Name"

    if dirs_only:
        attrs = "-Attributes Directory"

    command = f'Get-ChildItem -LiteralPath "{directory_prefix}" -Filter "{partial_name}*" {attrs} -Fo | select -Exp {exp}'
    ps = PowerShell(r_pool)
    ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
    ps.add_cmdlet("Out-String").add_parameter("Stream")
    ps.invoke()
    return ps.output


def get_local_path_suggestions(
    directory_prefix: str, partial_name: str, extension: str = None
) -> list[str]:
    """
    Returns a list of local path suggestions based on path entered by the user.
    Optionally filters files by extension (e.g., ".ps1").
    """
    suggestions = []

    # Expand the tilde to the user's home directory
    home = str(Path.home())

    try:
        entries = Path(directory_prefix).expanduser().iterdir()
        for entry in entries:
            if entry.match(f"{partial_name}*"):
                if entry.is_dir():
                    entry = (
                        f"{entry}{os.sep}"  # Append a trailing slash for directories
                    )
                    if directory_prefix.startswith("~"):
                        # If the directory prefix starts with ~, replace home with ~
                        entry = str(entry).replace(home, "~", 1)
                    suggestions.append(str(entry))
                else:
                    if (extension is None) or (
                        entry.suffix.lower() == extension.lower()
                    ):
                        if directory_prefix.startswith("~"):
                            # If the directory prefix starts with ~, replace home with ~
                            entry = str(entry).replace(home, "~", 1)
                        suggestions.append(str(entry))
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        pass
    finally:
        if extension:
            # Sort suggestions alphabetically, prioritizing those that match the extension
            return sorted(suggestions, key=lambda x: not x.endswith(extension))
        return suggestions


def quoted_command_split(command: str) -> list[str]:
    """
    Splits a command string into parts, respecting quoted strings.
    This is useful for handling paths with spaces or special characters.
    """
    actual_command_parts = []
    continuation = False
    cursor = 0

    command_parts = command.split(" ")
    for part in command_parts:
        if not part:
            continue
        if continuation:
            actual_command_parts[cursor] = actual_command_parts[cursor] + " " + part
            if part.endswith('"'):
                continuation = False
                cursor += 1
        else:
            if part.startswith('"'):
                actual_command_parts += [part]
                continuation = True
            elif part.find('"') != -1:
                # #TODO: decide later how to handle this case
                pass
            else:
                actual_command_parts += [part]
                cursor += 1
    return actual_command_parts


class CommandPathCompleter(Completer):
    """
    Completer for command paths in the interactive shell.
    This completer suggests command names based on the user's input.
    """

    def __init__(
        self, r_pool: RunspacePool, menu_commands: dict, command_suggestions: list
    ):
        self.r_pool = r_pool
        self.menu_commands = menu_commands
        self.command_suggestions = command_suggestions

    def get_completions(self, document: Document, complete_event):
        dirs_only = False  # Whether to suggest only directories
        text_before_cursor = document.text_before_cursor.lstrip()
        tokens = text_before_cursor.split(maxsplit=1)

        if not tokens:  # Empty input, suggest all commands
            for cmd_sugg in list(self.menu_commands.keys()) + self.command_suggestions:
                yield Completion(cmd_sugg, start_position=0, display=cmd_sugg)
            return

        command_typed_part = tokens[0]

        # Handle .\name or ./name as first-token paths (run from current remote directory)
        if command_typed_part.startswith(".\\") or command_typed_part.startswith("./"):
            path_being_completed = command_typed_part
            # strip surrounding quotes if any
            if path_being_completed.startswith('"') and path_being_completed.endswith(
                '"'
            ):
                path_being_completed = path_being_completed.strip('"')
            directory_prefix, partial_name = get_directory_and_partial_name(
                path_being_completed, sep="\\"
            )
            suggestions = get_remote_path_suggestions(
                self.r_pool, directory_prefix, partial_name
            )
            for sugg_path in suggestions:
                text_to_insert_in_prompt = f".\\" + sugg_path
                if " " in sugg_path:
                    text_to_insert_in_prompt = f'& ".\\{sugg_path}"'
                yield Completion(
                    text_to_insert_in_prompt,
                    start_position=-len(command_typed_part),
                    display=sugg_path,
                )
            return

        # Case 1: Completing the command name itself
        # There's only one token and no trailing space.
        if len(tokens) == 1 and not text_before_cursor.endswith(" "):
            # User is typing the command, -> "downl"
            for cmd_sugg in list(self.menu_commands.keys()) + self.command_suggestions:
                if cmd_sugg.startswith(command_typed_part):
                    yield Completion(
                        cmd_sugg + " ",  # Full suggested command
                        start_position=-len(
                            command_typed_part
                        ),  # Replace the typed part
                        display=cmd_sugg,
                    )
            return

        # Case 2: Completing a path argument
        path_typed_segment = ""  # What the user has typed for the current path argument
        if len(tokens) == 2:
            path_typed_segment = tokens[1]

        actual_command_name = command_typed_part.strip().lower()

        args = quoted_command_split(path_typed_segment.strip())

        suggestions = []
        current_arg_text_being_completed = ""
        directory_prefix = partial_name = ""

        if actual_command_name == "upload":
            # syntax: upload <local_path> <remote_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "upload "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(directory_prefix, partial_name)
            elif num_args_present == 1:
                # We have one argument part, e.g., "upload arg1" or "upload local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete
                    # Completing the 2nd argument (remote_path), currently empty
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep="\\"
                    )
                    suggestions = get_remote_path_suggestions(
                        self.r_pool, directory_prefix, partial_name
                    )
                else:
                    # Still completing the 1st argument (local_path), e.g., "upload arg1"
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name
                    )
            elif num_args_present == 2:
                #  We have two argument parts
                # e.g., "upload local_path arg2" or "upload local_path remote_path "
                if path_typed_segment.endswith(" "):
                    # 2nd argument (remote_path) is complete. No more suggestions for "upload".
                    pass
                else:
                    # Completing the 2nd argument (remote_path), e.g., "upload local_path arg2"
                    current_arg_text_being_completed = path_being_completed = args[1]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep="\\"
                    )
                    suggestions = get_remote_path_suggestions(
                        self.r_pool, directory_prefix, partial_name
                    )
            else:
                # More than 2 arguments, e.g., "upload local_path remote_path extra_arg"
                pass
        elif actual_command_name == "download":
            # syntax: download <remote_path> <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "download "
                # Completing 1st arg (remote_path), empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep="\\"
                )
                suggestions = get_remote_path_suggestions(
                    self.r_pool, directory_prefix, partial_name
                )
            elif num_args_present == 1:
                # We have "download arg1" or "download local_path "
                if path_typed_segment.endswith(" "):
                    # First arg (remote_path) is complete. Completing 2nd arg (local_path), empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name
                    )
                else:
                    # Still completing 1st arg (remote_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep="\\"
                    )
                    suggestions = get_remote_path_suggestions(
                        self.r_pool, directory_prefix, partial_name
                    )
            elif num_args_present == 2:
                # We have two argument parts
                # e.g., "download remote_path arg2" or "download remote_path local_path "
                if path_typed_segment.endswith(" "):
                    # 2nd argument (local_path) is complete. No more suggestions for "download".
                    pass
                else:
                    # Completing 2nd arg (local_path)
                    current_arg_text_being_completed = path_being_completed = args[1]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name
                    )
            else:
                # More than 2 arguments, e.g., "download remote_path local_path extra_arg"
                pass
        elif actual_command_name in ["loadps", "runps"]:
            # syntax: loadps <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "loadps "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(
                    directory_prefix, partial_name, extension=".ps1"
                )
            elif num_args_present == 1:
                # We have "loadps arg1" or "loadps local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete, currently empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".ps1"
                    )
                else:
                    # Still completing the 1st argument (local_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".ps1"
                    )
            else:
                # More than 1 argument, e.g., "loadps local_path extra_arg"
                pass
        elif actual_command_name in ["loaddll"]:
            # syntax: loaddll <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "loaddll "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(
                    directory_prefix, partial_name, extension=".dll"
                )
            elif num_args_present == 1:
                # We have "loaddll arg1" or "loaddll local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete, currently empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".dll"
                    )
                else:
                    # Still completing the 1st argument (local_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".dll"
                    )
            else:
                # More than 1 argument, e.g., "loaddll local_path extra_arg"
                pass
        elif actual_command_name in ["runexe"]:
            # syntax: runexe <local_path>
            num_args_present = len(args)

            if num_args_present == 0:
                # User typed "runexe "
                # Completing the 1st argument (local_path), currently empty
                current_arg_text_being_completed = ""
                directory_prefix, partial_name = get_directory_and_partial_name(
                    current_arg_text_being_completed, sep=os.sep
                )
                suggestions = get_local_path_suggestions(
                    directory_prefix, partial_name, extension=".exe"
                )
            elif num_args_present == 1:
                # We have "runexe arg1" or "runexe local_path "
                if path_typed_segment.endswith(" "):
                    # 1st argument (local_path) is complete, currently empty.
                    current_arg_text_being_completed = ""
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        current_arg_text_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".exe"
                    )
                else:
                    # Still completing the 1st argument (local_path)
                    current_arg_text_being_completed = path_being_completed = args[0]
                    if path_being_completed.startswith('"'):
                        path_being_completed = current_arg_text_being_completed.strip(
                            '"'
                        )
                    directory_prefix, partial_name = get_directory_and_partial_name(
                        path_being_completed, sep=os.sep
                    )
                    suggestions = get_local_path_suggestions(
                        directory_prefix, partial_name, extension=".exe"
                    )
            else:
                # More than 1 argument, e.g., "runexe local_path extra_arg"
                pass
        else:
            if actual_command_name == "cd":
                dirs_only = True

            current_arg_text_being_completed = path_being_completed = path_typed_segment

            if path_being_completed.startswith('"'):
                path_being_completed = current_arg_text_being_completed.strip('"')

            directory_prefix, partial_name = get_directory_and_partial_name(
                path_being_completed, sep="\\"
            )
            suggestions = get_remote_path_suggestions(
                self.r_pool, directory_prefix, partial_name, dirs_only
            )

        for sugg_path in suggestions:

            # If the path doesn't start with a drive letter, prepend the directory_prefix
            if (
                not re.match(r"^[a-zA-Z]:", directory_prefix)
                and directory_prefix
                and directory_prefix.endswith("\\")
            ):
                sugg_path = f"{directory_prefix}{sugg_path}"

            text_to_insert_in_prompt = sugg_path

            if " " in sugg_path:
                # If the path contains spaces, quote it
                text_to_insert_in_prompt = f'"{sugg_path}"'

            yield Completion(
                text_to_insert_in_prompt,
                start_position=-len(
                    current_arg_text_being_completed
                ),  # Use the length of quoted part
                display=sugg_path,
            )
