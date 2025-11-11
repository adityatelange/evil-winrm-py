# Built-in imports
import signal
import base64
import hashlib
import json
import re
import shutil
import tempfile
import time
from importlib import resources
from pathlib import Path

# External library imports
from loguru import logger

from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.complex_objects import PSInvocationState

from tqdm import tqdm


class DelayedKeyboardInterrupt:
    """
    A context manager to delay the handling of a SIGINT (Ctrl+C) signal until
    the enclosed block of code has completed execution.

    This is useful for ensuring that critical sections of code are not
    interrupted by a keyboard interrupt, while still allowing the signal
    to be handled after the block finishes.
    """

    def __enter__(self):
        self.signal_received = False
        self.old_handler = signal.getsignal(signal.SIGINT)

        def handler(sig, frame):
            logger.debug("Caught Ctrl+C. Will stop after current operation...")
            self.signal_received = True

        signal.signal(signal.SIGINT, handler)
        return self

    def __exit__(self, type, value, traceback):
        signal.signal(signal.SIGINT, self.old_handler)
        # Return False to not suppress exceptions, but don't re-raise the signal
        # The calling code should check self.signal_received to handle interruption
        return False


def get_ps_script(script_name: str) -> str:
    """
    Returns the content of a PowerShell script from the package resources.
    """
    try:
        with resources.path("evil_winrm_py._ps", script_name) as script_path:
            return script_path.read_text()
    except FileNotFoundError:
        logger.error(f"Script {script_name} not found.")
        return ""


def download_file(r_pool: RunspacePool, remote_path: str, local_path: str) -> None:
    ps = PowerShell(r_pool)
    script = get_ps_script("fetch.ps1")
    ps.add_script(script)
    ps.add_parameter("FilePath", remote_path)
    ps.begin_invoke()

    ts = int(time.time())
    tmp_file_path = Path(tempfile.gettempdir()) / f"evil-winrm-py.file_{ts}.tmp"

    try:
        # Create a temporary file to store the downloaded data
        with open(tmp_file_path, "ab+") as bin:
            cursor = 0
            metadata = {}
            while ps.state == PSInvocationState.RUNNING:
                with DelayedKeyboardInterrupt():
                    ps.poll_invoke()
                output = ps.output
                if cursor == 0:
                    line = json.loads(output[0])
                    if line["Type"] == "Error":
                        logger.error(f"Error: {line['Message']}")
                        return
                    elif line["Type"] == "Metadata":
                        metadata = line
                    pbar = tqdm(
                        total=metadata["FileSize"],
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                        desc=f"Downloading {remote_path}",
                        dynamic_ncols=True,
                        mininterval=0.1,
                    )
                for line in output[cursor:]:
                    line = json.loads(line)
                    if line["Type"] == "Chunk":
                        Base64Data = line["Base64Data"]
                        chunk = base64.b64decode(Base64Data)
                        bin.write(chunk)
                        pbar.update(metadata["ChunkSize"])
                    if line["Type"] == "Error":
                        logger.error(f"Error: {line['Message']}")
                        return
                cursor = len(output)
            pbar.close()
            bin.close()

        if ps.had_errors:
            if ps.streams.error:
                for error in ps.streams.error:
                    logger.error(str(error))

    except KeyboardInterrupt:
        if "pbar" in locals() and pbar:
            pbar.leave = (
                False  # Make the progress bar disappear on close after interrupt
            )
            pbar.close()
        Path(tmp_file_path).unlink(missing_ok=True)
        if ps.state == PSInvocationState.RUNNING:
            logger.info("Stopping command execution.")
            ps.stop()
        return

    # Verify the downloaded file's hash
    hexdigest = hashlib.md5(open(tmp_file_path, "rb").read()).hexdigest()
    if metadata["FileHash"].lower() == hexdigest:
        # If the hash matches, rename the temporary file to the final name
        tmp_file_path = Path(tmp_file_path)
        try:
            shutil.move(tmp_file_path, local_path)
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            return
        logger.info("File downloaded successfully and saved as: {}".format(local_path))
    else:
        logger.error("File hash mismatch. Downloaded file may be corrupted.")


def upload_file(r_pool: RunspacePool, local_path: str, remote_path: str) -> None:
    hexdigest = hashlib.md5(open(local_path, "rb").read()).hexdigest().upper()
    with open(local_path, "rb") as bin:
        file_size = Path(local_path).stat().st_size
        chunk_size_bytes = 65536  # 64 KB
        total_chunks = (file_size + chunk_size_bytes - 1) // chunk_size_bytes
        metadata = {"FileHash": ""}  # Declare a psuedo metadata

        pbar = tqdm(
            total=file_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=f"Uploading {local_path}",
            dynamic_ncols=True,
            mininterval=0.1,
        )
        try:
            temp_file_path = ""
            for i in range(total_chunks):
                start_offset = i * chunk_size_bytes
                bin.seek(start_offset)
                chunk = bin.read(chunk_size_bytes)

                if not chunk:  # End of file
                    break

                elif i == 0:
                    chunk_type = 0  # First chunk, tells PS script to create file
                    if len(chunk) < chunk_size_bytes:
                        chunk_type = 3
                elif i == total_chunks - 1:
                    chunk_type = 1  # Last chunk, tells PS script to calculate hash
                else:
                    chunk_type = 2  # Intermediate chunk

                base64_chunk = base64.b64encode(chunk).decode("utf-8")

                script = get_ps_script("send.ps1")
                with DelayedKeyboardInterrupt():
                    ps = PowerShell(r_pool)
                    ps.add_script(script)
                    ps.add_parameter("Base64Chunk", base64_chunk)
                    ps.add_parameter("ChunkType", chunk_type)

                    if chunk_type == 1:
                        # If it's the last chunk, we provide the file path and hash
                        ps.add_parameter("TempFilePath", temp_file_path)
                        ps.add_parameter("FilePath", remote_path)
                        ps.add_parameter("FileHash", hexdigest)
                    elif chunk_type == 2:
                        ps.add_parameter("TempFilePath", temp_file_path)
                    elif chunk_type == 3:
                        ps.add_parameter("FilePath", remote_path)
                        ps.add_parameter("FileHash", hexdigest)

                    ps.begin_invoke()

                    while ps.state == PSInvocationState.RUNNING:
                        ps.poll_invoke()
                output = ps.output

                for line in output:
                    line = json.loads(line)
                    if line["Type"] == "Metadata":
                        metadata = line
                        if "TempFilePath" in metadata:
                            temp_file_path = metadata["TempFilePath"]

                    if line["Type"] == "Error":
                        logger.error(f"Error: {line['Message']}")
                        pbar.leave = False  # Make the progress bar disappear on close
                        return
                if ps.had_errors:
                    if ps.streams.error:
                        for error in ps.streams.error:
                            logger.error(str(error))
                if chunk_type == 3:
                    pbar.update(file_size)
                else:
                    pbar.update(chunk_size_bytes)
            pbar.close()

            # Verify the downloaded file's hash
            if metadata["FileHash"] == hexdigest:
                logger.info(
                    "File uploaded successfully as: {}".format(metadata["FilePath"])
                )
            else:
                logger.error("File hash mismatch. Uploaded file may be corrupted.")

        except KeyboardInterrupt:
            if "pbar" in locals() and pbar:
                pbar.leave = (
                    False  # Make the progress bar disappear on close after interrupt
                )
                pbar.close()
            if ps.state == PSInvocationState.RUNNING:
                logger.info("Stopping command execution.")
                ps.stop()


def load_ps(r_pool: RunspacePool, local_path: str):
    ps = PowerShell(r_pool)
    try:
        with open(local_path, "r") as script_file:
            script = script_file.read()
            # Remove block comments (<#...#>) to avoid matching commented-out functions
            content = re.sub(r"<#.*?#>", "", script, flags=re.DOTALL)
            # Find all function names in the script
            pattern = r"function\s+([a-zA-Z0-9_-]+)\s*(?={|$)"
            function_names = re.findall(pattern, content, re.MULTILINE)

        ps.add_script(f". {{ {script} }}")  # Dot sourcing the script
        ps.begin_invoke()

        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()

        if ps.streams.error:
            logger.error(f"Failed to load PowerShell script '{local_path}'.")
            for error in ps.streams.error:
                logger.error("Error: {}".format(error._to_string))
                logger.error("\tCategoryInfo: {}".format(error.message))
                logger.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            logger.info(f"PowerShell script '{local_path}' loaded successfully.")
            global COMMAND_SUGGESTIONS
            # Update the command suggestions with the function names
            new_suggestions = []
            for func in function_names:
                if func not in COMMAND_SUGGESTIONS:
                    new_suggestions += [func]
            if new_suggestions:
                COMMAND_SUGGESTIONS += new_suggestions
                logger.info(
                    f"New commands available (use TAB to autocomplete): {', '.join(new_suggestions)}"
                )
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            logger.info("Stopping command execution.")
            ps.stop()


def run_ps(r_pool: RunspacePool, local_path: str) -> None:
    """Runs a local PowerShell script on the remote host."""
    ps = PowerShell(r_pool)
    try:
        with open(local_path, "r") as script_file:
            script = script_file.read()

        ps.add_script(script)
        ps.begin_invoke()

        cursor = 0
        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()
            output = ps.output
            for line in output[cursor:]:
                logger.info(line)
            cursor = len(output)

        if ps.streams.error:
            logger.error(f"Failed to run PowerShell script '{local_path}'.")
            for error in ps.streams.error:
                logger.error("Error: {}".format(error._to_string))
                logger.error("\tCategoryInfo: {}".format(error.message))
                logger.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            logger.info(f"PowerShell script '{local_path}' ran successfully.")
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            logger.info("Stopping command execution.")
            ps.stop()


def load_dll(r_pool: RunspacePool, local_path: str) -> None:
    """Uploads in-memory and loads a local DLL on the remote host, then invokes a specified function."""
    ps = PowerShell(r_pool)
    try:
        with open(local_path, "rb") as dll_file:
            dll_data = dll_file.read()
            base64_dll = base64.b64encode(dll_data).decode("utf-8")

        script = get_ps_script("loaddll.ps1")
        ps.add_script(script)
        ps.add_parameter("Base64Dll", base64_dll)
        ps.begin_invoke()

        cursor = 0
        name = ""
        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()
            output = ps.output
            for line in output[cursor:]:
                line = json.loads(line)
                if line["Type"] == "Error":
                    logger.error(f"Error: {line['Message']}")
                    return
                elif line["Type"] == "Metadata":
                    if "Name" in line:
                        name = line["Name"]
                        logger.info(f"Loading '{name}' as a module...")
                    elif "Funcs" in line:
                        logger.info(
                            f"New commands available (use TAB to autocomplete): {', '.join(line['Funcs'])}"
                        )
                        global COMMAND_SUGGESTIONS
                        new_suggestions = []
                        for func in line["Funcs"]:
                            if func not in COMMAND_SUGGESTIONS:
                                new_suggestions += [func]
                        if new_suggestions:
                            COMMAND_SUGGESTIONS += new_suggestions
            cursor = len(output)

        if ps.streams.error:
            logger.error(f"Failed to load DLL '{local_path}'")
            for error in ps.streams.error:
                logger.error("Error: {}".format(error._to_string))
                logger.error("\tCategoryInfo: {}".format(error.message))
                logger.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            logger.info(f"DLL '{local_path}' loaded successfully.")
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            logger.info("Stopping command execution.")
            ps.stop()


def run_exe(r_pool: RunspacePool, local_path: str, args: str = "") -> None:
    """Uploads in-memory and runs a local executable on the remote host."""
    ps = PowerShell(r_pool)
    file_path = Path(local_path)
    file_size = file_path.stat().st_size
    logger.info(f"Uploading in-memory ({file_size} bytes) and executing...")
    try:
        with open(local_path, "rb") as exe_file:
            exe_data = exe_file.read()
            base64_exe = base64.b64encode(exe_data).decode("utf-8")

        script = get_ps_script("exec.ps1")
        ps.add_script(script)
        ps.add_parameter("Base64Exe", base64_exe)
        ps.add_parameter("Args", args.split(" "))
        ps.begin_invoke()

        cursor = 0
        while ps.state == PSInvocationState.RUNNING:
            with DelayedKeyboardInterrupt():
                ps.poll_invoke()
            output = ps.output
            for line in output[cursor:]:
                logger.info(line)
            cursor = len(output)

        if ps.streams.error:
            logger.error(f"Failed to run executable '{local_path}'.")
            for error in ps.streams.error:
                logger.error("Error: {}".format(error._to_string))
                logger.error("\tCategoryInfo: {}".format(error.message))
                logger.error("\tFullyQualifiedErrorId: {}".format(error.fq_error))
        else:
            logger.info(f"Executable '{local_path}' ran successfully.")
    except KeyboardInterrupt:
        if ps.state == PSInvocationState.RUNNING:
            logger.info("Stopping command execution.")
            ps.stop()
