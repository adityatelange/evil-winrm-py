# toboggan/utils/banner.py

# Local library imports
from evil_winrm_py import __version__


def display_banner() -> str:
    return """          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\\ V | | |___\\ V  V | | ' \\| '_| '  |___| '_ | || |
 \\___|\\_/|_|_|    \\_/\\_/|_|_||_|_| |_|_|_|  | .__/\\_, |
                                            |_|   |__/  v{}\n""".format(
        __version__
    )
