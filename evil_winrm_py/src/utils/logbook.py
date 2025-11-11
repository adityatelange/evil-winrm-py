"""Logbook module for logging capabilities using Loguru.

Is this message about...

├─ Internal framework/library mechanics?
│  └─ Use TRACE
│
├─ Something the user might need to debug their usage?
│  └─ Use DEBUG
│
├─ Normal operational information?
│  └─ Use INFO
│
└─ Something went wrong or needs attention?
   └─ Use WARNING/ERROR
"""

import os
import sys
from pathlib import Path

# Third party library imports
from loguru import logger


def _format_message(record):
    """Custom formatter with compact symbols and colors."""
    level_name = record["level"].name

    # Modern color palette (hex colors for better terminal support)
    trace_brown = "#8b7355"
    debug_blue = "#6c9bd1"
    info_white = "#ecf0f1"
    success_green = "#52c88a"
    warning_orange = "#f39c12"
    error_red = "#e74c3c"
    critical_magenta = "#c71585"
    time_gray = "#a5a5a5"

    # Map levels to symbols and colors
    symbols = {
        "TRACE": (f"<fg {trace_brown}>[*]</fg {trace_brown}>", trace_brown),
        "DEBUG": (f"<fg {debug_blue}>[•]</fg {debug_blue}>", debug_blue),
        "INFO": (f"<fg {info_white}>[i]</fg {info_white}>", info_white),
        "SUCCESS": (f"<fg {success_green}>[✓]</fg {success_green}>", success_green),
        "WARNING": (f"<fg {warning_orange}>[!]</fg {warning_orange}>", warning_orange),
        "ERROR": (f"<fg {error_red}>[✗]</fg {error_red}>", error_red),
        "CRITICAL": (
            f"<fg {critical_magenta}><bold>[⚠]</bold></fg {critical_magenta}>",
            critical_magenta,
        ),
    }

    symbol, color = symbols.get(level_name, ("[?]", "white"))

    # Professional format: full UTC timestamp + symbol + message
    # Note: We must return a string template, not format it yet
    return (
        f"<fg {time_gray}>{{time:YYYY-MM-DD HH:mm:ss.SSS!UTC}} (UTC)</fg {time_gray}> "
        f"{symbol} "
        f"<fg {color}>{{message}}</fg {color}>"
        "\n{exception}"
    )


def _xdg_state_dir(app_name: str = "evil_winrm_py") -> Path:
    """Get platform-appropriate log directory following XDG standards."""
    # Highest priority: explicit override
    override = os.getenv("EVIL_WINRM_PY_LOG_DIR")
    if override:
        return Path(override).expanduser().resolve()

    if os.name == "nt":
        base = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return (base / app_name / "logs").resolve()

    # POSIX: follow XDG
    base = os.getenv("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser().resolve() / app_name / "logs"

    return Path.home() / ".local" / "state" / app_name / "logs"


def setup_logging(level: str = "INFO", no_colors: bool = False):
    """
    Setup logging with compact, visually intuitive output.

    Args:
        level: Log level (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
        no_colors: Disable colors in console output
    """
    level = level.upper()

    # Validate log level
    valid_levels = ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
    if level not in valid_levels:
        level = "INFO"

    # Remove all Loguru handlers to avoid duplicates
    logger.remove()

    # Add custom formatted handler
    # enqueue=False for synchronous output to maintain ordering when using print()
    logger.add(
        sys.stderr,
        enqueue=False,
        backtrace=True,
        diagnose=True,
        level=level,
        format=_format_message,
        colorize=not no_colors,  # Respect no_colors flag
    )

    # --- File handler (rotating, UTC timestamps)
    log_dir = _xdg_state_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "evil-winrm-py.log"

    # Configurable rotation & retention
    max_bytes = os.getenv("EVIL_WINRM_PY_LOG_MAX_BYTES", "10 MB")
    retention_days = int(os.getenv("EVIL_WINRM_PY_LOG_RETENTION_DAYS", "14"))

    # File format without colors
    file_format = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS!UTC} (UTC) "
        "[{level:7}] {message}\n"
        "{exception}"
    )

    logger.add(
        log_file,
        format=file_format,
        level=level,
        rotation=max_bytes,
        retention=f"{retention_days} days",
        compression="zip",
        encoding="utf-8",
        enqueue=True,  # Thread-safe
    )

    # Enable Kerberos trace logging for DEBUG and TRACE levels
    if level in ["DEBUG", "TRACE"]:
        krb5_trace_file = log_dir / "krb5_trace.log"
        os.environ["KRB5_TRACE"] = str(krb5_trace_file)
        logger.debug(f"KRB5_TRACE enabled: {krb5_trace_file}")

    logger.success(f"Logger initialized at level {level}")
    logger.trace(
        f"Log file: {log_file} (rotation {max_bytes}, retention {retention_days} days)"
    )
