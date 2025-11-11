import os
from pathlib import Path

from loguru import logger

# check if kerberos is installed
try:
    from gssapi.creds import Credentials as GSSAPICredentials
    from gssapi.exceptions import ExpiredCredentialsError, MissingCredentialsError
    from gssapi.raw import Creds as RawCreds
    from krb5._exceptions import Krb5Error

    IS_KERBEROS_AVAILABLE = True
except ImportError:
    IS_KERBEROS_AVAILABLE = False

    # If kerberos is not available, define dummy exceptions
    class Krb5Error(Exception):
        pass

    class MissingCredentialsError(Exception):
        pass

    class ExpiredCredentialsError(Exception):
        pass


def validate_kerberos_config() -> bool:
    """
    Validate Kerberos configuration and credentials.

    Returns:
        bool: True if valid, False otherwise (errors are logged)
    """
    if not IS_KERBEROS_AVAILABLE:
        logger.error("Kerberos is not installed. Install with: pip install gssapi krb5")
        return False

    krb5_ccname = os.environ.get("KRB5CCNAME")
    krb5_config = os.environ.get("KRB5_CONFIG")

    logger.info("Kerberos auth requested")
    logger.info(f"KRB5CCNAME: {krb5_ccname or '(not set, using default)'}")
    logger.info(
        f"KRB5_CONFIG: {krb5_config or '(not set, using default /etc/krb5.conf)'}"
    )

    # Validate credentials cache file exists and is readable
    if krb5_ccname:
        ccache_path = Path(krb5_ccname)
        if not ccache_path.exists():
            logger.error(f"Credentials cache file not found: {krb5_ccname}")
            return False
        if not os.access(krb5_ccname, os.R_OK):
            logger.error(f"Credentials cache file not readable: {krb5_ccname}")
            return False
        logger.debug(f"Credentials cache file exists and is readable: {krb5_ccname}")

    # Validate and read Kerberos config file
    if krb5_config:
        config_path = Path(krb5_config)
        if not config_path.exists():
            logger.error(f"Kerberos config file not found: {krb5_config}")
            return False
        krb5_config_file = krb5_config
    else:
        # Check default location
        default_krb5_config = Path("/etc/krb5.conf")
        if not default_krb5_config.exists():
            logger.warning("Default Kerberos config file not found at /etc/krb5.conf")
            logger.info("You may need to set KRB5_CONFIG environment variable")
            krb5_config_file = None
        else:
            krb5_config_file = str(default_krb5_config)

    # Validate krb5.conf content if it exists
    if krb5_config_file:
        if not _validate_krb5_config_content(krb5_config_file):
            return False

    # Validate Kerberos credentials are available
    if not _validate_kerberos_credentials():
        return False

    # Validate ccache coherence with krb5.conf config
    if not _validate_ccache_coherence(krb5_config):
        return False

    return True


def _extract_default_realm(config_file: str) -> str:
    """
    Extract default_realm from krb5.conf.

    Args:
        config_file: Path to krb5.conf file

    Returns:
        str: default_realm value or None
    """
    try:
        with open(config_file, "r") as f:
            in_libdefaults = False
            for line in f:
                line = line.strip()
                if line == "[libdefaults]":
                    in_libdefaults = True
                    continue
                elif line.startswith("[") and line.endswith("]"):
                    in_libdefaults = False
                    continue

                if in_libdefaults and "=" in line:
                    key, value = line.split("=", 1)
                    if key.strip().lower() == "default_realm":
                        return value.strip()
    except Exception:
        pass
    return None


def _validate_ccache_coherence(krb5_config_env: str) -> bool:
    """
    Validate that ccache credentials match krb5.conf configuration.

    Args:
        krb5_config_env: KRB5_CONFIG environment variable value

    Returns:
        bool: True if coherent or cannot verify, False if incoherent
    """
    try:
        # Get credentials from ccache
        cred = GSSAPICredentials(RawCreds())
        ccache_principal = str(
            cred.name
        )  # Convert Name object to string, e.g., "monitoring_svc@NANOCORP.HTB"

        if not ccache_principal or "@" not in ccache_principal:
            logger.debug("Cannot extract realm from ccache principal")
            return True

        # Extract realm from principal
        ccache_realm = ccache_principal.split("@")[1]
        logger.debug(f"ccache principal realm: {ccache_realm}")

        # Get krb5.conf file to read
        if krb5_config_env:
            krb5_config_file = krb5_config_env
        else:
            krb5_config_file = "/etc/krb5.conf"

        # Extract default_realm from krb5.conf
        default_realm = _extract_default_realm(krb5_config_file)
        if default_realm:
            logger.debug(f"krb5.conf default_realm: {default_realm}")

            # Compare realms
            if ccache_realm.lower() != default_realm.lower():
                logger.warning(
                    f"Realm mismatch: ccache has '{ccache_realm}' but krb5.conf default is '{default_realm}'"
                )
                logger.warning(
                    "This may cause authentication failures if the realm is not properly configured"
                )
                logger.info(
                    "Hint: Update krb5.conf default_realm or ensure realms section is configured"
                )
                # Don't fail, just warn - it might still work if realms are configured
            else:
                logger.success(f"ccache realm '{ccache_realm}' matches krb5.conf")

        return True
    except Exception as e:
        logger.debug(f"Could not validate ccache coherence: {e}")
        return True  # Don't fail if we can't verify


def _validate_krb5_config_content(config_file: str) -> bool:
    """
    Validate krb5.conf file content and structure.

    Args:
        config_file: Path to krb5.conf file

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        with open(config_file, "r") as f:
            config_content = f.read()
            if not config_content.strip():
                logger.error(f"Kerberos config file is empty: {config_file}")
                return False

            # Check if it has essential sections
            has_libdefaults = "[libdefaults]" in config_content
            has_realms = "[realms]" in config_content
            has_domain_realm = "[domain_realm]" in config_content

            logger.debug(
                f"krb5.conf sections - libdefaults: {has_libdefaults}, "
                f"realms: {has_realms}, domain_realm: {has_domain_realm}"
            )

            if not has_libdefaults:
                logger.warning("krb5.conf missing [libdefaults] section")
            if not has_realms:
                logger.warning(
                    "krb5.conf missing [realms] section (needed to locate KDC)"
                )
            if not has_domain_realm:
                logger.warning("krb5.conf missing [domain_realm] section")

            # Parse and validate krb5.conf content
            _validate_krb5_config_values(config_content)

            return True
    except IOError as e:
        logger.error(f"Failed to read krb5.conf: {e}")
        return False


def _validate_krb5_config_values(config_content: str) -> None:
    """
    Parse and validate krb5.conf configuration values.

    Args:
        config_content: Content of krb5.conf file
    """
    lines = config_content.split("\n")
    current_section = None
    realms = {}
    domain_realms = {}

    for line_num, line in enumerate(lines, 1):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Check for section headers
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].lower()
            if current_section == "realms":
                realms = {}
            elif current_section == "domain_realm":
                domain_realms = {}
            continue

        # Parse key-value pairs
        if "=" in line and current_section:
            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            # Validate specific settings
            if current_section == "libdefaults":
                if key == "default_realm":
                    logger.debug(f"  default_realm: {value}")
                elif key == "clock_skew":
                    try:
                        skew_seconds = int(value)
                        logger.debug(f"  clock_skew: {skew_seconds} seconds")
                        if skew_seconds < 300:
                            logger.warning(
                                f"clock_skew is only {skew_seconds}s (recommended ≥300s for NTP issues)"
                            )
                    except ValueError:
                        pass

            elif current_section == "realms":
                # Extract realm name from indented KDC entries
                if key == "kdc":
                    logger.debug(f"  KDC: {value}")

            elif current_section == "domain_realm":
                logger.debug(f"  {key} → {value}")


def _validate_kerberos_credentials() -> bool:
    """
    Validate that Kerberos credentials are available and valid.

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        cred = GSSAPICredentials(RawCreds())
        logger.success(f"Valid Kerberos credentials found for: {cred.name}")
        return True
    except MissingCredentialsError:
        logger.error("No Kerberos credentials found in cache.")
        return False
    except ExpiredCredentialsError:
        logger.error("Kerberos credentials have expired.")
        return False
    except Exception as e:
        logger.error(f"Failed to validate Kerberos credentials: {e}")
        logger.debug(f"Exception type: {type(e).__name__}")

        # Provide helpful hints for common errors
        error_str = str(e).lower()
        if "clock skew" in error_str:
            logger.error(
                "Clock skew detected! Your system clock is out of sync with the KDC."
            )

        return False


def get_kerberos_username() -> str:
    """
    Get the username from Kerberos credentials.

    Returns:
        str: Username from credentials, or None if not available
    """
    if not IS_KERBEROS_AVAILABLE:
        return None

    try:
        cred = GSSAPICredentials(RawCreds())
        return cred.name
    except Exception as e:
        logger.error(f"Failed to get Kerberos username: {e}")
        return None
