"""
Basic interactions with eix for package management.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from subprocess import CompletedProcess

logger = logging.getLogger(__name__)

_remote_cache_available: bool | None = None


def is_found() -> bool:
    """
    Check if eix is installed and available.
    """
    found = shutil.which("eix") is not None
    logger.debug("eix found: %s", found)
    return found


def has_cache() -> bool:
    """
    Check if eix local cache exists and is valid.
    """
    try:
        result: CompletedProcess[str] = subprocess.run(
            ["eix", "-Qq0"],
            capture_output=True,
            text=True,
            check=False,
        )
        ok = result.returncode == 0
        logger.debug("eix local cache available: %s", ok)
        return ok
    except FileNotFoundError:
        logger.warning("eix not found while checking local cache")
        return False


def has_remote_cache() -> bool:
    """
    Check if eix remote cache exists and is valid.

    Uses cached result to avoid repeated subprocess calls.
    """
    global _remote_cache_available

    if _remote_cache_available is not None:
        return _remote_cache_available

    try:
        result: CompletedProcess[str] = subprocess.run(
            ["eix", "-QRq0"],
            capture_output=True,
            text=True,
            check=False,
        )
        _remote_cache_available = result.returncode == 0
        logger.debug("eix remote cache available: %s", _remote_cache_available)
    except FileNotFoundError:
        logger.warning("eix not found while checking remote cache")
        _remote_cache_available = False

    return _remote_cache_available


def has_protobuf_support() -> bool:
    """
    Check if eix was compiled with protobuf support.
    """
    try:
        result: CompletedProcess[str] = subprocess.run(
            ["eix", "-Qq0", "--proto"],
            capture_output=True,
            text=True,
            check=False,
        )
        ok = result.returncode == 0
        logger.debug("eix protobuf support: %s", ok)
        return ok
    except FileNotFoundError:
        logger.warning("eix not found while checking protobuf support")
        return False


def eix_update() -> tuple[int, str, str]:
    """
    Update the eix local cache.

    Wraps: eix-update
    """
    logger.info("Executing: eix-update")

    try:
        result: CompletedProcess[str] = subprocess.run(
            ["eix-update"],
            capture_output=True,
            text=True,
        )
        logger.info("eix-update return code: %s", result.returncode)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError as e:
        logger.error("eix-update failed: %s", e)
        return 127, "", str(e)


def eix_remote_update() -> tuple[int, str, str]:
    """
    Update the eix remote cache.

    Wraps: eix-remote update

    Root is required only if the cache does not exist.
    """
    if has_remote_cache():
        logger.info("Executing: eix-remote update (no privilege escalation)")
        try:
            result: CompletedProcess[str] = subprocess.run(
                ["eix-remote", "update"],
                capture_output=True,
                text=True,
            )
            logger.info("eix-remote update return code: %s", result.returncode)
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError as e:
            logger.error("eix-remote failed: %s", e)
            return 127, "", str(e)

    # Cache does not exist → needs root
    logger.info("Executing: eix-remote update (privileged)")
    from carnage.core.privilege import run_privileged

    return run_privileged(
        ["eix-remote", "update"],
        backend=None,
        use_terminal=False,
    )
