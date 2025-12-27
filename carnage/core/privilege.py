"""Privilege escalation utilities."""

import shutil
import subprocess
import logging
from pathlib import Path
from subprocess import CompletedProcess
from typing import List, Tuple

from carnage.core.config import Configuration, get_config

# -------------------------
# Logging
# -------------------------

LOG_DIR = Path.home() / ".cache" / "carnage"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "carnage.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger("carnage.privilege")

# -------------------------
# Privilege backends
# -------------------------

BACKENDS: dict[str, str] = {
    "pkexec": "pkexec",
    "sudo": "sudo",
    "doas": "doas",
}


def detect_backend() -> str | None:
    for backend, cmd in BACKENDS.items():
        if shutil.which(cmd):
            log.debug("Detected backend: %s", backend)
            return backend
    log.warning("No privilege backend detected")
    return None


def get_configured_backend() -> str | None:
    config: Configuration = get_config()

    backend_raw = config.privilege_backend
    if not backend_raw:
        log.debug("No backend configured, auto-detecting")
        return detect_backend()

    backend = backend_raw.strip().lower()
    log.debug("Configured backend: %s", backend)

    if backend == "auto":
        return detect_backend()

    if backend == "none":
        return None

    if backend in BACKENDS:
        return backend

    log.warning("Invalid backend '%s', falling back to auto", backend)
    return detect_backend()


def run_privileged(
    cmd: List[str],
    backend: str | None = None,
    use_terminal: bool | None = None,
) -> Tuple[int, str, str]:

    if backend is None:
        backend = get_configured_backend()

    config: Configuration = get_config()
    terminal_cmd: List[str] = config.terminal or []

    if use_terminal is None:
        use_terminal = bool(terminal_cmd)

    full_cmd: List[str] = list(cmd)

    if backend and backend in BACKENDS:
        full_cmd = [BACKENDS[backend]] + full_cmd

    if use_terminal and terminal_cmd:
        full_cmd = terminal_cmd + full_cmd

    log.info("Executing: %s", " ".join(full_cmd))
    log.info("Backend=%s Terminal=%s", backend, use_terminal)

    try:
        result: CompletedProcess[str] = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
        )

        log.info("Return code: %d", result.returncode)

        if result.stdout:
            log.debug("STDOUT:\n%s", result.stdout)

        if result.stderr:
            log.debug("STDERR:\n%s", result.stderr)

        return result.returncode, result.stdout, result.stderr

    except Exception as e:
        log.exception("Execution failed")
        return 1, "", str(e)
