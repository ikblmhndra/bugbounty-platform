"""
Utilities for executing external shell commands with timeout, logging, and error handling.
All tool execution is routed through these helpers to ensure consistency.
"""
import asyncio
import shlex
import subprocess
from typing import Optional

from app.utils.logging import get_logger

logger = get_logger(__name__)


class CommandResult:
    """Result from a shell command execution."""

    def __init__(
        self,
        command: str,
        returncode: int,
        stdout: str,
        stderr: str,
        timed_out: bool = False,
    ):
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.success = returncode == 0 and not timed_out

    def lines(self) -> list[str]:
        """Return non-empty lines from stdout."""
        return [line.strip() for line in self.stdout.splitlines() if line.strip()]

    def __repr__(self) -> str:
        return (
            f"CommandResult(cmd={self.command!r}, rc={self.returncode}, "
            f"lines={len(self.lines())}, timed_out={self.timed_out})"
        )


def run_command(
    command: list[str] | str,
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    max_output_bytes: int = 1024 * 1024,
) -> CommandResult:
    """
    Run a shell command synchronously (for Celery workers).

    Args:
        command: Command as list of args or a string (will be split).
        timeout: Max execution time in seconds.
        cwd: Working directory.
        env: Additional environment variables.

    Returns:
        CommandResult with stdout, stderr, returncode.
    """
    if isinstance(command, str):
        command = shlex.split(command)
    if not isinstance(command, list) or not command:
        return CommandResult(command="", returncode=-1, stdout="", stderr="Invalid command")
    if any(("\n" in c or "\r" in c) for c in command):
        return CommandResult(command=" ".join(command), returncode=-1, stdout="", stderr="Invalid command input")

    cmd_str = " ".join(command)
    logger.info("Running command", command=cmd_str, timeout=timeout)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        logger.debug(
            "Command completed",
            command=cmd_str,
            returncode=result.returncode,
            stdout_lines=len(result.stdout.splitlines()),
        )
        stdout = result.stdout[:max_output_bytes]
        stderr = result.stderr[:max_output_bytes]
        return CommandResult(
            command=cmd_str,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    except subprocess.TimeoutExpired as e:
        logger.warning("Command timed out", command=cmd_str, timeout=timeout)
        return CommandResult(
            command=cmd_str,
            returncode=-1,
            stdout=e.stdout.decode() if e.stdout else "",
            stderr=e.stderr.decode() if e.stderr else "",
            timed_out=True,
        )
    except FileNotFoundError:
        logger.error("Command not found", command=command[0])
        return CommandResult(
            command=cmd_str,
            returncode=127,
            stdout="",
            stderr=f"Command not found: {command[0]}",
        )
    except Exception as e:
        logger.exception("Unexpected error running command", command=cmd_str, error=str(e))
        return CommandResult(
            command=cmd_str,
            returncode=-1,
            stdout="",
            stderr=str(e),
        )


async def run_command_async(
    command: list[str] | str,
    timeout: int = 300,
    cwd: Optional[str] = None,
) -> CommandResult:
    """
    Run a shell command asynchronously (for FastAPI endpoints if needed).
    """
    if isinstance(command, str):
        command = shlex.split(command)

    cmd_str = " ".join(command)
    logger.info("Running async command", command=cmd_str)

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await proc.communicate()
            return CommandResult(
                command=cmd_str,
                returncode=-1,
                stdout=stdout.decode(),
                stderr=stderr.decode(),
                timed_out=True,
            )

        return CommandResult(
            command=cmd_str,
            returncode=proc.returncode or 0,
            stdout=stdout.decode(),
            stderr=stderr.decode(),
        )
    except FileNotFoundError:
        return CommandResult(
            command=cmd_str,
            returncode=127,
            stdout="",
            stderr=f"Command not found: {command[0]}",
        )
    except Exception as e:
        logger.exception("Async command error", command=cmd_str, error=str(e))
        return CommandResult(
            command=cmd_str,
            returncode=-1,
            stdout="",
            stderr=str(e),
        )


def check_tool_available(tool_path: str) -> bool:
    """Check whether a tool binary is available and executable."""
    result = run_command(["which", tool_path], timeout=5)
    return result.success
