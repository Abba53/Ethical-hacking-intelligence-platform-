"""
services/subprocess_runner.py

Shared asynchronous subprocess execution utility.

Return-code contract:
    >= 0 : process exited normally
    -2   : process timed out
    -1   : execution failure / executable unavailable

Authorization is intentionally NOT handled here.
Authorization remains the responsibility of the calling security service.
"""

import asyncio
import logging

logger = logging.getLogger(__name__)


async def run_subprocess(
    cmd: list[str],
    timeout: int,
) -> tuple[int, str, str]:
    """
    Execute a local CLI command asynchronously.

    Returns:
        (returncode, stdout, stderr)

    Return-code contract:
        >= 0 : normal process exit
        -2   : timeout
        -1   : execution error
    """

    if not cmd:
        return -1, "", "empty command"

    if timeout <= 0:
        return -1, "", "timeout must be greater than zero"

    proc = None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            return (
                proc.returncode,
                stdout.decode("utf-8", errors="replace").strip(),
                stderr.decode("utf-8", errors="replace").strip(),
            )

        except asyncio.TimeoutError:
            logger.warning(
                "Subprocess timed out after %ss: %s",
                timeout,
                " ".join(cmd[:3]),
            )

            # The communicate() coroutine may have been cancelled by
            # wait_for(). We must still terminate and reap the process.
            try:
                if proc.returncode is None:
                    proc.terminate()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.debug(
                    "Subprocess terminate failed: %s",
                    exc,
                )

            # Give the process a short grace period.
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=5,
                )

            except asyncio.TimeoutError:
                logger.warning(
                    "Subprocess did not terminate gracefully; killing: %s",
                    " ".join(cmd[:3]),
                )

                try:
                    if proc.returncode is None:
                        proc.kill()
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    logger.debug(
                        "Subprocess kill failed: %s",
                        exc,
                    )

                # Always reap the child.
                try:
                    stdout, stderr = await proc.communicate()
                except Exception:
                    stdout, stderr = b"", b""

            except Exception as exc:
                logger.debug(
                    "Subprocess communicate after timeout failed: %s",
                    exc,
                )
                stdout, stderr = b"", b""

            return (
                -2,
                stdout.decode("utf-8", errors="replace").strip(),
                (
                    stderr.decode("utf-8", errors="replace").strip()
                    or f"timeout after {timeout}s"
                ),
            )

    except FileNotFoundError:
        executable = cmd[0]

        logger.error(
            "Subprocess executable not found: %s",
            executable,
        )

        return (
            -1,
            "",
            f"executable not found: {executable}",
        )

    except Exception as exc:
        logger.exception(
            "Subprocess execution error: %s",
            " ".join(cmd[:3]),
        )

        if proc is not None:
            try:
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
            except Exception:
                pass

        return -1, "", str(exc)
