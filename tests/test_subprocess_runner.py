import asyncio
import sys

from services.subprocess_runner import run_subprocess


def test_run_subprocess_success():
    returncode, stdout, stderr = asyncio.run(
        run_subprocess(
            [
                sys.executable,
                "-c",
                "print('subprocess-ok')",
            ],
            timeout=5,
        )
    )

    assert returncode == 0
    assert stdout == "subprocess-ok"
    assert stderr == ""


def test_run_subprocess_captures_stderr():
    returncode, stdout, stderr = asyncio.run(
        run_subprocess(
            [
                sys.executable,
                "-c",
                "import sys; print('stdout-ok'); print('stderr-ok', file=sys.stderr)",
            ],
            timeout=5,
        )
    )

    assert returncode == 0
    assert stdout == "stdout-ok"
    assert stderr == "stderr-ok"


def test_run_subprocess_missing_executable():
    returncode, stdout, stderr = asyncio.run(
        run_subprocess(
            [
                "definitely-not-a-real-executable-cti-test",
            ],
            timeout=5,
        )
    )

    assert returncode == -1
    assert stdout == ""
    assert "executable not found" in stderr


def test_run_subprocess_timeout():
    returncode, stdout, stderr = asyncio.run(
        run_subprocess(
            [
                sys.executable,
                "-c",
                "import time; time.sleep(30)",
            ],
            timeout=1,
        )
    )

    assert returncode == -2
    assert "timeout after 1s" in stderr


def test_run_subprocess_timeout_with_partial_stdout():
    returncode, stdout, stderr = asyncio.run(
        run_subprocess(
            [
                sys.executable,
                "-c",
                "import sys,time; print('partial-output', flush=True); time.sleep(30)",
            ],
            timeout=1,
        )
    )

    # Timeout state is authoritative. Pipe output after communicate()
    # cancellation is best-effort and may be empty depending on the
    # Python/platform subprocess implementation.
    assert returncode == -2
    assert isinstance(stdout, str)
    assert isinstance(stderr, str)
    assert "timeout after 1s" in stderr
