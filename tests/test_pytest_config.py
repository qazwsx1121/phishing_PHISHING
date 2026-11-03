import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_collection_output_has_no_third_party_deprecation_warning():
    """The starlette TestClient/httpx deprecation notice is filtered in pyproject.toml.

    Runs a fresh pytest process (collect-only, so this test is not re-run) because the
    warning is emitted when ``fastapi.testclient`` is first imported by ``conftest.py``.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "StarletteDeprecationWarning" not in output, output
    assert "warnings summary" not in output, output
