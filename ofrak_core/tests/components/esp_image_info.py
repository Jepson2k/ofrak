"""
Shared test helper: independently validate an ESP app image with esptool's ``image_info`` (a pinned
test dependency). Used by both the ESP app-component tests and the patch-from-source tests.
"""
import os
import subprocess
import sys
import tempfile
from typing import Optional


def verify_with_esptool(data: bytes, chip: Optional[str] = None, has_hash: bool = True) -> None:
    """
    Confirm esptool accepts ``data`` as a valid ESP app image. Pass ``chip`` to validate against a
    specific target (esptool's ``--chip``); set ``has_hash=False`` for formats without an appended
    SHA256 (e.g. ESP8266 v1/v2, which use a CRC32 or nothing).
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
        temp_file.write(data)
        temp_file.flush()
        temp_path = temp_file.name

    try:
        cmd = [sys.executable, "-m", "esptool"]
        if chip is not None:
            cmd += ["--chip", chip]
        cmd += ["image_info", "--version", "2", temp_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        assert result.returncode == 0, f"esptool rejected the image:\n{result.stderr}"

        output = result.stdout
        assert "Checksum:" in output, "esptool output should contain checksum information"
        assert "invalid" not in output.lower(), "Checksum should not be invalid"

        if has_hash:
            assert any(
                word in output.lower() for word in ["hash", "digest", "sha256"]
            ), "Output should contain hash information for images with an appended SHA256"

    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
