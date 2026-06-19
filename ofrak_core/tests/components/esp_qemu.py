"""
Test helper: assemble a bootable ESP flash image and run it under Espressif QEMU, capturing UART.

Used by the ESP PatchMaker boot tests to prove an injected/redirected patch actually executes on a
real chip model (esp32 = Xtensa, esp32c3 = RISC-V), mirroring how the x86 patch tests run the patched
binary and assert its result. The bootloader/partition-table/app artifacts are committed assets built
by ``boot/build_assets.sh`` in the official ``espressif/idf`` image (see ``boot/README.md``).
"""
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

# Espressif QEMU system emulator per chip (installed in the Docker image; see the patch_maker
# Dockerstub). The ``-M`` machine name matches the chip.
_QEMU_BIN: Dict[str, str] = {
    "esp32": "qemu-system-xtensa",
    "esp32c3": "qemu-system-riscv32",
}

# A blank eFuse backing store; Espressif QEMU memory-maps this as the efuse drive. 1 KiB of zeros is
# what ``idf.py qemu`` generates for a fresh part.
_EFUSE_SIZE = 1024

RESULT_PREFIX = "ESP_PATCH_RESULT="

# A *complete* result line: the prefix, the decimal value, and its terminator. Matching the
# terminator (not just the prefix) ensures the printed value has fully flushed before we stop QEMU.
_RESULT_LINE = re.compile(re.escape(RESULT_PREFIX.encode()) + rb"\d+[\r\n]")


def merge_flash(chip: str, app_bin: Path, asset_dir: Path, out_path: Path) -> None:
    """
    Assemble a full bootable flash image: the committed bootloader + partition table at their real
    offsets plus ``app_bin`` (the possibly-patched app) at the app offset, padded to flash size.
    Offsets and the app slot come from the committed ``flasher_args.json`` so we never hand-code
    per-chip layout. The app slot is identified by ``flasher_args``' explicit ``app`` offset (not a
    filename guess); every other flashed region is read from its committed asset by basename, so a
    future extra region with no committed file fails loudly rather than being silently filled with
    the app image.
    """
    flasher = json.loads((asset_dir / "flasher_args.json").read_text())
    flash_size = flasher["flash_settings"]["flash_size"]
    app_offset = int(flasher["app"]["offset"], 16)
    addr_file_pairs = []
    for offset, rel_name in sorted(flasher["flash_files"].items(), key=lambda kv: int(kv[0], 16)):
        src = app_bin if int(offset, 16) == app_offset else asset_dir / os.path.basename(rel_name)
        addr_file_pairs += [offset, str(src)]
    subprocess.run(
        [
            sys.executable,
            "-m",
            "esptool",
            "--chip",
            chip,
            "merge_bin",
            "-o",
            str(out_path),
            "--fill-flash-size",
            flash_size,
            *addr_file_pairs,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def boot_capture(chip: str, flash_path: Path, work_dir: Path, timeout: float = 90.0) -> str:
    """
    Boot ``flash_path`` in Espressif QEMU and return the UART output captured up to the moment the
    result line appears (or ``timeout`` elapses). The app loops forever after printing, so we stop
    QEMU ourselves rather than wait for it to exit.
    """
    qemu = _QEMU_BIN[chip]
    uart = work_dir / "uart.log"
    efuse = work_dir / "efuse.bin"
    efuse.write_bytes(b"\x00" * _EFUSE_SIZE)

    cmd = [qemu, "-M", chip]
    if chip == "esp32":
        cmd += ["-m", "4M"]
    cmd += [
        "-drive",
        f"file={flash_path},if=mtd,format=raw",
        "-drive",
        f"file={efuse},if=none,format=raw,id=efuse",
        "-global",
        f"driver=nvram.{chip}.efuse,property=drive,value=efuse",
        "-global",
        f"driver=timer.{chip}.timg,property=wdt_disable,value=true",
        "-nic",
        "user,model=open_eth",
        "-nographic",
        "-serial",
        f"file:{uart}",
    ]
    qemu_err = work_dir / "qemu.stderr"
    # `with` so the stderr handle is always closed, even if Popen below raises (no leaked fd).
    with open(qemu_err, "w+b") as proc_err:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=proc_err)
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.05)
                if uart.exists() and _RESULT_LINE.search(uart.read_bytes()):
                    break
                if proc.poll() is not None:
                    # QEMU exited on its own (e.g. it rejected the image); stop now instead of
                    # waiting out the full timeout for a result line that will never appear.
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    final = uart.read_bytes() if uart.exists() else b""
    # latin-1 maps all 256 byte values, so decoding never fails (no error handler needed).
    text = final.decode("latin-1")
    if not _RESULT_LINE.search(final):
        # No complete result line appeared: surface QEMU's own diagnostics (rejected image, bad
        # machine config, crash) instead of returning a silent partial capture that just looks empty.
        err = qemu_err.read_text(encoding="latin-1").strip()
        if err:
            text += f"\n[qemu stderr]\n{err}"
    return text


def boot_result(
    chip: str, app_bin: Path, asset_dir: Path, work_dir: Path, timeout: float = 90.0
) -> str:
    """Convenience: merge ``app_bin`` into a flash image and return the captured UART text."""
    flash = work_dir / "flash_image.bin"
    merge_flash(chip, app_bin, asset_dir, flash)
    return boot_capture(chip, flash, work_dir, timeout=timeout)
