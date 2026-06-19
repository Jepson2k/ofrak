# ESP bootable test apps

Minimal ESP-IDF apps used by `tests/components/test_esp_patch_from_source.py` to prove the ESP patch
flow end to end: unpack the flash image, redirect an existing call to an injected patch, repack, and
boot in Espressif QEMU to confirm the printed value changed (`target(7)=7` → `esp_patch_entry(7)=70`).

- `src/` (app source) is written for this repo and released under the OFRAK license.
- `bootloader.bin` / `partition-table.bin` are ESP-IDF build outputs (Espressif, Apache-2.0); `app.bin`
  is the compiled `src/`; `flasher_args.json` / `symbols.json` are build metadata. No third-party
  application code is included.

Rebuild (no host ESP-IDF needed):

    docker run --rm -v <repo>:/work -w /work espressif/idf:release-v5.3 \
        bash /work/ofrak_core/tests/components/assets/esp/boot/build_assets.sh

`build_assets.sh` builds for esp32 (Xtensa) and esp32c3 (RISC-V) and copies out, per chip, `app.bin`,
`bootloader.bin`, `partition-table.bin`, `flasher_args.json`, and `symbols.json` (the `app_main` /
`target` addresses the test uses to locate the call to redirect).
