#!/usr/bin/env bash
# Build the committed bootable ESP test apps. Run inside the espressif/idf image:
#   docker run --rm -v <repo>:/work -w /work espressif/idf:release-v5.3 \
#       bash /work/ofrak_core/tests/components/assets/esp/boot/build_assets.sh
# Produces, per chip, the artifacts the OFRAK boot test assembles + boots, plus a small
# symbols.json (app_main + target addresses) used to locate the call site to redirect.
set -euxo pipefail
. "$IDF_PATH/export.sh"

BOOT=/work/ofrak_core/tests/components/assets/esp/boot
SRC="$BOOT/src"
NAME=esp_patch_demo

cd "$SRC"
for CHIP in esp32 esp32c3; do
  case "$CHIP" in
    esp32 | esp32s2 | esp32s3) NM=xtensa-esp-elf-nm ;;
    *) NM=riscv32-esp-elf-nm ;;
  esac
  rm -rf build sdkconfig
  idf.py set-target "$CHIP"
  idf.py build
  d="$BOOT/$CHIP"
  mkdir -p "$d"
  cp "build/${NAME}.bin"                         "$d/app.bin"
  cp "build/bootloader/bootloader.bin"           "$d/bootloader.bin"
  cp "build/partition_table/partition-table.bin" "$d/partition-table.bin"
  cp "build/flasher_args.json"                   "$d/flasher_args.json"
  rm -f "$d/app.elf" "$d/app.map"
  "$NM" -S "build/${NAME}.elf" | python3 -c '
import sys, json
syms = {}
for line in sys.stdin:
    p = line.split()
    if len(p) == 4 and p[3] in ("app_main", "target"):
        syms[p[3]] = {"addr": int(p[0], 16), "size": int(p[1], 16)}
assert "app_main" in syms and "target" in syms, syms
with open(sys.argv[1], "w") as f:
    json.dump(syms, f, indent=2)
    f.write("\n")
print(syms)
' "$d/symbols.json"
  ls -la "$d"
done
# The last chip leaves a generated sdkconfig in src/; it is build output, not a committed asset.
rm -f sdkconfig
echo "ASSETS_DONE"
