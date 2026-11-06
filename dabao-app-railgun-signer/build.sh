#!/bin/bash
# Build the dabao Railgun signer, for the emulator and/or the device.
# Expects xous-core checked out next to ethereum-app (../../xous-core) and the
# Xous toolchain installed (`cargo xtask install-toolkit` in xous-core).
#   ./build.sh emu     host binary for `cargo xtask dabao-emu`
#   ./build.sh device  riscv binary for `cargo xtask dabao`
#   ./build.sh         both
set -e
cd "$(dirname "$0")"
what=${1:-all}
case "$what" in
    emu|device|all) ;;
    *) echo "usage: $0 [emu|device|all]" >&2; exit 2 ;;
esac
if [ "$what" = emu ] || [ "$what" = all ]; then
    cargo build --release
    echo "emulator binary: $(pwd)/target/release/railgun-signer"
fi
if [ "$what" = device ] || [ "$what" = all ]; then
    cargo build --release --target riscv32imac-unknown-xous-elf --features board-dabao,bao1x
    echo "device binary: $(pwd)/target/riscv32imac-unknown-xous-elf/release/railgun-signer"
fi
