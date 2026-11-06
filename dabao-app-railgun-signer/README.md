# Railgun signer for dabao

`railgun-signer` is a [Railgun](https://railgun.org) and Ethereum signer for a bare
[dabao](../../xous-core/apps-dabao/README.md) (Xous on a bao1x, no screen): the
Ethereum burner (`dabao-app-eth-burner`, on this repository's `dabao-burner` branch) plus the Railgun requests of the ZKNOX Ledger app
([ZKN-HW-RAILGUN](https://github.com/ZKNoxHQ/ZKN-HW-RAILGUN)). rsgun-wallet's `railgun-dabao` crate drives
it: the spending key stays on the device, the wallet's public account (shield) is its Ethereum key.

Like the burner, it has no PIN, no recovery phrase and no review. **Anyone who can reach the USB port can
sign anything and export the viewing keys: test networks and small amounts only.**

The host talks to it over a single vendor-defined USB HID interface (xous-core's
`--feature usb-bao1x/generic-hid`, on its `dabao-burner` branch) or, in the emulator, over a TCP socket.
Messages are `length (u32 BE) || type || CBOR`; see [`protocol.cddl`](protocol.cddl) (the same file as
rsgun-wallet's `crates/railgun-dabao/protocol.cddl`).

* **Seed:** the burner's. It is created on the first boot from the chip TRNG and stored in keystore
  application slots 132 and 133, in the burner's format. A dabao that ran `eth-burner` keeps its seed, and
  so its Ethereum address.
* **Ethereum:** the burner's requests, unchanged: get-address, then transactions, EIP-712 and EIP-191
  messages signed at once (ERC-4527).
* **Railgun:** keys as the Railgun engine derives them (Railway, the wallet's mnemonic signer), from the
  seed's BIP-39 seed with SLIP-0010 keyed with `"babyjubjub seed"`:
  * spending key `m/44'/1984'/0'/0'/account'`: its BabyJubJub public key, and Poseidon-EdDSA signatures
    of a transaction hash, as circomlib's `signPoseidon` (the Kohaku SDK's `kohaku-crypto`);
  * viewing key `m/420'/1984'/0'/0'/account'`: its ed25519 public key, or the key itself (export);
  * the chain-agnostic `0zk1…` address.

  These paths are not the Ledger app's (`m/44'/1984'/account'/0'/0'`); the two agree on account 0 only.
* **Boot log:** the Ethereum address at `m/44'/60'/0'/0/0` and the Railgun address of account 0
  (serial console).
* **Emulator seed:** a host file, `target/railgun-signer-seed.bin` in this crate or `$RAILGUN_SIGNER_SEED`.
  Delete it for a new seed. On the device, a new seed needs slots 132..133 erased.

## Build and run

With xous-core (branch `dabao-burner`) checked out next to `ethereum-app`, and the Xous toolchain installed
(`cargo xtask install-toolkit` in xous-core):

```sh
./build.sh               # host and device binaries (or ./build.sh emu / ./build.sh device)
cargo test --release     # protocol, seed storage, Railgun engine vectors

# emulator: only the base services (ticktimer, log, names)
cd ../../xous-core
cargo xtask dabao-emu ../ethereum-app/dabao-app-railgun-signer/target/release/railgun-signer
# in another terminal, from this directory
tools/eth_client.py get-version                      # 0.1.0 railgun-signer
tools/railgun_client.py address --account 0          # the 0zk address logged at boot
tools/railgun_client.py spending-key                 # also viewing-key, viewing-private-key
tools/railgun_client.py sign 0x1234
tools/eth_client.py sign-tx --expect <the Ethereum address logged at boot>

# device image: the app path must come before the flags
cargo xtask dabao ../ethereum-app/dabao-app-railgun-signer/target/riscv32imac-unknown-xous-elf/release/railgun-signer \
    --feature usb-bao1x/generic-hid
tools/railgun_client.py --hid address                # needs `pip install hidapi`
```

`railgun_client.py` prints what the device answers without checking it. rsgun-wallet's `railgun-dabao`
tests check it against the Railgun SDK, including against the emulator. `RAILGUN_SIGNER_PORT` changes the
emulator's TCP port (default 7600).

## Size

`apps.img` is 805 KiB (824,064 bytes). The dabao's application region is 0xDA000 bytes plus the signature block
(873 KiB). With the full `poseidon-rust` (13 widths) it was 1,041 KiB and didn't fit, so
`vendor/poseidon-rust` patches in a copy that keeps the widths the signer uses; see its README.

## Hardware tests

So far the signer has only run in the emulator. The checks to run on a real board are in xous-core's
[apps-dabao/HARDWARE-TESTS.md](../../xous-core/apps-dabao/HARDWARE-TESTS.md), section 4.

## Layout

| Path | Role |
|---|---|
| `src/main.rs` | seed creation and storage (the burner's), request handling, Ethereum signing |
| `src/railgun.rs` | Railgun key derivation, Poseidon-EdDSA, 0zk address (unit tested on the engine's vectors) |
| `src/protocol.rs` | framing, custom CBOR, HID chunking (unit tested) |
| `src/transport.rs` | HID (device) and TCP (emulator) transports; answers get-version |
| `protocol.cddl` | protocol definition |
| `vendor/poseidon-rust` | the SDK's Poseidon, trimmed to 1..5 inputs |
| `tools/eth_client.py`, `tools/ethlib.py` | Ethereum host client and its helpers |
| `tools/railgun_client.py` | Railgun host client |
