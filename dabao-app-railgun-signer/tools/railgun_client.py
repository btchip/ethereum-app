#!/usr/bin/env python3
"""Railgun host client for the dabao Railgun signer (protocol.cddl, commands 3-7).

    railgun_client.py [--tcp HOST:PORT | --hid] spending-key [--account N]
    railgun_client.py [--tcp HOST:PORT | --hid] viewing-key [--account N]
    railgun_client.py [--tcp HOST:PORT | --hid] viewing-private-key [--account N]
    railgun_client.py [--tcp HOST:PORT | --hid] sign 0xHASH [--account N]
    railgun_client.py [--tcp HOST:PORT | --hid] address [--account N]

Prints what the device returns; it does not check it (no BabyJubJub or
Poseidon here): rsgun-wallet's railgun-dabao tests verify the keys, the
signatures and the address against the Railgun SDK. The Ethereum commands are
in eth_client.py, which shares the transports.
"""
import argparse, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eth_client import HidTransport, TcpTransport, hexarg, request  # noqa: E402

COMMANDS = {"spending-key": 3, "viewing-key": 4, "viewing-private-key": 5, "sign": 6, "address": 7}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcp", default="127.0.0.1:7600")
    ap.add_argument("--hid", action="store_true")
    ap.add_argument("command", choices=list(COMMANDS))
    ap.add_argument("hash", nargs="?", help="32-byte hash for sign, big-endian hex")
    ap.add_argument("--account", type=int, default=0)
    a = ap.parse_args()
    t = HidTransport() if a.hid else TcpTransport(a.tcp)
    msg = {1: COMMANDS[a.command], 3: a.account}
    if a.command == "sign":
        if not a.hash: ap.error("sign needs a hash")
        msg[4] = hexarg(a.hash).rjust(32, b"\0")
    r = request(t, msg)
    if r is None:
        sys.exit(1)
    if a.command == "spending-key":
        print("x", r[2][:32].hex())
        print("y", r[2][32:].hex())
    elif a.command == "viewing-key":
        print("public key ", r[2].hex())
    elif a.command == "viewing-private-key":
        print("private key", r[8].hex())
    elif a.command == "sign":
        s = r[9]
        print("R8.x", s[:32].hex()); print("R8.y", s[32:64].hex()); print("S   ", s[64:].hex())
    else:
        print(r[3])

if __name__ == "__main__":
    main()
