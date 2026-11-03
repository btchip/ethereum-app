#!/usr/bin/env python3
"""Host client for the dabao Ethereum burner (protocol.cddl).

    eth_client.py [--tcp HOST:PORT | --hid] get-version
    eth_client.py [--tcp HOST:PORT | --hid] get-address "m/44'/60'/0'/0/0"
    eth_client.py [--tcp HOST:PORT | --hid] sign-tx [--legacy] [--chain-id 1] [--to 0x..]
                  [--value-wei N] [--data 0x..] [--path ..] [--expect 0x..]
    eth_client.py [--tcp HOST:PORT | --hid] sign-typed-data [mail | group | FILE.json] [--path ..] [--expect 0x..]
    eth_client.py [--tcp HOST:PORT | --hid] sign-message [TEXT | siwe | 0xHEX] [--path ..] [--expect 0x..]
    eth_client.py calldata-digest 0x...

sign-tx sends an ERC-4527 eth-sign-request (EIP-1559 by default, or legacy
EIP-155), decodes the eth-signature and recovers the signer from it with an
independent secp256k1 implementation (tools/ethlib.py).

--tcp (default 127.0.0.1:7600) talks to the emulator; --hid needs the
`hidapi` Python package and talks to the device (vendor HID, 64-byte reports).
No other dependencies: a minimal CBOR encoder/decoder is included.
"""
import argparse, json, os, socket, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ethlib  # noqa: E402

TYPE_ERC4527 = 0x01
TYPE_CUSTOM = 0x02
ERRORS = {1: "user-rejected", 2: "invalid-request", 3: "unsupported", 4: "busy", 5: "internal", 6: "not-ready"}

# ---------------------------------------------------------------- CBOR (subset)
def _head(major, n):
    if n < 24: return bytes([major << 5 | n])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, n)

class Tag:
    def __init__(self, tag, value): self.tag, self.value = tag, value

def cbor_encode(v):
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes): return _head(2, len(v)) + v
    if isinstance(v, str): b = v.encode(); return _head(3, len(b)) + b
    if isinstance(v, list): return _head(4, len(v)) + b"".join(map(cbor_encode, v))
    if isinstance(v, dict): return _head(5, len(v)) + b"".join(cbor_encode(k) + cbor_encode(x) for k, x in v.items())
    if isinstance(v, Tag): return _head(6, v.tag) + cbor_encode(v.value)
    raise TypeError(v)

def cbor_decode(b, i=0):
    ib = b[i]; major, ai = ib >> 5, ib & 31; i += 1
    if ai < 24: n = ai
    else:
        size = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
        n = int.from_bytes(b[i:i + size], "big"); i += size
    if major == 0: return n, i
    if major == 1: return -1 - n, i
    if major in (2, 3):
        d = b[i:i + n]; return (d if major == 2 else d.decode()), i + n
    if major == 4:
        out = []
        for _ in range(n): x, i = cbor_decode(b, i); out.append(x)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n): k, i = cbor_decode(b, i); out[k], i = cbor_decode(b, i)
        return out, i
    if major == 6: x, i = cbor_decode(b, i); return Tag(n, x), i
    if major == 7: return {20: False, 21: True, 22: None}[ai], i
    raise ValueError("unsupported CBOR")

# ---------------------------------------------------------------- transports
def frame(ty, msg): return struct.pack(">I", len(msg) + 1) + bytes([ty]) + msg

class TcpTransport:
    def __init__(self, addr):
        host, port = addr.rsplit(":", 1)
        self.s = socket.create_connection((host, int(port)))
    def exchange(self, data):
        self.s.sendall(data)
        n = struct.unpack(">I", self._read(4))[0]
        return self._read(n)
    def _read(self, n):
        out = b""
        while len(out) < n:
            chunk = self.s.recv(n - len(out))
            if not chunk: raise ConnectionError("device closed the connection")
            out += chunk
        return out

class HidTransport:
    VID, PID = 0x1D50, 0x6197
    def __init__(self):
        import hid
        self.d = hid.device(); self.d.open(self.VID, self.PID)
    def exchange(self, data):
        for off in range(0, len(data), 64):
            chunk = data[off:off + 64].ljust(64, b"\0")
            self.d.write(b"\0" + chunk)  # report id 0
        buf = bytes(self.d.read(64, 0))
        n = struct.unpack(">I", buf[:4])[0]
        while len(buf) < 4 + n: buf += bytes(self.d.read(64, 0))
        return buf[4:4 + n]

# ---------------------------------------------------------------- commands
def keypath(path):
    comps = []
    for c in path.split("/")[1:]:
        comps += [int(c.rstrip("'h")), c.endswith("'") or c.endswith("h")]
    return Tag(304, {1: comps})

def request(t, msg):
    body = t.exchange(frame(TYPE_CUSTOM, cbor_encode(msg)))
    return check(body)

def check(body):
    """Decode a reply body; print and return None on an error-response."""
    resp, _ = cbor_decode(body[1:])
    if body[0] == TYPE_CUSTOM and resp.get(1) != 0:
        code = resp.get(1)
        print(f"error {code} ({ERRORS.get(code, '?')}): {resp.get(6, '')}")
        return None
    return resp

def hexarg(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)

def sign_tx(t, a):
    to, data = hexarg(a.to), hexarg(a.data)
    if a.legacy:
        # EIP-155 unsigned legacy: rlp([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])
        sign_data = ethlib.rlp([a.nonce, 20 * 10**9, a.gas, to, a.value_wei, data, a.chain_id, 0, 0])
        data_type = 1
    else:
        # EIP-1559: 0x02 || rlp([chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList])
        sign_data = b"\x02" + ethlib.rlp([a.chain_id, a.nonce, 10**9, 20 * 10**9, a.gas, to, a.value_wei, data, []])
        data_type = 4
    request_id = os.urandom(16)
    req = {1: Tag(37, request_id), 2: sign_data, 3: data_type, 4: a.chain_id, 5: keypath(a.path), 7: "eth_client"}
    if a.address:
        req[6] = hexarg(a.address)
    body = t.exchange(frame(TYPE_ERC4527, cbor_encode(req)))
    resp = check(body)
    if resp is None:
        return None
    if body[0] != TYPE_ERC4527:
        print("unexpected reply type", body[0]); return None
    rid = resp.get(1)
    if not isinstance(rid, Tag) or rid.value != request_id:
        print("request-id not echoed"); return None
    sig = resp[2]
    r, s_, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), int.from_bytes(sig[64:], "big")
    recid = v - 35 - 2 * a.chain_id if a.legacy else v
    signer = ethlib.recover_address(ethlib.keccak256(sign_data), r, s_, recid)
    print("signature ", sig.hex())
    print("v         ", v)
    print("signer    ", signer)
    if a.expect and a.expect.lower() != signer.lower():
        print("MISMATCH: expected", a.expect); return None
    return resp

def sign_typed_data(t, a):
    src = a.arg or "mail"
    if src == "mail":
        typed = ethlib.MAIL_EXAMPLE
    elif src == "group":
        typed = ethlib.group_example()
    else:
        typed = json.load(open(src))
    digest, domain, message = ethlib.eip712_hashes(typed)
    print("expected EIP-712 Digest", digest)
    print("expected Domain Hash   ", domain)
    print("expected Message Hash  ", message)
    request_id = os.urandom(16)
    req = {1: Tag(37, request_id), 2: json.dumps(typed).encode(), 3: 2, 5: keypath(a.path), 7: "eth_client"}
    if a.address:
        req[6] = hexarg(a.address)
    body = t.exchange(frame(TYPE_ERC4527, cbor_encode(req)))
    resp = check(body)
    if resp is None:
        return None
    rid = resp.get(1)
    if body[0] != TYPE_ERC4527 or not isinstance(rid, Tag) or rid.value != request_id:
        print("bad eth-signature reply"); return None
    sig = resp[2]
    r, s_, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), int.from_bytes(sig[64:], "big")
    signer = ethlib.recover_address(bytes.fromhex(digest[2:]), r, s_, v - 27)
    print("signature ", sig.hex())
    print("v         ", v)
    print("signer    ", signer)
    if a.expect and a.expect.lower() != signer.lower():
        print("MISMATCH: expected", a.expect); return None
    return resp

def message_arg(arg):
    """sign-message input: 0x-hex bytes, the SIWE example, or UTF-8 text
    (Python escapes such as \\n or \\u00e9 are interpreted)."""
    if arg is None or arg == "siwe":
        return ethlib.SIWE_EXAMPLE.encode()
    if arg.startswith("0x"):
        return hexarg(arg)
    return arg.encode("latin-1", "backslashreplace").decode("unicode_escape").encode()

def sign_message(t, a):
    message = message_arg(a.arg)
    digest = ethlib.eip191_digest(message)
    print("expected EIP-191 Digest", digest)
    request_id = os.urandom(16)
    req = {1: Tag(37, request_id), 2: message, 3: 3, 5: keypath(a.path), 7: "eth_client"}
    if a.address:
        req[6] = hexarg(a.address)
    body = t.exchange(frame(TYPE_ERC4527, cbor_encode(req)))
    resp = check(body)
    if resp is None:
        return None
    rid = resp.get(1)
    if body[0] != TYPE_ERC4527 or not isinstance(rid, Tag) or rid.value != request_id:
        print("bad eth-signature reply"); return None
    sig = resp[2]
    r, s_, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), int.from_bytes(sig[64:], "big")
    signer = ethlib.recover_address(bytes.fromhex(digest[2:]), r, s_, v - 27)
    print("signature ", sig.hex())
    print("v         ", v)
    print("signer    ", signer)
    if a.expect and a.expect.lower() != signer.lower():
        print("MISMATCH: expected", a.expect); return None
    return resp

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcp", default="127.0.0.1:7600")
    ap.add_argument("--hid", action="store_true")
    ap.add_argument("command", choices=["get-version", "get-address", "sign-tx", "sign-typed-data", "sign-message",
                                         "calldata-digest"])
    ap.add_argument("arg", nargs="?", help="path for get-address, calldata for calldata-digest, "
                    "typed data for sign-typed-data (mail, group or a JSON file), "
                    "message for sign-message (text, siwe or 0x-hex)")
    ap.add_argument("--path", default="m/44'/60'/0'/0/0")
    ap.add_argument("--legacy", action="store_true")
    ap.add_argument("--chain-id", type=int, default=1)
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--gas", type=int, default=21000)
    ap.add_argument("--to", default="0x4675C7e5BaAFBFFbca748158bEcBA61ef3b0a263")
    ap.add_argument("--value-wei", type=int, default=10**16)
    ap.add_argument("--data", default="")
    ap.add_argument("--address", help="declared signer address in the request (key 6)")
    ap.add_argument("--expect", help="address the recovered signer must equal")
    a = ap.parse_args()
    if a.command == "calldata-digest":
        print(ethlib.calldata_digest(hexarg(a.arg or "")))
        return
    t = HidTransport() if a.hid else TcpTransport(a.tcp)
    if a.command == "get-version":
        r = request(t, {1: 2})
        if r: print("version", r[5])
    elif a.command == "get-address":
        r = request(t, {1: 1, 2: keypath(a.arg or a.path)})
        if r:
            print("public key", r[2].hex())
            print("address   ", r[3])
            print("chain code", r[4].hex())
    elif a.command == "sign-message":
        r = sign_message(t, a)
    elif a.command == "sign-typed-data":
        r = sign_typed_data(t, a)
    else:
        r = sign_tx(t, a)
    sys.exit(0 if r else 1)

if __name__ == "__main__":
    main()
