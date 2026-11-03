"""Minimal, dependency-free Ethereum helpers for the host tools: Keccak-256,
RLP encoding, secp256k1 public key recovery and EIP-55 checksums.

Independent from the device's Rust code, so the tools can check the device's
results (e.g. recover the signer of a returned signature).
"""

# ---------------------------------------------------------------- Keccak-256
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    buf = bytearray(data) + b"\x01"
    while len(buf) % rate:
        buf += b"\x00"
    buf[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(buf[off + 8 * i:off + 8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

# ---------------------------------------------------------------- RLP


def _rlp_len(n, offset):
    if n < 56:
        return bytes([offset + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(b)]) + b


def rlp(item) -> bytes:
    """RLP-encode bytes, non-negative ints and (nested) lists."""
    if isinstance(item, int):
        item = item.to_bytes((item.bit_length() + 7) // 8, "big") if item else b""
    if isinstance(item, (bytes, bytearray)):
        if len(item) == 1 and item[0] < 0x80:
            return bytes(item)
        return _rlp_len(len(item), 0x80) + bytes(item)
    payload = b"".join(rlp(x) for x in item)
    return _rlp_len(len(payload), 0xC0) + payload


# ---------------------------------------------------------------- secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def recover_address(digest: bytes, r: int, s: int, recid: int) -> str:
    """Address of the key that produced (r, s) over `digest` (EIP-55)."""
    x = r
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y & 1 != recid & 1:
        y = P - y
    rinv = pow(r, -1, N)
    e = int.from_bytes(digest, "big")
    q = _add(_mul(s * rinv % N, (x, y)), _mul((-e * rinv) % N, G))
    pub = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return checksum(keccak256(pub)[12:])


def checksum(addr20: bytes) -> str:
    h = keccak256(addr20.hex().encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(addr20.hex()))


def calldata_digest(calldata: bytes) -> str:
    """ERC-8213 Calldata Digest."""
    return "0x" + keccak256(len(calldata).to_bytes(32, "big") + calldata).hex()


# ERC-8213 example: ERC-20 transfer calldata and its digest
assert calldata_digest(bytes.fromhex(
    "a9059cbb0000000000000000000000004675c7e5baafbffbca748158becba61ef3b0a263"
    "0000000000000000000000000000000000000000000000000de0b6b3a7640000")) == \
    "0x812cee5d9cc7461c04bbcd7b70af9c28b243ac5d74d3453b008b93b7dac69985"


def eip191_digest(message: bytes) -> str:
    """ERC-8213 EIP-191 Digest (personal_sign, version 0x45)."""
    return "0x" + keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message).hex()


# ethers.js hashMessage("Hello World")
assert eip191_digest(b"Hello World") == "0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"

# Sign-In with Ethereum (EIP-4361) style message, long enough to scroll
SIWE_EXAMPLE = (
    "example.com wants you to sign in with your Ethereum account:\n"
    "0xA27DF20E6579aC472481F0Ea918165d24bFb713b\n\n"
    "I accept the ExampleOrg Terms of Service: https://example.com/tos\n\n"
    "URI: https://example.com/login\n"
    "Version: 1\n"
    "Chain ID: 1\n"
    "Nonce: 32891756\n"
    "Issued At: 2026-10-25T16:25:24Z\n"
    "Resources:\n"
    + "".join(f"- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/{i}\n" for i in range(8))
)


# ---------------------------------------------------------------- EIP-712
def _referenced(types, primary, found=None):
    found = found if found is not None else []
    if primary in found or primary not in types:
        return found
    found.append(primary)
    for f in types[primary]:
        _referenced(types, f["type"].split("[")[0], found)
    return found


def _encode_type(types, primary):
    deps = _referenced(types, primary)
    deps = [primary] + sorted(d for d in deps if d != primary)
    return "".join(f"{t}(" + ",".join(f"{f['type']} {f['name']}" for f in types[t]) + ")" for t in deps)


def _encode_value(types, typ, value):
    if typ.endswith("]"):
        inner = typ[:typ.rindex("[")]
        return keccak256(b"".join(_encode_value(types, inner, v) for v in value))
    if typ in types:
        return hash_struct(types, typ, value)
    if typ == "string":
        return keccak256(value.encode())
    if typ == "bytes":
        return keccak256(bytes.fromhex(value[2:]))
    if typ == "bool":
        return int(bool(value)).to_bytes(32, "big")
    if typ == "address":
        return int(value, 16).to_bytes(32, "big")
    if typ.startswith("bytes"):
        return bytes.fromhex(value[2:]).ljust(32, b"\0")
    if typ.startswith("uint") or typ.startswith("int"):
        n = int(value, 0) if isinstance(value, str) else int(value)
        return (n % (1 << 256)).to_bytes(32, "big")
    raise ValueError(f"unsupported EIP-712 type {typ}")


def hash_struct(types, primary, data) -> bytes:
    enc = keccak256(_encode_type(types, primary).encode())
    for f in types[primary]:
        enc += _encode_value(types, f["type"], data[f["name"]])
    return keccak256(enc)


def eip712_hashes(typed: dict):
    """(EIP-712 Digest, Domain Hash, Message Hash) as 0x-hex strings."""
    types = typed["types"]
    domain = hash_struct(types, "EIP712Domain", typed["domain"])
    message = hash_struct(types, typed["primaryType"], typed["message"])
    digest = keccak256(b"\x19\x01" + domain + message)
    return "0x" + digest.hex(), "0x" + domain.hex(), "0x" + message.hex()


MAIL_EXAMPLE = {
    "types": {
        "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                         {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
        "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"},
                 {"name": "contents", "type": "string"}],
    },
    "primaryType": "Mail",
    "domain": {"name": "Ether Mail", "version": "1", "chainId": 1,
               "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
    "message": {"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
                "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
                "contents": "Hello, Bob!"},
}

# vectors from the EIP-712 specification's example
assert eip712_hashes(MAIL_EXAMPLE) == (
    "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
    "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
    "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
)


def group_example(members: int = 12) -> dict:
    """A larger typed message (arrays of structs), long enough to scroll."""
    people = [{"name": f"Member {i}", "wallet": "0x" + f"{i + 1:040x}"} for i in range(members)]
    return {
        "types": {
            "EIP712Domain": MAIL_EXAMPLE["types"]["EIP712Domain"],
            "Person": MAIL_EXAMPLE["types"]["Person"],
            "Group": [{"name": "name", "type": "string"}, {"name": "members", "type": "Person[]"},
                      {"name": "nonce", "type": "uint256"}],
        },
        "primaryType": "Group",
        "domain": MAIL_EXAMPLE["domain"],
        "message": {"name": "burner testers", "members": people, "nonce": 42},
    }
