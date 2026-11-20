"""Open what a gate sealed with code that shares nothing with it, and check every byte.

    python3 sealcheck/open.py out/sealed-go.json out/sealed-python.json

The input is sealcheck/emit (the Go gate's SealAnswer and StreamSealer) or sealcheck/emit.py (the
Python library's seal_answer and StreamSealer). This file uses the standard library and
spec/vectors/mlkem768.py (FIPS 203, pure Python) only: HKDF-SHA256 and ChaCha20-Poly1305 are
written out below. For each answer: the wire body is exactly {"e2e":"<B64>"}; the blob is
mlkem_ct || nonce || ct || tag to the response key, HKDF info "e2e-resp-v2" with salt mlkem_ct[:16],
AAD "chutes-e2e-v2 answer" || SHA-256(request blob); the plaintext is one gzip member holding
{"v":2,"status":S} "\\n" body. For the stream: e2e_init, then the head (kind 1, seq 0), the data
chunks (kind 2) and one end (kind 3), info "e2e-stream-v2", AAD "chutes-e2e-v2 stream" ||
SHA-256(request blob). A flipped byte, a wrong request digest and a reordering must each fail.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spec", "vectors"))
sys.dont_write_bytecode = True
import mlkem768  # noqa: E402

MASK = 0xFFFFFFFF


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block = b"", b""
    for i in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
    return out[:length]


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]
    s[d] = ((s[d] << 16) | (s[d] >> 16)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]
    s[b] = ((s[b] << 12) | (s[b] >> 20)) & MASK
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]
    s[d] = ((s[d] << 8) | (s[d] >> 24)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]
    s[b] = ((s[b] << 7) | (s[b] >> 25)) & MASK


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """RFC 8439 section 2.3."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, *struct.unpack("<8I", key), counter,
             *struct.unpack("<3I", nonce)]
    w = list(state)
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12)
        _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14)
        _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15)
        _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13)
        _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + state[i]) & MASK for i in range(16)])


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        stream = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], stream))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    """RFC 8439 section 2.5."""
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def aead_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305 (RFC 8439 section 2.8); ValueError when the tag does not verify."""
    if len(sealed) < 16:
        raise ValueError("short")
    ct, tag = sealed[:-16], sealed[-16:]

    def pad(x):
        return b"\x00" * (-len(x) % 16)
    mac_data = aad + pad(aad) + ct + pad(ct) + struct.pack("<QQ", len(aad), len(ct))
    if not hmac.compare_digest(poly1305(chacha20_block(key, 0, nonce)[:32], mac_data), tag):
        raise ValueError("tag")
    return chacha20(key, 1, nonce, ct)


def response_key(seed_hex: str) -> bytes:
    seed = bytes.fromhex(seed_hex)
    return mlkem768.keygen(seed[:32], seed[32:])[1]


def open_answer(dk: bytes, request_blob: bytes, blob: bytes):
    ct, nonce, sealed = blob[:1088], blob[1088:1100], blob[1100:]
    key = hkdf_sha256(mlkem768.decaps(dk, ct), ct[:16], b"e2e-resp-v2")
    plain = aead_open(key, nonce, sealed, b"chutes-e2e-v2 answer" + hashlib.sha256(request_blob).digest())
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    member = inflater.decompress(plain)
    if not inflater.eof or inflater.unused_data:
        raise ValueError("not exactly one gzip member")
    head, sep, body = member.partition(b"\n")
    header = json.loads(head)
    if not sep or set(header) != {"v", "status"} or header["v"] != 2 or head != b'{"v":2,"status":%d}' % header["status"]:
        raise ValueError(f"bad status header {head!r}")
    return header["status"], body


def open_stream(dk: bytes, request_blob: bytes, sse: str):
    lines = sse.split("\n\n")
    if lines[-1] != "":
        raise ValueError("the stream does not end with a blank line")
    events = []
    for line in lines[:-1]:
        if not line.startswith("data: ") or "\n" in line:
            raise ValueError(f"not one data line: {line[:40]!r}")
        event = json.loads(line[6:])
        if len(event) != 1 or line != 'data: {"%s":"%s"}' % (next(iter(event)), next(iter(event.values()))):
            raise ValueError("not an exact event")
        events.append(event)
    ct = base64.b64decode(events[0]["e2e_init"], validate=True)
    key = hkdf_sha256(mlkem768.decaps(dk, ct), ct[:16], b"e2e-stream-v2")
    aad = b"chutes-e2e-v2 stream" + hashlib.sha256(request_blob).digest()
    status, data, ended = None, [], False
    for seq, event in enumerate(events[1:]):
        raw = base64.b64decode(event["e2e"], validate=True)
        plain = aead_open(key, raw[:12], raw[12:], aad)
        kind, got_seq = plain[0], struct.unpack(">Q", plain[1:9])[0]
        payload = plain[9:]
        if got_seq != seq or ended:
            raise ValueError("order")
        if seq == 0:
            if kind != 1:
                raise ValueError("no head")
            status = json.loads(payload)["status"]
            if payload != b'{"v":2,"status":%d}' % status:
                raise ValueError("bad head")
        elif kind == 2:
            if len(payload) > 65536:
                raise ValueError("data chunk over 64 KiB")
            data.append(payload)
        elif kind == 3:
            if payload:
                raise ValueError("end with data")
            ended = True
        else:
            raise ValueError("kind")
    if not ended:
        raise ValueError("no end")
    return status, data


def flip(b64: str, at: int) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[at % len(raw)] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def fails(fn, *args) -> bool:
    try:
        fn(*args)
    except (ValueError, KeyError, IndexError, zlib.error, json.JSONDecodeError):
        return True
    return False


def check(doc) -> int:
    dk = response_key(doc["response_seed"])
    request_blob = base64.b64decode(doc["request_blob"])
    checks = 0
    for a in doc["answers"]:
        wire = a["wire"]
        assert wire.startswith('{"e2e":"') and wire.endswith('"}') and json.loads(wire).keys() == {"e2e"}, "wire body"
        b64 = json.loads(wire)["e2e"]
        assert wire == '{"e2e":"' + b64 + '"}', "wire body not exact"
        blob = base64.b64decode(b64, validate=True)
        status, body = open_answer(dk, request_blob, blob)
        assert (status, body) == (a["status"], base64.b64decode(a["body"])), f"answer {a['status']}"
        for at in (5, 1090, 1105, -3):  # mlkem_ct, nonce, ciphertext, tag
            assert fails(open_answer, dk, request_blob, base64.b64decode(flip(b64, at))), f"a flipped byte at {at} opened"
        assert fails(open_answer, dk, request_blob + b"x", blob), "another request's digest opened"
        checks += 7
    s = doc["stream"]
    stream_blob = base64.b64decode(s["request_blob"])
    status, data = open_stream(dk, stream_blob, s["sse"])
    assert status == s["status"] and data == [base64.b64decode(x) for x in s["data"]], "stream data"
    assert fails(open_stream, dk, stream_blob + b"x", s["sse"]), "the stream opened for another request"
    lines = s["sse"].split("\n\n")
    swapped = "\n\n".join(lines[:2] + [lines[3], lines[2]] + lines[4:])
    assert fails(open_stream, dk, stream_blob, swapped), "a reordered stream opened"
    dropped = "\n\n".join(lines[:-2] + [lines[-1]])
    assert fails(open_stream, dk, stream_blob, dropped), "a stream without its end opened"
    return checks + 4


def main(paths) -> int:
    total = 0
    for path in paths:
        with open(path, "rb") as stream:
            doc = json.load(stream)
        n = check(doc)
        print(f"sealcheck {doc['form']}: {len(doc['answers'])} answers and one stream opened independently ({n} checks)")
        total += n
    print(f"sealcheck: {total} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
