"""The caller's side, for the tests: build request blobs, open answers and streams."""

import base64
import gzip
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "spec", "vectors")


def load(name):
    with open(os.path.join(VECTORS, name), "rb") as stream:
        return json.load(stream)


def derive(shared, ct, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ct[:16], info=info).derive(shared)


def seal_request(pk: bytes, envelope: bytes) -> bytes:
    shared, ct = MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
    nonce = os.urandom(12)
    return ct + nonce + ChaCha20Poly1305(derive(shared, ct, b"e2e-req-v2")).encrypt(
        nonce, gzip.compress(envelope), b"chutes-e2e-v2 request")


class Caller:
    """One request's caller: its response key and, once sealed, the blob's digest."""

    def __init__(self):
        self.seed = os.urandom(64)
        self.key = MLKEM768PrivateKey.from_seed_bytes(self.seed)
        self.pk_b64 = base64.b64encode(self.key.public_key().public_bytes_raw()).decode()
        self.blob = None

    def envelope(self, *, endpoint_id, instance_id, path, stream=False, ts, body, nonce=None, **over):
        value = {"v": 2, "endpoint_id": endpoint_id, "instance_id": instance_id, "path": path, "stream": stream,
                 "nonce": nonce or base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="), "ts": ts,
                 "e2e_response_pk": self.pk_b64, "body": body}
        value.update(over)
        return value

    def seal(self, server_pk: bytes, envelope) -> bytes:
        raw = envelope if isinstance(envelope, bytes) else json.dumps(envelope, separators=(",", ":")).encode()
        self.blob = seal_request(server_pk, raw)
        return self.blob

    def open_answer(self, blob: bytes):
        return open_answer(self.key, hashlib.sha256(self.blob).digest(), blob)

    def open_sse(self, raw: bytes, presented: int):
        return open_sse(self.key, hashlib.sha256(self.blob).digest(), raw, presented)


def open_answer(key, digest, blob):
    ct, nonce, sealed = blob[:1088], blob[1088:1100], blob[1100:]
    shared = key.decapsulate(ct)
    plain = gzip.decompress(ChaCha20Poly1305(derive(shared, ct, b"e2e-resp-v2")).decrypt(
        nonce, sealed, b"chutes-e2e-v2 answer" + digest))
    head, _, body = plain.partition(b"\n")
    header = json.loads(head)
    assert set(header) == {"v", "status"} and header["v"] == 2
    return header["status"], body


def open_sse(key, digest, raw: bytes, presented: int):
    """The data of an SSE stream answer; raises AssertionError on any break of the order."""
    events = [json.loads(line[6:]) for line in raw.split(b"\n") if line.startswith(b"data: ")]
    assert "e2e_init" in events[0], "no e2e_init"
    ct = base64.b64decode(events[0]["e2e_init"])
    aead = ChaCha20Poly1305(derive(key.decapsulate(ct), ct, b"e2e-stream-v2"))
    data, expected, ended = b"", 0, False
    for event in events[1:]:
        chunk = base64.b64decode(event["e2e"])
        plain = aead.decrypt(chunk[:12], chunk[12:], b"chutes-e2e-v2 stream" + digest)
        kind, seq = struct.unpack(">BQ", plain[:9])
        assert seq == expected and not ended, "out of order"
        expected += 1
        if seq == 0:
            assert kind == 1 and json.loads(plain[9:]) == {"v": 2, "status": presented}
        elif kind == 3:
            assert plain[9:] == b""
            ended = True
        else:
            assert kind == 2
            data += plain[9:]
    assert ended, "cut short"
    return data
