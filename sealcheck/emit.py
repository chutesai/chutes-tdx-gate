"""Seal answers and one stream with the Python library's own sealer (seal_answer, answer_body,
StreamSealer) and print them as JSON for sealcheck/open.py (the same cases as sealcheck/emit).

    PYTHONPATH=python python3 sealcheck/emit.py > out/sealed-python.json
"""

import base64
import gzip
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from chutes_tdx_gate import e2e

ENDPOINT, INSTANCE, NOW = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40", "5813945712345678901", 1795000000000


def seal_request(pk: bytes, envelope: bytes) -> bytes:
    shared, ct = MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ct[:16], info=b"e2e-req-v2").derive(shared)
    nonce = os.urandom(12)
    return ct + nonce + ChaCha20Poly1305(key).encrypt(nonce, gzip.compress(envelope), b"chutes-e2e-v2 request")


def opened(gate: e2e.ServerKey, seed: bytes, path: str, stream: bool):
    pk = MLKEM768PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()
    env = {"v": 2, "endpoint_id": ENDPOINT, "instance_id": INSTANCE, "path": path, "stream": stream,
           "nonce": base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="), "ts": NOW,
           "e2e_response_pk": base64.b64encode(pk).decode(), "body": {"stream": stream}}
    blob = seal_request(gate.public_key, json.dumps(env).encode())
    o = e2e.open_request(gate, blob, presented_path=path, method="POST", routes=[{"path": path, "stream": stream}],
                         identity=e2e.Identity(ENDPOINT, INSTANCE), cache=e2e.ReplayCache(), now_ms=NOW)
    return o, blob


def main() -> int:
    gate, seed = e2e.ServerKey.generate(), os.urandom(64)
    out = {"form": "python", "response_seed": seed.hex(), "answers": [], "stream": {}}
    o, blob = opened(gate, seed, "/v1/answer", False)
    out["request_blob"] = base64.b64encode(blob).decode()
    for status, body in ((200, b""), (201, b"hello"), (418, '{"error":"teapot","é":"😀"}'.encode()),
                         (599, b"0123456789abcdef" * 6000)):
        wire = e2e.answer_body(e2e.seal_answer(o, status, body)).decode()
        out["answers"].append({"status": status, "body": base64.b64encode(body).decode(), "wire": wire})
    so, sblob = opened(gate, seed, "/v1/stream", True)
    sealer = e2e.StreamSealer(so)
    events = sealer.init_event() + sealer.head(200)
    data = [b'data: {"i":0}\n\n', bytes(e2e.MAX_CHUNK_DATA), b"x"]
    for chunk in data:
        events += sealer.data(chunk)
    events += sealer.end()
    out["stream"] = {"request_blob": base64.b64encode(sblob).decode(), "status": 200,
                     "data": [base64.b64encode(c).decode() for c in data], "sse": events.decode()}
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
