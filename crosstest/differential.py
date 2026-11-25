#!/usr/bin/env python3
"""Differential test: the SDK runtime's own ``endpoint_e2e.open_request`` (the oracle) against the
gate's Python library (and, through the corpus it writes, the Go gate) on mutated requests.

    PYTHONPATH=<SDK copy>:python python crosstest/differential.py --count 3000 --corpus OUT.json
    DIFF_CORPUS=OUT.json go test ./pkg/e2ev2 -run TestDifferentialCorpus

Every request is a valid envelope with 0 to 3 random mutations (field types and values, the
identity, ts, nonce, the response key, method and presented path, and byte-level breaks: a
duplicate key, NaN, a lone surrogate, a number at the edge of a float (an integer of 309 digits or
more, an exponent, a leading zero), trailing bytes, another gzip, another AAD, a flipped byte).
All three are fed the same requests in the same order, each with its own replay cache.

The gate is deliberately stricter than the SDK runtime in exactly these places (spec section 4.3
and strict JSON); a divergence is accepted only when the request carries one of these mutations
and the gate refuses with the listed code:

* ``body.stream`` not a JSON boolean (the SDK compares truthiness): ``e2e_v2_stream_mismatch``
* a duplicate key, a lone surrogate, a number that overflows a float, nesting deeper than 512:
  ``e2e_v2_malformed`` (strict JSON)
* a response key that fails FIPS 203's modulus check: ``e2e_v2_malformed``

Anything else that differs fails the run.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import random
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(os.path.dirname(HERE), "spec", "vectors")
NOW = 1795000000000
FLOAT_EDGE = 2 ** 1024 - 2 ** 970  # the least magnitude a float64 reads as infinity (309 digits)
ROUTES = [{"path": "/v1/compress", "stream": False}, {"path": "/v1/stream", "stream": True}]
ALLOWED = {
    "body_stream_nonbool": "e2e_v2_stream_mismatch",
    "dup_key": "e2e_v2_malformed",
    "lone_surrogate": "e2e_v2_malformed",
    "float_overflow": "e2e_v2_malformed",
    "deep": "e2e_v2_malformed",
    "pk_modulus": "e2e_v2_malformed",
}


def seal(pk, plain_gz, info=b"e2e-req-v2", aad=b"chutes-e2e-v2 request"):
    shared, ct = MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=ct[:16], info=info).derive(shared)
    nonce = os.urandom(12)
    return ct + nonce + ChaCha20Poly1305(key).encrypt(nonce, plain_gz, aad)


def generate(rng, count, pk, response_pk, identity):
    used_nonces = []
    out = []
    for i in range(count):
        route = rng.choice(ROUTES)
        nonce = base64.urlsafe_b64encode(rng.randbytes(32)).decode().rstrip("=")
        env = {"v": 2, "endpoint_id": identity[0], "instance_id": identity[1], "path": route["path"],
               "stream": route["stream"], "nonce": nonce, "ts": NOW + rng.randint(-1000, 1000),
               "e2e_response_pk": base64.b64encode(response_pk).decode(), "body": {"messages": [{"role": "user", "content": "x"}]}}
        if route["stream"]:
            env["body"]["stream"] = True
        presented, method, own = route["path"], "POST", "known"
        tags, raw_ops = [], []
        for _ in range(rng.choice((0, 1, 1, 2, 2, 3))):
            op = rng.randrange(30)
            if op == 0:
                field = rng.choice(sorted(env))
                del env[field]
                tags.append("del_" + field)
            elif op == 1:
                env[rng.choice(("x", "V", "body2", ""))] = 1
                tags.append("extra_field")
            elif op == 2:
                field = rng.choice(sorted(env))
                env[field] = rng.choice((None, True, False, 0, 1, 2, 1.5, "x", "", [], {}, "2"))
                tags.append("type_" + field)
            elif op == 3:
                env["v"] = rng.choice((1, 3, 2.0, "2", True))
                tags.append("v")
            elif op == 4:
                field = rng.choice(("endpoint_id", "instance_id"))
                env[field] = rng.choice(("other", "", "5" * 256, "5" * 257, identity[0] + "\u0007", identity[0] + "​",
                                         identity[0] + " ", "a b", "é", identity[1] + " ", "퟿"))
                tags.append("id")
            elif op == 5:
                env["path"] = rng.choice(("/v1/other", "v1/compress", "/v1/stream", "/v1/compress", "/" + "a" * 256, "/é"))
                tags.append("path")
            elif op == 6:
                env["stream"] = not env["stream"] if isinstance(env.get("stream"), bool) else True
                tags.append("stream")
            elif op == 7:
                value = rng.choice((None, True, False, 1, 0, "true", "false", [], {}, "absent"))
                if not isinstance(env.get("body"), dict):
                    env["body"] = {}
                if value == "absent":
                    env["body"].pop("stream", None)
                else:
                    env["body"]["stream"] = value
                if not isinstance(value, bool) and value != "absent":
                    tags.append("body_stream_nonbool")
                else:
                    tags.append("body_stream")
            elif op == 8:
                env["ts"] = rng.choice((NOW - 120000, NOW - 120001, NOW + 60000, NOW + 60001, float(NOW), 10 ** 25,
                                        -(10 ** 25), str(NOW), NOW - 10 ** 9))
                tags.append("ts")
            elif op == 9:
                env["nonce"] = rng.choice(("A" * 42, "A" * 44, "+" * 43, "=" * 43, "é" * 43,
                                           used_nonces[-1] if used_nonces else nonce))
                tags.append("nonce")
            elif op == 10:
                bad = bytearray(response_pk)
                choice = rng.randrange(5)
                if choice == 0:
                    env["e2e_response_pk"] = base64.b64encode(bytes(bad[:-1])).decode()
                elif choice == 1:
                    env["e2e_response_pk"] = "\n" + env["e2e_response_pk"]
                elif choice == 2:
                    env["e2e_response_pk"] = env["e2e_response_pk"].rstrip("=")
                elif choice == 3:
                    env["e2e_response_pk"] = env["e2e_response_pk"].replace("+", "-").replace("/", "_")
                else:
                    bad[0] = bad[1] = 0xFF
                    env["e2e_response_pk"] = base64.b64encode(bytes(bad)).decode()
                    tags.append("pk_modulus")
                tags.append("pk")
            elif op == 11:
                method = rng.choice(("GET", "PUT", "post", "DELETE"))
                tags.append("method")
            elif op == 12:
                presented = rng.choice(("/v1/stream", "/v1/compress", "/v1/other", "/"))
                tags.append("presented")
            elif op == 13:
                own = "unknown"
                tags.append("own")
            elif op in (14, 15):
                raw_ops.append(rng.choice(("dup_key", "big_int", "nan", "lone_surrogate", "float_overflow", "deep", "trailing",
                                           "bom", "gzip_trailing", "not_gzip", "v1_aad", "truncate", "flip", "deep_ok",
                                           "int_overflow", "number_form")))
            elif op == 16:
                if isinstance(env.get("body"), dict):
                    env["body"]["deep"] = json.loads("[" * 40 + "]" * 40)
                tags.append("body_nested")
            else:
                pass
        plain = json.dumps(env, separators=(",", ":"), ensure_ascii=False).encode()
        gz_trailing = b""
        info, aad = b"e2e-req-v2", b"chutes-e2e-v2 request"
        for rop in raw_ops:
            tags.append(rop)
            if rop == "dup_key":
                where = rng.randrange(3)
                if where == 0 and plain.startswith(b'{"v":2,'):
                    plain = b'{"v":2,' + plain[1:]  # "v" twice, same value
                elif where == 1 and b'"stream":true}' in plain:
                    plain = plain.replace(b'"stream":true}', b'"stream":false,"stream":true}', 1)
                else:
                    plain = plain.replace(b'"body":{', b'"body":{"k":1,"k":2,', 1)
            elif rop == "nan":
                plain = plain[:-1] + b',"n":NaN}'
            elif rop == "lone_surrogate":
                plain = plain[:-1] + b',"s":"\\udc00"}'
            elif rop == "big_int":
                plain = plain.replace(b'"body":{', b'"body":{"b":' + rng.choice((
                    b"18446744073709551616", b"-9223372036854775809", b"18446744073709551615", b"-9223372036854775808",
                    b"9" * 308, b"1" + b"0" * 308, str(FLOAT_EDGE - 1).encode(), str(1 - FLOAT_EDGE).encode())) + b",", 1)
            elif rop == "int_overflow":
                # No fraction and no exponent: every reader must refuse it as it refuses 1e400.
                plain = plain.replace(b'"body":{', b'"body":{"i":' + rng.choice((
                    str(FLOAT_EDGE).encode(), str(-FLOAT_EDGE).encode(), b"2" + b"0" * 308, b"9" * 309, b"-" + b"9" * 309,
                    b"1" + b"0" * 309, b"9" * 400, b"-" + b"9" * 400, b"9" * 5000)) + b",", 1)
            elif rop == "number_form":
                plain = plain.replace(b'"body":{', b'"body":{"n":' + rng.choice((
                    b"-0", b"-0.0", b"0e400", b"1e-400", b"-1e-400", b"5e-324", b"1e308", b"1.7976931348623158e308",
                    b"1.7976931348623159e308", b"1e309", b"-1E+400", b"9" * 400 + b".0", b"1" + b"0" * 399 + b"e-100",
                    b"01", b"-01", b"00", b"1.", b".5", b"1e", b"+1")) + b",", 1)
            elif rop == "float_overflow":
                plain = plain.replace(b'"body":{', b'"body":{"f":1e400,', 1)
            elif rop == "deep":
                plain = plain.replace(b'"body":{', b'"body":{"d":' + b"[" * 600 + b"]" * 600 + b",", 1)
            elif rop == "deep_ok":
                plain = plain.replace(b'"body":{', b'"body":{"d":' + b"[" * 500 + b"]" * 500 + b",", 1)
            elif rop == "trailing":
                plain += b"x"
            elif rop == "bom":
                plain = b"\xef\xbb\xbf" + plain
            elif rop == "gzip_trailing":
                gz_trailing = b"junk"
            elif rop == "v1_aad":
                info, aad = b"e2e-req-v1", None
        compressed = gzip.compress(plain, mtime=0) + gz_trailing
        if "not_gzip" in raw_ops:
            compressed = plain
        blob = seal(pk, compressed, info, aad)
        if "truncate" in raw_ops:
            blob = blob[: rng.randrange(1, 1116)]
        if "flip" in raw_ops:
            b = bytearray(blob)
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            blob = bytes(b)
        if isinstance(env.get("nonce"), str):
            used_nonces.append(env["nonce"])
        out.append({"i": i, "tags": tags, "blob_b64": base64.b64encode(blob).decode(), "presented_path": presented,
                    "method": method, "own": own, "now_ms": NOW,
                    "nonce": env.get("nonce") if isinstance(env.get("nonce"), str) else None})
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=20261116)
    parser.add_argument("--corpus", help="write the corpus and the library's results here (for the Go test)")
    args = parser.parse_args()

    from chutes.entrypoint import cpu_e2e, endpoint_e2e
    from chutes_tdx_gate import e2e as lib

    with open(os.path.join(VECTORS, "e2e_v2.json"), "rb") as stream:
        v = json.load(stream)
    seed = bytes.fromhex(v["vm_key"]["seed_d_z_hex"])
    handle = cpu_e2e.CpuE2EHandle()
    handle._pk = base64.b64decode(v["vm_key"]["public_key_b64"])
    handle._sk = base64.b64decode(v["vm_key"]["decapsulation_key_b64"])
    key = lib.ServerKey.from_seed(seed)
    assert key.public_key == handle._pk
    identity = (v["identity"]["endpoint_id"], v["identity"]["instance_id"])
    response_pk = base64.b64decode(v["response_key"]["public_key_b64"])
    rng = random.Random(args.seed)
    corpus = generate(rng, args.count, key.public_key, response_pk, identity)

    sdk_cache, lib_cache = endpoint_e2e.ReplayCache(), lib.ReplayCache()
    sdk_routes = {(r["path"], "POST", r["stream"]): r["path"] for r in ROUTES}
    lib_routes = lib.Routes([{**r, "app_path": r["path"]} for r in ROUTES])
    sdk_own = endpoint_e2e.Identity(required=True, endpoint_id=identity[0], instance_id=identity[1])
    sdk_unknown = endpoint_e2e.Identity(required=True)
    unexpected, allowed, agree = [], {}, 0
    sdk_only = set()  # nonces only the SDK admitted, in an allowed divergence: a later replay differs too
    outcomes = {}
    for case in corpus:
        blob = base64.b64decode(case["blob_b64"])
        try:
            endpoint_e2e.open_request(handle, handle.e2e_new_ctx(), blob, presented_path=case["presented_path"],
                                      method=case["method"], routes=sdk_routes, cache=sdk_cache, now_ms=case["now_ms"],
                                      own=sdk_unknown if case["own"] == "unknown" else sdk_own)
            sdk = "admitted"
        except endpoint_e2e.Refusal as exc:
            sdk = exc.code
        except Exception as exc:  # noqa: BLE001 - an SDK crash is recorded, never a pass
            sdk = "sdk_error:" + type(exc).__name__
        try:
            lib.open_request(key, blob, presented_path=case["presented_path"], method=case["method"], routes=lib_routes,
                             identity=lib.Identity() if case["own"] == "unknown" else lib.Identity(*identity),
                             cache=lib_cache, now_ms=case["now_ms"])
            got = "admitted"
        except lib.Refusal as exc:
            got = exc.code
        case["sdk"], case["lib"] = sdk, got
        outcomes[got] = outcomes.get(got, 0) + 1
        if sdk == got:
            agree += 1
            continue
        reason = next((t for t in case["tags"] if t in ALLOWED and ALLOWED[t] == got), None)
        if reason is None and sdk == "e2e_v2_replayed" and got == "admitted" and case["nonce"] in sdk_only:
            reason = "replay_after_allowed"
        if reason is not None and sdk == "admitted" and case["nonce"]:
            sdk_only.add(case["nonce"])
        if reason is None:
            unexpected.append(case)
        else:
            allowed[reason] = allowed.get(reason, 0) + 1
    print(f"{len(corpus)} requests: {agree} agree with the SDK runtime; allowed (gate stricter): {allowed}; "
          f"unexpected: {len(unexpected)}")
    print("library outcomes:", dict(sorted(outcomes.items())))
    for case in unexpected[:20]:
        print("  UNEXPECTED", case["i"], case["tags"], "sdk", case["sdk"], "lib", case["lib"])
    if args.corpus:
        with open(args.corpus, "w") as stream:
            json.dump({"seed_d_z_hex": seed.hex(), "identity": identity, "routes": ROUTES, "cases": corpus}, stream)
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
