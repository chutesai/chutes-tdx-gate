"""Every vector the gate consumes (spec/vectors), through the Python library."""

import base64
import hashlib
import json
import os

import pytest

from chutes_tdx_gate import attest, e2e, strict_json
from helpers import VECTORS, load, open_answer, open_sse
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey


def test_sha256sums():
    with open(os.path.join(VECTORS, "SHA256SUMS")) as stream:
        lines = [line.split() for line in stream if line.strip()]
    # The contract's lines for the files the gate consumes, unchanged (spec/SPEC.md).
    assert sorted(name for _, name in lines) == ["e2e_v2.json", "health.json", "mlkem768.py", "reportdata.json"]
    for digest, name in lines:
        with open(os.path.join(VECTORS, name), "rb") as stream:
            assert hashlib.sha256(stream.read()).hexdigest() == digest, name


def test_reportdata():
    v = load("reportdata.json")
    assert bytes.fromhex(v["tag_hex"]) == attest.TAG
    keys = {}
    for name, entry in v["keys"].items():
        key = e2e.ServerKey.from_seed(bytes.fromhex(entry["seed_d_z_hex"]))
        assert key.public_key == base64.b64decode(entry["public_key_b64"]), name
        keys[name] = key.public_key
    for case in v["cases"]:
        got = attest.reportdata(bytes.fromhex(case["nonce_hex"]), keys[case["public_key"]])
        assert got.hex() == case["report_data_hex"], case["name"]
    first = attest.reportdata(bytes.fromhex(v["cases"][0]["nonce_hex"]), keys[v["cases"][0]["public_key"]]).hex()
    for wrong in v["wrong_forms_for_cases_0"]:
        assert wrong["report_data_hex"] != first, wrong["name"]
    query = v["attest"]["request"].split("?", 1)[1].encode()
    assert attest.parse_nonce_query(query) == bytes.fromhex(v["cases"][0]["nonce_hex"])
    for refused in v["attest"]["refused_queries"]:
        with pytest.raises(ValueError):
            attest.parse_nonce_query(refused["query"].encode())
    quote = b"\x01\x02\x03"
    assert attest.answer(quote, keys["vm-1"]) == (
        b'{"quote":"' + base64.b64encode(quote) + b'","public_key":"' + v["attest"]["answer_shape"]["public_key"].encode() + b'"}')


@pytest.fixture(scope="module")
def e2e_vectors():
    return load("e2e_v2.json")


def test_requests_in_order(e2e_vectors):
    v = e2e_vectors
    key = e2e.ServerKey.from_seed(bytes.fromhex(v["vm_key"]["seed_d_z_hex"]))
    assert key.public_key == base64.b64decode(v["vm_key"]["public_key_b64"])
    routes = e2e.Routes([{"path": r["path"], "stream": r["stream"], "app_path": r["path"]} for r in v["routes"]])
    cache = e2e.ReplayCache()
    own = e2e.Identity(v["identity"]["endpoint_id"], v["identity"]["instance_id"])
    assert len(v["requests"]) == 34
    for case in v["requests"]:
        identity = e2e.Identity() if case.get("own") == "unknown" else own
        expect = case["expect"]
        try:
            opened = e2e.open_request(key, base64.b64decode(case["blob_b64"]), presented_path=case["presented_path"],
                                      method=case["method"], routes=routes, identity=identity, cache=cache,
                                      now_ms=case["now_ms"])
        except e2e.Refusal as exc:
            assert "refused" in expect, f"{case['name']}: refused {exc.status} {exc.code}"
            assert [exc.status, exc.code] == expect["refused"], case["name"]
            continue
        assert expect.get("admit"), f"{case['name']}: admitted, expected {expect}"
        assert opened.body == expect["body"] and opened.path == expect["path"] and opened.stream == expect["stream"]
        assert opened.nonce == expect["nonce"]
        assert hashlib.sha256(opened.response_key).hexdigest() == expect["e2e_response_pk_sha256"]


def test_answers_and_stream(e2e_vectors):
    v = e2e_vectors
    resp = MLKEM768PrivateKey.from_seed_bytes(bytes.fromhex(v["response_key"]["seed_d_z_hex"]))
    blobs = {c["name"].split(" ", 1)[0]: base64.b64decode(c["blob_b64"]) for c in v["requests"]}
    for case in v["answers"]:
        digest = hashlib.sha256(blobs[case["request"]]).digest()
        try:
            status, body = open_answer(resp, digest, base64.b64decode(case["blob_b64"]))
            if status != case["http_status"]:
                raise ValueError("presented status differs")
        except Exception:  # noqa: BLE001
            assert "refused" in case["expect"], case["name"]
            continue
        assert case["expect"] == {"status": status, "body_b64": base64.b64encode(body).decode()}, case["name"]
        if "wire_body" in case:
            assert case["wire_body"].encode() == e2e.answer_body(base64.b64decode(case["blob_b64"]))
    stream = v["stream"]
    digest = hashlib.sha256(blobs[stream["request"]]).digest()
    raw = base64.b64decode(stream["sse_b64"])
    assert base64.b64encode(open_sse(resp, digest, raw, 200)).decode() == stream["expect"]["data_b64"]
    lines = [line for line in raw.split(b"\n\n") if line]
    init, chunks = lines[0], lines[1:]
    for variant in stream["variants"]:
        seq = list(chunks)
        if "drop_chunk" in variant:
            del seq[variant["drop_chunk"]]
        elif "swap" in variant:
            i, j = variant["swap"]
            seq[i], seq[j] = seq[j], seq[i]
        elif "repeat" in variant:
            seq.insert(variant["repeat"], seq[variant["repeat"]])
        with pytest.raises(Exception):
            open_sse(resp, digest, b"\n\n".join([init, *seq]) + b"\n\n", 200)


def test_refusal_bodies(e2e_vectors):
    v = e2e_vectors
    assert sorted(e2e.CODES) == sorted(v["relay_passes"]["codes"]) and len(e2e.CODES) == 15
    for code, body in v["refusal_bodies"].items():
        assert e2e.refusal(code).body() == body.encode(), code


def test_replay_bound(e2e_vectors):
    bound = e2e_vectors["replay_cache"]
    cache = e2e.ReplayCache(max_entries=bound["max_entries"])
    for step in bound["sequence"]:
        nonce = (step["nonce"] * 43)[:43]
        try:
            cache.admit(nonce, step["ts"], step["now_ms"])
            got = "admitted"
        except e2e.Refusal as exc:
            got = [exc.status, exc.code]
            if "retry_after" in step:
                assert exc.retry_after == step["retry_after"]
        assert got == step["expect"], step


def probe_healthy(status, body_bytes, event):
    return event is None and status is not None and 200 <= status <= 299 and body_bytes <= 4096


def test_health():
    cases = load("health.json")["cases"]
    assert len(cases) == 10
    for case in cases:
        want = case["expect"].startswith("healthy")
        assert probe_healthy(case["status"], case["body_bytes"], case["event"]) == want, case
    assert probe_healthy(200, 0, None) and not probe_healthy(503, 0, None)


def test_strict_json_numbers():
    # The kit's own cases, not the contract's (spec/SPEC.md): the Go reader's tests read the same file.
    with open(os.path.join(os.path.dirname(VECTORS), "strict_json", "numbers.json"), "rb") as stream:
        cases = json.load(stream)["cases"]
    assert len(cases) == 60
    for case in cases:
        assert case["expect"] in ("accept", "refuse"), case["name"]
        doc = case["doc"].encode()
        for raw in (doc, b'{"b":[' + doc + b"]}"):
            try:
                strict_json.loads(raw)
                got = "accept"
            except ValueError:
                got = "refuse"
            assert got == case["expect"], case["name"]
