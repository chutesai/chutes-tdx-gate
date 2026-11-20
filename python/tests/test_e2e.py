"""Envelope rules beyond the vectors, the strict JSON, sealing and the replay cache."""

import json
import os
import sys

import pytest

from chutes_tdx_gate import e2e, strict_json
from helpers import Caller, open_answer

NOW = 1795000000000


@pytest.fixture
def setup():
    key = e2e.ServerKey.generate()
    routes = e2e.Routes([{"path": "/r", "stream": False, "app_path": "/app"}])
    return key, routes


def run(key, routes, raw, cache=None, **kw):
    caller = Caller()
    raw = raw.replace(b"PK", caller.pk_b64.encode())
    blob = caller.seal(key.public_key, raw)
    try:
        e2e.open_request(key, blob, presented_path="/r", method="POST", routes=routes, identity=e2e.Identity("e", "1"),
                         cache=cache or e2e.ReplayCache(), now_ms=NOW, **kw)
        return ""
    except e2e.Refusal as exc:
        return exc.code


def env(body=b"{}", ts=str(NOW).encode(), nonce=b"a" * 43, v=b"2", stream=b"false", pk=b'"PK"'):
    return (b'{"v":' + v + b',"endpoint_id":"e","instance_id":"1","path":"/r","stream":' + stream + b',"nonce":"' + nonce +
            b'","ts":' + ts + b',"e2e_response_pk":' + pk + b',"body":' + body + b"}")


@pytest.mark.parametrize("raw,code", [
    (env().replace(b'"v":2,', b'"v":2,"v":2,'), "e2e_v2_malformed"),
    (env(body=b'{"stream":false,"stream":true}'), "e2e_v2_malformed"),
    (env(body=b'{"a":"\\ud800"}'), "e2e_v2_malformed"),
    (env(body=b'{"a":NaN}'), "e2e_v2_malformed"),
    (env(body=b'{"a":1e400}'), "e2e_v2_malformed"),
    (env(body=b'{"a":' + b"9" * 400 + b"}"), "e2e_v2_malformed"),
    (env(body=b'{"a":[-' + b"9" * 309 + b"]}"), "e2e_v2_malformed"),
    (env(body=b'{"a":1' + b"0" * 308 + b"}"), ""),
    (env(ts=str(NOW).encode() + b".0"), "e2e_v2_malformed"),
    (env(ts=b"18446744073709551615"), "e2e_v2_from_the_future"),
    (env(ts=b"-9223372036854775808"), "e2e_v2_stale"),
    (env(ts=b"18446744073709551616"), "e2e_v2_malformed"),
    (env(ts=b"-9223372036854775809"), "e2e_v2_malformed"),
    (env(body=b'{"n":99999999999999999999999}'), ""),
    (env(pk=b'"\\nPK"'), "e2e_v2_malformed"),
    (env(nonce=b"a" * 44), "e2e_v2_malformed"),
    (env(nonce=b"+" + b"a" * 42), "e2e_v2_malformed"),
    (env(body=b"[]"), "e2e_v2_malformed"),
    (env(v=b'"2"'), "e2e_v2_malformed"),
    (env(v=b"true"), "e2e_v2_malformed"),
    (env(stream=b"null"), "e2e_v2_malformed"),
    (env(body=b'{"stream":"false"}'), "e2e_v2_stream_mismatch"),
    (env(body=b'{"stream":null}'), "e2e_v2_stream_mismatch"),
    (env(body=b'{"stream":false}'), ""),
    (b"\xef\xbb\xbf" + env(), "e2e_v2_malformed"),
    (env(body=b"[" * 600 + b"]" * 600), "e2e_v2_malformed"),
])
def test_envelope_rules(setup, raw, code):
    key, routes = setup
    assert run(key, routes, raw) == code


def test_response_key_modulus(setup):
    key, routes = setup
    caller = Caller()
    bad = bytearray(caller.key.public_key().public_bytes_raw())
    bad[0] = bad[1] = 0xFF
    import base64
    raw = env(pk=b'"' + base64.b64encode(bytes(bad)) + b'"')
    cache = e2e.ReplayCache()
    blob = caller.seal(key.public_key, raw)
    with pytest.raises(e2e.Refusal) as exc:
        e2e.open_request(key, blob, presented_path="/r", method="POST", routes=routes, identity=e2e.Identity("e", "1"),
                         cache=cache, now_ms=NOW)
    assert exc.value.code == "e2e_v2_malformed" and len(cache) == 0


def test_plaintext_limit(setup):
    key, routes = setup
    assert run(key, routes, env(body=b'{"x":"' + b"a" * 2000 + b'"}'), max_plaintext=1024) == "e2e_v2_malformed"


def test_seal_round_trip(setup):
    key, routes = setup
    caller = Caller()
    blob = caller.seal(key.public_key, env().replace(b"PK", caller.pk_b64.encode()))
    opened = e2e.open_request(key, blob, presented_path="/r", method="POST", routes=routes,
                              identity=e2e.Identity("e", "1"), cache=e2e.ReplayCache(), now_ms=NOW)
    assert caller.open_answer(e2e.seal_answer(opened, 418, b"body")) == (418, b"body")
    with pytest.raises(Exception):
        open_answer(caller.key, b"\x00" * 32, e2e.seal_answer(opened, 200, b"x"))
    with pytest.raises(ValueError):
        e2e.seal_answer(opened, 199, b"")


def test_refusal_codes_closed():
    assert len(e2e.CODES) == 15
    with pytest.raises(ValueError):
        e2e.Refusal(503, "e2e_v2_overloaded")
    with pytest.raises(ValueError):
        e2e.Refusal(400, "e2e_v2_stale", 5)


def test_replay_floor():
    cache = e2e.ReplayCache(4)
    cache.admit("a" * 43, NOW, NOW)
    later = NOW + e2e.MAX_AGE_MS + 1
    cache.admit("b" * 43, later, later)
    with pytest.raises(e2e.Refusal) as exc:
        cache.admit("a" * 43, NOW, NOW + 1000)
    assert exc.value.code == "e2e_v2_stale"


@pytest.mark.parametrize("doc", [
    b'{"a":1,"a":2}', b"NaN", b"[Infinity]", b"1e400", b"\xef\xbb\xbf{}", b'{"a":"\xff"}', b'"\\ud800"', b'{"a":1}x',
    b"[" * 513 + b"]" * 513,
    b"9" * 309, b"-" + b"9" * 309, b"[" + b"9" * 400 + b"]", str(2 ** 1024 - 2 ** 970).encode(),
])
def test_strict_json_refuses(doc):
    with pytest.raises(ValueError):
        strict_json.loads(doc)


def test_strict_json_accepts():
    assert strict_json.loads(b"[" * 512 + b"]" * 512)
    assert strict_json.loads(b'{"a":"\\ud83d\\ude00","b":1e-400}') == {"a": "\U0001f600", "b": 0.0}
    # An integer of 309 digits that a float can hold stays an exact int, as the Go gate keeps its text.
    edge = 2 ** 1024 - 2 ** 970 - 1
    assert strict_json.loads(str(edge).encode()) == edge and strict_json.loads(str(-edge).encode()) == -edge
    assert strict_json.loads(b"9" * 308) == 10 ** 308 - 1


def test_strict_json_integer_range_without_the_interpreter_limit():
    # CPython refuses to convert an integer of more digits than sys.get_int_max_str_digits() (4300
    # by default; 0 lifts it): the reader's refusal must not rest on that setting.
    lift = getattr(sys, "set_int_max_str_digits", None)  # absent before 3.10.7, which has no limit
    limit = sys.get_int_max_str_digits() if lift else 0
    if lift:
        lift(0)
    try:
        with pytest.raises(ValueError):
            strict_json.loads(b"9" * 5000)
        with pytest.raises(ValueError):
            strict_json.loads(b'{"a":[-' + b"9" * 5000 + b"]}")
    finally:
        if lift:
            lift(limit)


# Exactly one gzip member with nothing after it, whatever the last four bytes claim (the Go gate's
# TestGunzipOneMember).
def test_gunzip_one_member():
    import gzip as gzip_module
    plain = b'{"v":2}'
    member = gzip_module.compress(plain, mtime=0)
    assert e2e._gunzip(member, 1024) == plain
    size = len(plain).to_bytes(4, "little")
    for data in (member + member, member + bytes(4) + size):
        with pytest.raises(e2e.Refusal) as exc:
            e2e._gunzip(data, 1024)
        assert exc.value.code == "e2e_v2_malformed"
    short = member[:-4] + (len(plain) - 1).to_bytes(4, "little")
    with pytest.raises(e2e.Refusal):
        e2e._gunzip(short, 1024)
