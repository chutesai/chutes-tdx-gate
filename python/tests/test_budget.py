"""The memory budget, the parse caps, the work off the event loop, and the one-process guard."""

import asyncio
import gzip
import json
import threading
import tracemalloc

import pytest

from chutes_tdx_gate import e2e, strict_json
from chutes_tdx_gate.asgi import GateMiddleware, min_budget
from chutes_tdx_gate.config import ConfigError, parse_config
import chutes_tdx_gate.asgi as asgi_module
from helpers import Caller, seal_request
from test_asgi import ENDPOINT, INSTANCE, NOW, App, FakeQuoter, call, config, make, refused, request

ROUTES = [{"path": "/v1/compress", "stream": False, "app_path": "/v1/compress"}]


def envelope_bytes(caller, body: bytes) -> bytes:
    """An envelope whose body is the given raw JSON (too large to build as a dict)."""
    head = json.dumps(caller.envelope(endpoint_id=ENDPOINT, instance_id=INSTANCE, path="/v1/compress", ts=NOW, body={}),
                      separators=(",", ":")).encode()
    i = head.rindex(b'"body":{}')
    return head[:i] + b'"body":' + body + head[i + len(b'"body":{}'):]


def zeros(n: int) -> bytes:
    return b'{"x":[' + b"0," * ((n - 9) // 2) + b"0]}"


def big_string(n: int, extra: str = "") -> bytes:
    return b'{"s":"' + extra.encode() + b"x" * (n - 8 - len(extra.encode())) + b'"}'


def open_with(budget, blob, max_plaintext=e2e.MAX_PLAINTEXT):
    lease = budget.lease()
    try:
        opened = e2e.open_request(e2e.ServerKey.from_seed(KEY_SEED), blob, presented_path="/v1/compress", method="POST",
                                  routes=ROUTES, identity=e2e.Identity(ENDPOINT, INSTANCE), cache=e2e.ReplayCache(),
                                  now_ms=NOW, max_plaintext=max_plaintext, lease=lease)
        return opened, lease
    except e2e.Refusal:
        lease.release()
        raise


KEY_SEED = bytes(range(64))
PK = e2e.ServerKey.from_seed(KEY_SEED).public_key


@pytest.mark.parametrize("doc", [
    b"0", b"[]", b"{}", b'{"a":[]}', b'[[],[1],{},{"k":{}}]', b' [ 1 , [ ] , { } , "a,[{" ] ',
    b'{"a":"\\"[,{","b":[true,false,null,-1.5e3]}', b'[[[[[]]]]]',
    b'["a\\\\",1,"\\\\\\"[{",[]]', b'{"k\\"":"\\u0022,"}',
])
def test_node_count_exact(doc):
    def walk(v):
        if isinstance(v, dict):
            return 1 + sum(walk(x) for x in v.values())
        if isinstance(v, list):
            return 1 + sum(walk(x) for x in v)
        return 1
    assert strict_json.node_count(doc) == walk(json.loads(doc))


def test_parse_caps():
    with pytest.raises(ValueError):
        strict_json.loads(b'{"' + b"k" * (strict_json.MAX_KEY_BYTES + 1) + b'":1}')
    strict_json.loads(b'{"' + b"k" * strict_json.MAX_KEY_BYTES + b'":1}')
    with pytest.raises(ValueError):
        strict_json.loads(b'{"b":{"' + "é".encode() * (strict_json.MAX_KEY_BYTES // 2 + 1) + b'":1}}')
    with pytest.raises(ValueError):
        strict_json.loads(b"[" + b"0," * 10 + b"0]", max_nodes=11)
    assert strict_json.loads(b"[" + b"0," * 9 + b"0]", max_nodes=11) == [0] * 10


# What Python really holds while it opens, parses and re-encodes a request stays within what was
# reserved for it, for each shape of body.
SHAPES = {
    "zeros": lambda: zeros(1 << 20),
    "ascii string": lambda: big_string(8 << 20),
    "astral character": lambda: big_string(8 << 20, "😀"),
    "escaped character": lambda: big_string(8 << 20, "\\u00e9"),
    "latin and BMP": lambda: big_string(4 << 20, "é" * 1000 + "ā" * 1000),
    "many keys": lambda: b"{" + b",".join(b'"k%d":%d' % (i, i) for i in range(300_000)) + b"}",
    "small objects": lambda: b'{"items":[' + b",".join(b'{"a":[%d]}' % i for i in range(200_000)) + b"]}",
    "nested arrays": lambda: b'{"x":' + b"[" * 500 + b"]" * 500 + b',"y":[' + b",".join([b"[[],{}]"] * 150_000) + b"]}",
}


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_parse_cost_bounds_the_memory(name):
    body = SHAPES[name]()
    caller = Caller()
    blob = seal_request(PK, envelope_bytes(caller, body))
    budget = e2e.Budget(1 << 30)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        opened, lease = open_with(budget, blob)
        opened.body_bytes()
        peak = tracemalloc.get_traced_memory()[1] - base
    finally:
        tracemalloc.stop()
    print(f"SHAPE {name}: plaintext {len(body)}, python held {peak}, reserved {lease.held}, ratio {peak / lease.held:.2f}")
    assert peak <= lease.held, f"{name}: held {peak}, reserved {lease.held}"
    lease.release()
    assert budget.used == 0


# A 64 MiB-plaintext request (a gzip bomb of zeros) is refused without the budget or Python's
# allocations exceeding the budget.
def test_gzip_bomb_within_budget():
    caller = Caller()
    raw = envelope_bytes(caller, zeros((64 << 20) - 4096))
    assert len(raw) <= 64 << 20
    blob = seal_request(PK, raw)
    assert len(blob) < 1 << 20
    budget = e2e.Budget(e2e.DEFAULT_BUDGET)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        with pytest.raises(e2e.Refusal) as refused_:
            open_with(budget, blob)
        peak = tracemalloc.get_traced_memory()[1] - base
    finally:
        tracemalloc.stop()
    assert refused_.value.code == "e2e_v2_malformed"  # over a million values
    # Reserved before anything was made: the opened plaintext, the inflated envelope (from the gzip
    # trailer) and the node count's copies; never more than the budget.
    assert budget.peak == len(blob) + len(raw) + 1 + strict_json.count_cost(raw), budget.peak
    assert budget.peak <= budget.max and budget.used == 0
    assert peak <= budget.peak, f"Python held {peak}, the budget {budget.peak}"


# The node cap applies to the envelope even when the budget would hold the parse.
def test_node_cap_in_the_envelope():
    budget = e2e.Budget(e2e.DEFAULT_BUDGET)
    for count, admitted in ((strict_json.MAX_NODES - 64, True), (strict_json.MAX_NODES + 1, False)):
        caller = Caller()
        head = envelope_bytes(caller, b"{}")
        body_nodes = count - strict_json.node_count(head) - 1  # the array, then its zeros
        blob = seal_request(PK, envelope_bytes(caller, b'{"x":[' + b",".join([b"0"] * body_nodes) + b"]}"))
        if admitted:
            opened, lease = open_with(budget, blob)
            lease.release()
        else:
            with pytest.raises(e2e.Refusal) as refused_:
                open_with(budget, blob)
            assert refused_.value.code == "e2e_v2_malformed"


def test_plaintext_over_limit_not_inflated():
    raw = b'{"pad":"' + b"x" * ((64 << 20) - 9) + b'"}'
    assert len(raw) == (64 << 20) + 1
    budget = e2e.Budget()
    with pytest.raises(e2e.Refusal) as refused_:
        open_with(budget, seal_request(PK, raw))
    assert refused_.value.code == "e2e_v2_malformed" and budget.peak < 1 << 20


def test_never_fits_is_malformed_and_busy_is_retryable():
    caller = Caller()
    blob = seal_request(PK, envelope_bytes(caller, big_string(40 << 20)))
    with pytest.raises(e2e.Refusal) as refused_:
        open_with(e2e.Budget(32 << 20), blob)
    assert refused_.value.code == "e2e_v2_malformed"
    budget = e2e.Budget(400 << 20)
    other = budget.lease()
    other.charge(300 << 20)
    with pytest.raises(e2e.Refusal) as refused_:
        open_with(budget, blob)
    assert refused_.value.code == "e2e_v2_busy" and refused_.value.retry_after == 1
    assert budget.used == 300 << 20
    other.release()
    opened, lease = open_with(budget, blob)
    assert opened.body["s"].startswith("xxx")
    lease.release()


def test_min_budget():
    with pytest.raises(ConfigError):
        GateMiddleware(App(), config(), test_identity=True, quoter=FakeQuoter(), memory_budget=64 << 20)
    assert min_budget(parse_config(config()).limits) <= e2e.DEFAULT_BUDGET
    # The example configuration's limits (16 MiB answers) fit the default too.
    assert min_budget(parse_config(config(max_answer_bytes=16777216)).limits) <= e2e.DEFAULT_BUDGET


def test_app_base_trailing_slash_refused():
    for base in (b"http://127.0.0.1:9000/", b"http://127.0.0.1:9000?"):
        with pytest.raises(ConfigError):
            parse_config(config().replace(b"http://127.0.0.1:9000", base))


# The middleware reserves the request's body as it reads it, and the opened plaintext.
def test_request_body_charged():
    gate, _, _ = make()
    body = bytes(4 << 20)
    refused(call(gate, "POST", "/v1/compress", body), 400, "e2e_v2_undecryptable")
    assert gate.budget.peak >= 4 * len(body) and gate.budget.used == 0


# The answer is reserved as it is collected, and its sealing before it is sealed.
def test_answer_charged():
    class Answer(App):
        async def __call__(self, scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"a" * (512 << 10)})
    gate, _, _ = make(Answer())
    caller, blob, _ = request(gate)
    status, _, raw = call(gate, "POST", "/v1/compress", blob)
    assert status == 200
    assert gate.budget.peak >= 2 * (512 << 10) + e2e.seal_cost(512 << 10) and gate.budget.used == 0


# Busy is answered only before the application runs: the stream reservation comes
# with the request; an answer the budget cannot hold after the application ran is
# e2e_v2_answer_too_large.
def test_busy_only_before_the_application():
    calls = []

    class Answer(App):
        async def __call__(self, scope, receive, send):
            calls.append(scope["path"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"a" * (512 << 10)})
    gate, _, _ = make(Answer())
    other = gate.budget.lease()
    other.charge(gate.budget.max - (512 << 10))  # less than the stream reservation is left
    _, blob, _ = request(gate, "/v1/stream", stream=True, body={"stream": True})
    refused(call(gate, "POST", "/v1/stream", blob), 503, "e2e_v2_busy")
    assert calls == []
    other.release()
    other.charge(gate.budget.max - (4 << 20))  # room for the request, not for the answer's sealing
    _, blob, _ = request(gate)
    refused(call(gate, "POST", "/v1/compress", blob), 502, "e2e_v2_answer_too_large")
    assert calls == ["/v1/compress"]
    other.release()
    assert gate.budget.used == 0


# Opening (decrypt, inflate, parse) runs in a worker thread, not on the event loop.
def test_open_off_the_event_loop(monkeypatch):
    seen = []
    real = asgi_module.open_request

    def spy(*args, **kwargs):
        seen.append(threading.current_thread() is threading.main_thread())
        return real(*args, **kwargs)
    monkeypatch.setattr(asgi_module, "open_request", spy)
    gate, _, _ = make()
    caller, blob, _ = request(gate)
    assert call(gate, "POST", "/v1/compress", blob)[0] == 201
    assert seen == [False]
    assert gate.budget.used == 0


# 204 and 304 cannot carry a sealed answer: e2e_v2_app_failed (spec section 4.3).
@pytest.mark.parametrize("status", [204, 304])
@pytest.mark.parametrize("path,stream", [("/v1/compress", False), ("/v1/stream", True)])
def test_bodyless_status_is_app_failed(status, path, stream):
    class NoBody(App):
        async def __call__(self, scope, receive, send):
            await send({"type": "http.response.start", "status": status, "headers": []})
            await send({"type": "http.response.body", "body": b""})
    gate, _, _ = make(NoBody())
    _, blob, _ = request(gate, path, stream=stream, body={"stream": True} if stream else {})
    refused(call(gate, "POST", path, blob), 502, "e2e_v2_app_failed")


# Called from another process than the one that made it (a forked worker), the middleware serves
# nothing: its key is not the one /attest would bind there.
def test_another_process_is_refused(monkeypatch):
    gate, _, quoter = make()
    _, blob, _ = request(gate)
    monkeypatch.setattr(gate, "_pid", gate._pid + 1)
    assert call(gate, "GET", "/attest", query=b"nonce=" + b"00" * 32)[::2] == (503, b'{"detail":{"code":"attest_unavailable"}}')
    assert call(gate, "GET", "/health")[0] == 503
    refused(call(gate, "POST", "/v1/compress", blob), 503, "e2e_v2_busy")
    assert quoter.seen == []
