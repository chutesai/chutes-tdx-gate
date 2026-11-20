"""GateMiddleware: the library form's HTTP behaviour (the Go gate's pkg/gate tests, mirrored)."""

import asyncio
import base64
import hashlib
import json
import os

import pytest

from chutes_tdx_gate import attest, e2e
from chutes_tdx_gate.asgi import GateMiddleware
import chutes_tdx_gate.asgi as asgi_module
from helpers import Caller

ENDPOINT = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40"
INSTANCE = "5813945712345678901"
NOW = 1795000000000


def config(**limits):
    lim = {"max_request_bytes": 8454144, "max_plaintext_bytes": 67108864, "max_answer_bytes": 1048576,
           "max_inflight": 8, "replay_cache_entries": 65536}
    lim.update(limits)
    return json.dumps({
        "schema": "chutes.tdx-gate-config.v1", "listen": "0.0.0.0:8080",
        "app": {"base": "http://127.0.0.1:9000", "health_path": "/app-health", "timeout_s": 2},
        "health_path": "/health",
        "routes": [{"path": "/v1/compress", "stream": False, "app_path": "/v1/compress"},
                   {"path": "/v1/stream", "stream": True, "app_path": "/v1/stream"},
                   {"path": "/v1/echo", "stream": False, "app_path": "/app/echo"}],
        "identity": {"source": "static", "endpoint_id": ENDPOINT, "instance_id": INSTANCE},
        "limits": lim, "tsm_report_dir": "/sys/kernel/config/tsm/report"}).encode()


class FakeQuoter:
    def __init__(self):
        self.seen = []

    def quote(self, rd):
        self.seen.append(rd)
        q = bytearray(640)
        q[0:2] = (4).to_bytes(2, "little")
        q[4:8] = (0x81).to_bytes(4, "little")
        q[568:632] = rd
        return bytes(q)


class App:
    """A raw ASGI app recording what it receives."""

    def __init__(self, mode="echo"):
        self.mode = mode
        self.requests = []
        self.health_status = 200
        self.block = None

    async def __call__(self, scope, receive, send):
        assert scope["type"] == "http"
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        self.requests.append((scope["method"], scope["path"], list(scope["headers"]), body))
        if scope["path"] == "/app-health":
            await send({"type": "http.response.start", "status": self.health_status, "headers": []})
            await send({"type": "http.response.body", "body": b"x" * 5000})
            return
        if self.block is not None:
            await self.block.wait()
        if self.mode == "stream" or scope["path"] == "/v1/stream":
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]})
            for i in range(3):
                await send({"type": "http.response.body", "body": b'data: {"i":%d}\n\n' % i, "more_body": True})
            if self.mode == "cut":
                raise RuntimeError("the app failed mid-stream")
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        if self.mode == "big":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"x" * (1048577)})
            return
        if self.mode == "fail":
            raise RuntimeError("down")
        await send({"type": "http.response.start", "status": 201,
                    "headers": [(b"x-app-secret", b"no"), (b"set-cookie", b"a=b"), (b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"echo:" + body})


def call(gate, method, path, body=b"", query=b"", headers=()):
    async def run():
        sent = []
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            await asyncio.sleep(3600)

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": method, "path": path, "query_string": query, "headers": list(headers)}
        await gate(scope, receive, send)
        start = sent[0]
        raw = b"".join(m.get("body", b"") for m in sent[1:])
        return start["status"], {k.decode(): v.decode() for k, v in start["headers"]}, raw

    return asyncio.run(run())


def make(app=None, **limits):
    app = app or App()
    quoter = FakeQuoter()
    gate = GateMiddleware(app, config(**limits), test_identity=True, quoter=quoter, clock=lambda: NOW)
    return gate, app, quoter


def request(gate, path="/v1/compress", stream=False, body=None, caller=None, **over):
    caller = caller or Caller()
    env = caller.envelope(endpoint_id=ENDPOINT, instance_id=INSTANCE, path=path, stream=stream, ts=NOW,
                          body={} if body is None else body, **over)
    return caller, caller.seal(gate.public_key, env), env


def refused(result, status, code):
    got_status, headers, body = result
    assert (got_status, body) == (status, b'{"detail":{"code":"%s"}}' % code.encode())
    assert headers["content-type"] == "application/json"
    assert ("retry-after" in headers) == (code == "e2e_v2_busy")


def sealed(caller, result):
    status, headers, body = result
    wire = json.loads(body)
    assert set(wire) == {"e2e"} and body == b'{"e2e":"' + wire["e2e"].encode() + b'"}'
    assert set(headers) == {"content-type", "content-length"} and headers["content-type"] == "application/json"
    sealed_status, plain = caller.open_answer(base64.b64decode(wire["e2e"]))
    assert sealed_status == status
    return status, plain


def test_sealed_answer_and_app_request():
    gate, app, _ = make()
    caller, blob, _ = request(gate, "/v1/echo", body={"messages": ["hi"], "z": "ü"})
    status, plain = sealed(caller, call(gate, "POST", "/v1/echo", blob, headers=[(b"x-chutes-caller", b"x")]))
    assert status == 201 and plain == 'echo:{"messages":["hi"],"z":"ü"}'.encode()
    method, path, headers, body = app.requests[-1]
    assert (method, path) == ("POST", "/app/echo")
    assert headers == [(b"host", b"127.0.0.1"), (b"content-type", b"application/json"),
                       (b"content-length", str(len(body)).encode())]
    refused(call(gate, "POST", "/v1/echo", blob), 409, "e2e_v2_replayed")


def test_stream():
    gate, _, _ = make()
    caller, blob, _ = request(gate, "/v1/stream", stream=True, body={"stream": True})
    status, headers, raw = call(gate, "POST", "/v1/stream", blob)
    assert status == 200 and headers["content-type"] == "text/event-stream"
    assert caller.open_sse(raw, 200) == b'data: {"i":0}\n\ndata: {"i":1}\n\ndata: {"i":2}\n\n'


def test_stream_cut_has_no_end():
    gate, _, _ = make(App("cut"))
    caller, blob, _ = request(gate, "/v1/stream", stream=True, body={"stream": True})
    status, _, raw = call(gate, "POST", "/v1/stream", blob)
    with pytest.raises(AssertionError, match="cut short"):
        caller.open_sse(raw, status)


def test_app_failures():
    gate, _, _ = make(App("big"))
    _, blob, _ = request(gate)
    refused(call(gate, "POST", "/v1/compress", blob), 502, "e2e_v2_answer_too_large")
    gate, _, _ = make(App("fail"))
    _, blob, _ = request(gate)
    refused(call(gate, "POST", "/v1/compress", blob), 502, "e2e_v2_app_failed")


@pytest.mark.parametrize("name,over,path,method,status,code", [
    ("endpoint", {"endpoint_id": "00000000-0000-4000-8000-000000000000"}, "/v1/compress", "POST", 403, "e2e_v2_wrong_endpoint"),
    ("instance", {"instance_id": "1"}, "/v1/compress", "POST", 403, "e2e_v2_wrong_instance"),
    ("method", {}, "/v1/compress", "PUT", 405, "e2e_v2_method"),
    ("path", {}, "/v1/stream", "POST", 403, "e2e_v2_wrong_path"),
    ("route", {"path": "/v1/other"}, "/v1/other", "POST", 404, "e2e_v2_route_not_served"),
    ("stream", {"body": {"stream": True}}, "/v1/compress", "POST", 400, "e2e_v2_stream_mismatch"),
    ("stream not boolean", {"body": {"stream": 0}}, "/v1/compress", "POST", 400, "e2e_v2_stream_mismatch"),
    ("stale", {"ts": NOW - 120001}, "/v1/compress", "POST", 400, "e2e_v2_stale"),
    ("future", {"ts": NOW + 60001}, "/v1/compress", "POST", 400, "e2e_v2_from_the_future"),
    ("non-printable id", {"endpoint_id": ENDPOINT + "​"}, "/v1/compress", "POST", 400, "e2e_v2_malformed"),
])
def test_checks(name, over, path, method, status, code):
    gate, _, _ = make()
    caller = Caller()
    env = caller.envelope(endpoint_id=ENDPOINT, instance_id=INSTANCE, path="/v1/compress", ts=NOW, body={})
    env.update(over)
    refused(call(gate, method, path, caller.seal(gate.public_key, env)), status, code)


def test_nonce_consumed_last():
    gate, _, _ = make()
    caller, blob, env = request(gate)
    other = Caller()
    bad = other.envelope(endpoint_id=ENDPOINT, instance_id=INSTANCE, path="/v1/other", ts=NOW, body={}, nonce=env["nonce"])
    refused(call(gate, "POST", "/v1/other", other.seal(gate.public_key, bad)), 404, "e2e_v2_route_not_served")
    assert sealed(caller, call(gate, "POST", "/v1/compress", blob))[0] == 201


def test_busy_cache_and_inflight():
    gate, _, _ = make(replay_cache_entries=1)
    caller, blob, _ = request(gate)
    sealed(caller, call(gate, "POST", "/v1/compress", blob))
    _, blob2, _ = request(gate)
    result = call(gate, "POST", "/v1/compress", blob2)
    assert result[1]["retry-after"] == "120"
    refused(result, 503, "e2e_v2_busy")

    app = App()
    gate, _, _ = make(app, max_inflight=1)

    async def two():
        app.block = asyncio.Event()
        caller1, blob1, _ = request(gate)
        _, blob2, _ = request(gate)
        out = []

        async def one(blob):
            sent = []
            done = False

            async def receive():
                nonlocal done
                if not done:
                    done = True
                    return {"type": "http.request", "body": blob, "more_body": False}
                await asyncio.sleep(3600)

            async def send(m):
                sent.append(m)
            await gate({"type": "http", "method": "POST", "path": "/v1/compress", "query_string": b"", "headers": []}, receive, send)
            return sent
        first = asyncio.create_task(one(blob1))
        await asyncio.sleep(0.05)
        second = await one(blob2)
        app.block.set()
        await first
        return second
    second = asyncio.run(two())
    assert second[0]["status"] == 503 and second[1]["body"] == b'{"detail":{"code":"e2e_v2_busy"}}'


def test_request_too_large():
    gate, _, _ = make(max_request_bytes=2000)
    refused(call(gate, "POST", "/v1/compress", bytes(2001)), 400, "e2e_v2_malformed")


def test_identity_unknown_and_not_from_request():
    app = App()
    gate = GateMiddleware(app, config().replace(b'"source": "static", "endpoint_id": "' + ENDPOINT.encode() + b'", "instance_id": "' + INSTANCE.encode() + b'"', b'"source": "gce-metadata"'),
                          quoter=FakeQuoter(), clock=lambda: NOW, start_identity=False)
    _, blob, _ = request(gate)
    hdrs = [(b"x-chutes-endpoint-id", ENDPOINT.encode()), (b"x-instance-id", INSTANCE.encode()), (b"metadata-flavor", b"Google")]
    refused(call(gate, "POST", "/v1/compress", blob, headers=hdrs), 503, "e2e_v2_identity_unknown")
    assert call(gate, "GET", "/health")[0] == 503
    gate.set_identity(e2e.Identity("00000000-0000-4000-8000-000000000001", INSTANCE))
    _, blob, _ = request(gate)
    refused(call(gate, "POST", "/v1/compress", blob, headers=hdrs), 403, "e2e_v2_wrong_endpoint")


def test_health(monkeypatch):
    gate, app, _ = make()
    assert call(gate, "GET", "/health") == (200, {"content-length": "0"}, b"")
    for status, want in ((204, 200), (299, 200), (301, 503), (404, 503), (500, 503)):
        app.health_status = status
        assert call(gate, "GET", "/health")[0] == want
    assert call(gate, "POST", "/health")[0] == 405
    monkeypatch.setattr(asgi_module, "HEALTH_APP_TIMEOUT", 0.05)
    app.health_status = 200

    class Slow(App):
        async def __call__(self, scope, receive, send):
            await asyncio.sleep(0.5)
            await super().__call__(scope, receive, send)
    gate, _, _ = make(Slow())
    assert call(gate, "GET", "/health")[0] == 503


def test_attest():
    gate, _, quoter = make()
    nonce = os.urandom(32)
    status, headers, body = call(gate, "GET", "/attest", query=b"nonce=" + nonce.hex().encode())
    rd = hashlib.sha512(b"chutes-tdx-endpoint-attest-v1\x00" + nonce + gate.public_key).digest()
    assert status == 200 and headers["content-type"] == "application/json"
    assert body == attest.answer(quoter.quote(rd), gate.public_key)
    assert quoter.seen[0] == rd
    for query in (b"", nonce.hex().upper().encode(), b"nonce=" + nonce.hex().encode() + b"&x=1", b"report_data=" + rd.hex().encode()):
        assert call(gate, "GET", "/attest", query=query)[:3:2] == (400, b'{"detail":{"code":"attest_bad_nonce"}}')
    assert call(gate, "POST", "/attest", query=b"nonce=" + nonce.hex().encode())[0] == 405
    assert len(quoter.seen) == 2  # the first request's and this test's own call


def test_only_attest_quotes():
    gate, _, quoter = make()
    rd = os.urandom(64)
    for path in ("/attest/", "/attest2", "/v1/compress", "/v1/stream", "/health", "/quote", "/"):
        for method in ("GET", "POST"):
            call(gate, method, path, rd, query=b"nonce=" + rd[:32].hex().encode() + b"&report_data=" + rd.hex().encode())
    assert quoter.seen == []
