#!/usr/bin/env python3
"""Cross-test: the SDK's own ``chutes.endpoint.EndpointClient`` against the gate on loopback.

    PYTHONPATH=<SDK copy>:python python crosstest/crosstest.py --form go --gate-binary out/tdx-gate-faketsm
    PYTHONPATH=<SDK copy>:python python crosstest/crosstest.py --form python

``<SDK copy>`` is a ``git archive`` copy of the Chutes SDK source with ``chutes.endpoint`` (the
endpoint client and E2E v2), never a worktree import. The path under test:

    EndpointClient.call  --TLS-->  fake validator relay  --HTTP-->  gate  --HTTP/ASGI-->  sample app

* The relay is a stand-in for the validator's relay: the listing, ``/evidence`` (a
  ``GET /attest`` with spec section 4.4's exact headers) and ``/e2e`` (section 4.3's exact request
  headers and the three answer forms: a sealed answer, an SSE stream, or one of the 15 refusal
  bodies byte for byte; anything else 502 endpoint_upstream_error).
* The client's ``verify_instance`` is replaced by the quote binding check alone: the evidence
  key is the listing's and the quote's REPORTDATA is the rule over the client's nonce and that
  key. The gate runs with a faketsm test build (Go) or a fake quoter (Python): the quotes are
  unsigned, so the quote signature and provider checks need a real TDX VM.
* Everything after verification is the SDK's own code: encryption, the request, the resend rules,
  the sealed answer, the stream order and its end, and the error mapping.

Exit 0 only when every case passes.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import parse_qs, urlsplit

ENDPOINT = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40"
OTHER_ENDPOINT = "0d8f4a52-1c3e-4b7a-9f60-2e5d7c9a1b34"
INSTANCE = "5813945712345678901"
HOST = "127.88.0.1"
REFUSALS = {
    "e2e_v2_undecryptable": 400, "e2e_v2_malformed": 400, "e2e_v2_stream_mismatch": 400, "e2e_v2_stale": 400,
    "e2e_v2_from_the_future": 400, "e2e_v2_wrong_endpoint": 403, "e2e_v2_wrong_instance": 403,
    "e2e_v2_wrong_path": 403, "e2e_v2_route_not_served": 404, "e2e_v2_method": 405, "e2e_v2_replayed": 409,
    "e2e_v2_app_failed": 502, "e2e_v2_answer_too_large": 502, "e2e_v2_identity_unknown": 503, "e2e_v2_busy": 503,
}
ROUTES = [
    {"path": "/v1/echo", "stream": False},
    {"path": "/v1/sealed-error", "stream": False},
    {"path": "/v1/stream", "stream": True},
    {"path": "/v1/stream-cut", "stream": True},
    {"path": "/v1/undeclared-at-gate", "stream": False},
]
STREAM_EVENTS = [b'data: {"delta":"Analyze"}\n\n', b'data: {"delta":" context"}\n\n', b"data: [DONE]\n\n"]


def free_port(host=HOST) -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- the sample application

class AppHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_error(404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        AppHandler.seen.append((self.path, dict(self.headers), body))
        if self.path == "/v1/echo":
            self._answer(200, body)
        elif self.path == "/v1/sealed-error":
            self._answer(418, b'{"error":"teapot"}')
        elif self.path in ("/v1/stream", "/v1/stream-cut"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for event in STREAM_EVENTS[: 1 if self.path == "/v1/stream-cut" else None]:
                self.wfile.write(b"%x\r\n%s\r\n" % (len(event), event))
                self.wfile.flush()
            if self.path == "/v1/stream-cut":
                self.connection.shutdown(socket.SHUT_RDWR)  # cut: no terminating chunk
                return
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_error(404)

    def _answer(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-App-Secret", "never-forwarded")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def sample_asgi_app(scope, receive, send):
    """The same sample application as an in-process ASGI app (the Python library form)."""
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break
    path = scope["path"]
    AppHandler.seen.append((path, {k.decode(): v.decode() for k, v in scope["headers"]}, body))
    if path == "/health":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})
    elif path in ("/v1/echo", "/v1/sealed-error"):
        status, out = (200, body) if path == "/v1/echo" else (418, b'{"error":"teapot"}')
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"x-app-secret", b"never-forwarded")]})
        await send({"type": "http.response.body", "body": out})
    elif path in ("/v1/stream", "/v1/stream-cut"):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]})
        for event in STREAM_EVENTS[: 1 if path == "/v1/stream-cut" else None]:
            await send({"type": "http.response.body", "body": event, "more_body": True})
        if path == "/v1/stream-cut":
            raise RuntimeError("the application failed mid-stream")
        await send({"type": "http.response.body", "body": b"", "more_body": False})
    else:
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})


# ------------------------------------------------------------------------------ the validator relay

def make_tls(tmp: str):
    """A throwaway CA and a server certificate for HOST (the relay's TLS, as the validator's)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "crosstest CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=2))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(HOST))]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    paths = {name: os.path.join(tmp, name) for name in ("ca.pem", "cert.pem", "key.pem")}
    with open(paths["ca.pem"], "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(paths["cert.pem"], "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(paths["key.pem"], "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return paths


class Relay:
    """State of the stand-in validator relay."""

    def __init__(self, gate_host, gate_port):
        self.gate = (gate_host, gate_port)
        self.listed_instance = INSTANCE
        self.present_path = None  # an override of the path presented to the VM (the wrong-path case)
        self.last_blob = None
        self.upstream_requests = []
        self.gate_pk_b64 = None

    def attest(self, nonce_hex):
        conn = http.client.HTTPConnection(*self.gate, timeout=10)
        conn.putrequest("GET", "/attest?nonce=" + nonce_hex, skip_host=True, skip_accept_encoding=True)
        for name, value in (("Host", f"{self.gate[0]}:{self.gate[1]}"), ("Accept-Encoding", "identity"),
                            ("Connection", "close"), ("User-Agent", "chutes-vms-relay/1")):
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read(65537)

    def e2e(self, path, stream, blob):
        """Spec section 4.3: the request with exactly its headers, then the three answer forms."""
        conn = http.client.HTTPConnection(*self.gate, timeout=60)
        conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        for name, value in (("Host", f"{self.gate[0]}:{self.gate[1]}"), ("Accept-Encoding", "identity"),
                            ("Connection", "keep-alive"), ("User-Agent", "chutes-vms-relay/1"),
                            ("Content-Type", "application/octet-stream"), ("X-E2E-Stream", "true" if stream else "false"),
                            ("Content-Length", str(len(blob)))):
            conn.putheader(name, value)
        conn.endheaders(blob)
        self.upstream_requests.append(path)
        return conn, conn.getresponse()


def relay_handler(relay: Relay):
    upstream_error = (502, b'{"detail":{"code":"endpoint_upstream_error"}}')

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, status, body, ctype="application/json", extra=()):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlsplit(self.path)
            parts = url.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "endpoints":
                return self._send(404, b'{"detail":"not found"}')
            endpoint, what = parts[1], parts[2]
            if what == "instances":
                listing = {"endpoint_id": endpoint, "kind": "tdx_vm", "instances": [{
                    "instance_id": relay.listed_instance, "e2e_pubkey": relay.gate_pk_b64,
                    "serving_spki_sha256": "0" * 64, "nonces": [secrets.token_urlsafe(32) for _ in range(4)]}],
                    "nonce_expires_in": 60, "nonce_expires_at": int(time.time()) + 60}
                return self._send(200, json.dumps(listing).encode())
            if what == "evidence":
                query = parse_qs(url.query)
                status, body = relay.attest(query["nonce"][0])
                if status != 200 or len(body) > 65536:
                    return self._send(502, b'{"detail":{"code":"vm_attest_unavailable"}}')
                return self._send(200, body)
            return self._send(404, b'{"detail":"not found"}')

        def do_POST(self):
            parts = urlsplit(self.path).path.strip("/").split("/")
            if len(parts) != 3 or parts[2] != "e2e":
                return self._send(404, b'{"detail":"not found"}')
            blob = self.rfile.read(int(self.headers["Content-Length"]))
            relay.last_blob = blob
            path = relay.present_path or self.headers["X-E2E-Path"]
            stream = next((r["stream"] for r in ROUTES if r["path"] == self.headers["X-E2E-Path"]), False)
            conn, resp = relay.e2e(path, stream, blob)
            try:
                ctype = (resp.getheader("Content-Type") or "").split(";")[0]
                if resp.status == 200 and stream:
                    if ctype != "text/event-stream":
                        return self._send(*upstream_error)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    while True:
                        line = resp.readline(1 << 20)
                        if not line:
                            break
                        self.wfile.write(line)
                        self.wfile.flush()
                    self.close_connection = True
                    return
                body = resp.read(64 << 20)
                try:
                    wire = json.loads(body)
                except ValueError:
                    wire = None
                if (isinstance(wire, dict) and set(wire) == {"e2e"} and isinstance(wire["e2e"], str)
                        and body == b'{"e2e":"' + wire["e2e"].encode() + b'"}'):
                    return self._send(resp.status, base64.b64decode(wire["e2e"]), "application/octet-stream")
                for code, status in REFUSALS.items():
                    if resp.status == status and body == b'{"detail":{"code":"' + code.encode() + b'"}}':
                        extra = ()
                        retry = resp.getheader("Retry-After")
                        if code == "e2e_v2_busy" and retry and retry.isdigit() and 1 <= int(retry) <= 180:
                            extra = (("Retry-After", retry),)
                        return self._send(status, body, extra=extra)
                return self._send(*upstream_error)
            finally:
                conn.close()

    return Handler


# ----------------------------------------------------------------------------------------- the run

def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wait_port(host, port, deadline=20.0):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listens on {host}:{port}")


def gate_config(app_port, replay_entries):
    return {
        "schema": "chutes.tdx-gate-config.v1", "listen": f"{HOST}:8080",
        "app": {"base": f"http://{HOST}:{app_port}", "health_path": "/health", "timeout_s": 30},
        "health_path": "/health",
        "routes": [{"path": r["path"], "stream": r["stream"], "app_path": r["path"]} for r in ROUTES
                   if r["path"] != "/v1/undeclared-at-gate"],
        "identity": {"source": "static", "endpoint_id": ENDPOINT, "instance_id": INSTANCE},
        "limits": {"max_request_bytes": 8454144, "max_plaintext_bytes": 67108864, "max_answer_bytes": 16777216,
                   "max_inflight": 64, "replay_cache_entries": replay_entries},
        "tsm_report_dir": "/sys/kernel/config/tsm/report",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--form", choices=("go", "python"), required=True)
    parser.add_argument("--gate-binary", help="a faketsm test build of tdx-gate (--form go)")
    args = parser.parse_args()

    from chutes.endpoint import client as client_mod, crypto, trust as trust_mod
    from chutes.endpoint.client import EndpointClient, EndpointHTTPError, EndpointRefusal

    tmp = tempfile.mkdtemp(prefix="tdx-gate-crosstest-")
    replay_entries = 24
    gate_proc = None
    if args.form == "go":
        app_port = free_port()
        serve(http.server.ThreadingHTTPServer((HOST, app_port), AppHandler))
        cfg_path = os.path.join(tmp, "gate.json")
        with open(cfg_path, "w") as f:
            json.dump(gate_config(app_port, replay_entries), f)
        gate_proc = subprocess.Popen([args.gate_binary, "serve", "--config", cfg_path, "--test-identity"],
                                     stdout=subprocess.DEVNULL, stderr=open(os.path.join(tmp, "gate.log"), "wb"))
    else:
        import uvicorn
        from chutes_tdx_gate.asgi import GateMiddleware

        class FakeQuoter:
            def quote(self, rd):
                q = bytearray(640)
                q[0:2], q[4:8], q[568:632] = (4).to_bytes(2, "little"), (0x81).to_bytes(4, "little"), rd
                return bytes(q)

        cfg = gate_config(9, replay_entries)
        # The gate runs in this process: its clock must not follow the client's patched time.time.
        unpatched = time.time
        app = GateMiddleware(sample_asgi_app, json.dumps(cfg).encode(), test_identity=True, quoter=FakeQuoter(),
                             clock=lambda: int(unpatched() * 1000))
        server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=8080, log_level="error", lifespan="off"))
        threading.Thread(target=server.run, daemon=True).start()
    try:
        wait_port(HOST, 8080)
        relay = Relay(HOST, 8080)
        status, body = relay.attest(secrets.token_hex(32))
        assert status == 200, (status, body)
        relay.gate_pk_b64 = json.loads(body)["public_key"]
        tls = make_tls(tmp)
        relay_port = free_port()
        relay_server = http.server.ThreadingHTTPServer((HOST, relay_port), relay_handler(relay))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls["cert.pem"], tls["key.pem"])
        relay_server.socket = ctx.wrap_socket(relay_server.socket, server_side=True)
        serve(relay_server)

        def binding_only(self, entry):
            """The quote binding check only (the other checks need real quotes)."""
            nonce = secrets.token_hex(32)
            evidence = self.fetch_evidence(entry["instance_id"], nonce)
            if set(evidence) != {"quote", "public_key"}:
                raise EndpointRefusal("endpoint_vm_attest_invalid", "evidence shape")
            quote, key = base64.b64decode(evidence["quote"]), base64.b64decode(evidence["public_key"])
            rd = hashlib.sha512(b"chutes-tdx-endpoint-attest-v1\x00" + bytes.fromhex(nonce) + key).digest()
            if (key != base64.b64decode(entry["e2e_pubkey"]) or quote[0:2] != b"\x04\x00"
                    or quote[4:8] != b"\x81\x00\x00\x00" or quote[568:632] != rd):
                raise EndpointRefusal("endpoint_vm_binding_mismatch", "binding")
            verdict = client_mod.Verdict(instance_id=entry["instance_id"], e2e_pubkey=entry["e2e_pubkey"],
                                         serving_spki_sha256=entry["serving_spki_sha256"],
                                         verified_at=client_mod._monotonic(), rows=[])
            with self._lock:
                self._verdicts[entry["instance_id"]] = verdict
            return verdict

        EndpointClient.verify_instance = binding_only

        def client(endpoint=ENDPOINT):
            value = {"schema": "chutes.endpoint-trust.v2",
                     "saved": {"at": time.time(), "client": "crosstest", "profile": "vms",
                               "origin": "https://site.example", "validator_origin": f"https://{HOST}:{relay_port}"},
                     "endpoint": {"endpoint_id": endpoint, "owner": str(uuid.uuid4()), "mode": "owner",
                                  "routes": ROUTES, "callers": []}}
            trust = trust_mod.EndpointTrust(os.path.join(tmp, endpoint + ".json"), json.dumps(value).encode(), value)
            key = "cek_" + secrets.token_hex(16) + "_" + secrets.token_urlsafe(32)
            return EndpointClient(f"https://{HOST}:{relay_port}", endpoint, key, trust, ca_file=tls["ca.pem"])

        results = []

        def case(name, fn):
            try:
                fn()
                results.append((name, None))
            except Exception as exc:  # noqa: BLE001
                results.append((name, f"{type(exc).__name__}: {exc}"))

        def expect_code(fn, status, code):
            try:
                fn()
            except EndpointHTTPError as exc:
                assert (exc.status, exc.code, exc.encrypted) == (status, code, False), (exc.status, exc.code, exc.encrypted)
                return exc
            raise AssertionError(f"expected {status} {code}")

        c = client()
        body = {"session_id": "s", "model": "m", "messages": [{"role": "user", "content": "Analyze ünïcødé ✓"}]}

        def sealed_echo():
            AppHandler.seen.clear()
            assert c.call("/v1/echo", body) == body
            path, headers, raw = AppHandler.seen[-1]
            assert path == "/v1/echo" and json.loads(raw) == body
            names = sorted(k.lower() for k in headers)
            if args.form == "go":
                assert names == ["content-length", "content-type", "host"], names
            assert headers.get("Content-Type", headers.get("content-type")) == "application/json"

        def stream():
            data = b"".join(c.call("/v1/stream", {"stream": True, "messages": []}, stream=True))
            assert data == b"".join(STREAM_EVENTS), data

        def stream_cut():
            chunks = c.call("/v1/stream-cut", {"stream": True}, stream=True)
            got = b""
            try:
                for chunk in chunks:
                    got += chunk
            except crypto.E2EError as exc:
                assert "cut short" in str(exc), exc
                assert got == STREAM_EVENTS[0]
                return
            raise AssertionError("a stream without its sealed end was accepted")

        def sealed_error():
            try:
                c.call("/v1/sealed-error", {})
            except EndpointHTTPError as exc:
                assert exc.encrypted and exc.status == 418 and exc.detail == {"error": "teapot"}, vars(exc)
                return
            raise AssertionError("the sealed 418 was not raised")

        def replay():
            c.call("/v1/echo", body)
            blob = relay.last_blob
            conn, resp = relay.e2e("/v1/echo", False, blob)
            got = (resp.status, resp.read())
            conn.close()
            assert got == (409, b'{"detail":{"code":"e2e_v2_replayed"}}'), got

        def stale():
            real = crypto.time.time
            crypto.time.time = lambda: real() - 121
            try:
                expect_code(lambda: c.call("/v1/echo", body), 400, "e2e_v2_stale")
            finally:
                crypto.time.time = real

        def future():
            real = crypto.time.time
            crypto.time.time = lambda: real() + 61
            try:
                expect_code(lambda: c.call("/v1/echo", body), 400, "e2e_v2_from_the_future")
            finally:
                crypto.time.time = real

        def wrong_path():
            relay.present_path = "/v1/sealed-error"
            try:
                expect_code(lambda: c.call("/v1/echo", body), 403, "e2e_v2_wrong_path")
            finally:
                relay.present_path = None

        def wrong_instance():
            relay.listed_instance = "5813945712345678902"
            other = client()
            try:
                expect_code(lambda: other.call("/v1/echo", body), 403, "e2e_v2_wrong_instance")
            finally:
                relay.listed_instance = INSTANCE

        def wrong_endpoint():
            expect_code(lambda: client(OTHER_ENDPOINT).call("/v1/echo", body), 403, "e2e_v2_wrong_endpoint")

        def route_not_served():
            expect_code(lambda: c.call("/v1/undeclared-at-gate", body), 404, "e2e_v2_route_not_served")

        def busy():
            # The replay cache holds replay_entries live nonces: fill it, then the next call is busy.
            for _ in range(replay_entries):
                try:
                    c.call("/v1/echo", {"messages": []})
                except EndpointHTTPError as exc:
                    if exc.code == "e2e_v2_busy":
                        break
                    raise
            exc = expect_code(lambda: c.call("/v1/echo", body), 503, "e2e_v2_busy")
            assert exc.retryable and exc.retry_after is not None and 1 <= exc.retry_after <= 180, vars(exc)

        for name, fn in (("sealed answer, the application's request", sealed_echo), ("stream", stream),
                         ("stream cut: no sealed end", stream_cut), ("sealed 418", sealed_error), ("replay 409", replay),
                         ("stale", stale), ("future", future), ("wrong path", wrong_path),
                         ("wrong instance", wrong_instance), ("wrong endpoint", wrong_endpoint),
                         ("route not served", route_not_served), ("busy (cache bound)", busy)):
            case(name, fn)
        failed = 0
        for name, error in results:
            print(f"{'ok  ' if error is None else 'FAIL'} {args.form}: {name}" + (f": {error}" if error else ""))
            failed += error is not None
        print(f"{len(results) - failed}/{len(results)} cross-test cases passed ({args.form} gate, SDK EndpointClient)")
        return 1 if failed else 0
    finally:
        if gate_proc is not None:
            gate_proc.terminate()
            gate_proc.wait(5)


if __name__ == "__main__":
    sys.exit(main())
