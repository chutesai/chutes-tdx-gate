"""``GateMiddleware``: the gate as ASGI middleware around an in-process Python service.

It serves ``/attest``, the health path (pass-through to the wrapped app's ``app.health_path``) and
every other path as an E2E v2 route, exactly as ``tdx-gate`` does (spec sections 4.1, 4.3,
4.4). The wrapped app receives a plain ``POST <app_path>`` with only ``host``, ``content-type:
application/json`` and ``content-length`` headers and the envelope's body as JSON; its answer is
sealed (status and body; no header passes) or, on a stream route with a 2xx, streamed as sealed
chunks with a sealed end only after the app's body ended normally.

Logs carry the route (a configured one), the status and the refusal code: no body, no envelope
field and no decrypted byte.

**One process.** The per-boot key and the replay cache live in this object: run exactly one
process with one worker (no ``--workers``, no ``--reload``, no worker recycling such as gunicorn's
``max_requests``), with core dumps off and no swap. A middleware called from another process than
the one that made it (a fork) answers ``/attest`` 503 ``attest_unavailable``, the health path 503
and every E2E route ``e2e_v2_busy``. The key is per process: if the process restarts, the key
changes and the validator replaces the VM (the Go gate keeps its key across a restart instead).

**Memory.** All in-flight requests together hold at most ``memory_budget`` bytes (1 GiB): each
reserves its body, its plaintext, Python's objects for the parse and the re-encoded body, and its
answer before making them (``e2e_v2_busy`` when the budget is held by others, ``e2e_v2_malformed``
when one request alone needs more than all of it; after the application ran, an answer the budget
cannot hold is ``e2e_v2_answer_too_large``, never busy). Parsing a body costs up to 15 times its
plaintext for text with ``\\u`` escapes or characters above U+00FF (7 times for ASCII), so the
Python form's effective plaintext limit for such text is about the budget ÷ 17 (about 60 MiB at
the default; a larger request is ``e2e_v2_malformed`` where the Go gate admits it). A budget of
1.5 GiB (``memory_budget=1536 << 20``) admits every request within the configuration's limits.
Opening, parsing and sealing run in worker threads, off the event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Optional

from chutes_tdx_gate import attest
from chutes_tdx_gate.config import ConfigError, GateConfig, load_config, parse_config
from chutes_tdx_gate.e2e import (
    DEFAULT_BUDGET,
    MAX_CHUNK_DATA,
    Budget,
    Identity,
    Refusal,
    ReplayCache,
    Routes,
    ServerKey,
    StreamSealer,
    answer_body,
    busy,
    open_request,
    refusal,
    seal_answer,
    seal_cost,
)
from chutes_tdx_gate.metadata import METADATA_BASE, load_identity_forever

log = logging.getLogger("chutes_tdx_gate")
HEALTH_APP_TIMEOUT = 4.0
_DONE, _FAILED = object(), object()


class _AppCall:
    """One in-process call of the wrapped app: its messages through a bounded queue."""

    def __init__(self, app, method: str, path: str, body: bytes):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._finished = asyncio.Event()
        headers = [(b"host", b"127.0.0.1"), (b"content-type", b"application/json"),
                   (b"content-length", str(len(body)).encode("ascii"))] if method == "POST" else [(b"host", b"127.0.0.1")]
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": path, "raw_path": path.encode("ascii"), "root_path": "",
            "query_string": b"", "headers": headers, "client": ("127.0.0.1", 0), "server": ("127.0.0.1", 0),
        }
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await self._finished.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            await self.queue.put(message)

        async def run():
            try:
                await app(scope, receive, send)
                await self.queue.put(_DONE)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - any failure of the app is e2e_v2_app_failed
                await self.queue.put(_FAILED)

        self.task = asyncio.create_task(run())

    async def next(self, timeout: float):
        return await asyncio.wait_for(self.queue.get(), timeout)

    async def close(self):
        self._finished.set()
        if not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


#: What a stream answer holds (its chunks and events), reserved with every request.
STREAM_RESERVE = 1 << 20


def min_budget(limits) -> int:
    """The smallest ``memory_budget`` that admits one request at ``limits`` with an ASCII body: its
    body read and opened, the inflated envelope, its parse and re-encoding (``parse_cost``), and
    the largest answer collected and sealed. A body with ``\\u`` escapes or characters above U+00FF
    costs more to parse (up to 15 times its plaintext): such a request near ``max_plaintext_bytes``
    needs a budget of about 15 times that limit (README, "Memory")."""
    return (STREAM_RESERVE + 4 * (limits.max_request_bytes + 1) + 7 * (limits.max_plaintext_bytes + 1)
            + 8 * limits.max_answer_bytes + (2 << 20))


class GateMiddleware:
    """``GateMiddleware(app, config)``: ``config`` is a :class:`GateConfig`, a path, or the JSON
    bytes of ``chutes.tdx-gate-config.v1``. A static identity needs ``test_identity=True`` (tests
    only). ``key`` and ``quoter`` default to a fresh per-boot key and configfs-tsm;
    ``memory_budget`` is the in-flight memory budget in bytes (at least :func:`min_budget`)."""

    def __init__(self, app, config, *, test_identity: bool = False, key: Optional[ServerKey] = None,
                 quoter=None, metadata_base: str = METADATA_BASE, clock=None, start_identity: bool = True,
                 memory_budget: int = DEFAULT_BUDGET):
        if isinstance(config, (bytes, bytearray)):
            config = parse_config(bytes(config))
        elif isinstance(config, (str, os.PathLike)):
            config = load_config(os.fspath(config))
        if not isinstance(config, GateConfig):
            raise ConfigError("config must be a GateConfig, a path or JSON bytes")
        if (config.identity_source == "static") != bool(test_identity):
            raise ConfigError("a static identity goes with test_identity=True only (tests)")
        if memory_budget < min_budget(config.limits):
            raise ConfigError(f"memory_budget {memory_budget} cannot hold one request at the configured limits "
                              f"({min_budget(config.limits)} bytes)")
        self.app = app
        self.config = config
        self.budget = Budget(memory_budget)
        self._pid = os.getpid()
        self.key = key or ServerKey.generate()
        self.quoter = quoter or attest.ConfigfsTsm(config.tsm_report_dir)
        self.routes = Routes(config.routes)
        self.cache = ReplayCache(config.limits.replay_cache_entries)
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._identity = Identity()
        self._inflight = 0
        self._lock = threading.Lock()
        if config.identity_source == "static":
            self._identity = Identity(config.static_endpoint_id, config.static_instance_id)
        elif start_identity:
            threading.Thread(target=load_identity_forever, args=(self.set_identity, metadata_base), daemon=True).start()

    @property
    def public_key(self) -> bytes:
        return self.key.public_key

    @property
    def identity(self) -> Identity:
        return self._identity

    def set_identity(self, identity: Identity) -> None:
        self._identity = identity
        log.info("identity known")

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        path = scope["path"]
        if os.getpid() != self._pid:
            # A forked worker: this process does not hold the key /attest would bind.
            log.error("GateMiddleware called from another process than the one that made it; run one process")
            if path == "/attest":
                await self._reply(send, 503, b'{"detail":{"code":"attest_unavailable"}}',
                                  [(b"content-type", b"application/json")])
            elif path == self.config.health_path:
                await self._reply(send, 503)
            else:
                await self._refuse(send, busy(1))
            return
        if path == "/attest":
            return await self._attest(scope, send)
        if path == self.config.health_path:
            return await self._health(scope, send)
        return await self._e2e(scope, receive, send)

    @staticmethod
    async def _reply(send, status: int, body: bytes = b"", headers=()):
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-length", str(len(body)).encode("ascii")), *headers]})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def _attest(self, scope, send):
        if scope["method"] != "GET":
            await self._reply(send, 405, headers=[(b"allow", b"GET")])
            return
        json_type = [(b"content-type", b"application/json")]
        try:
            nonce = attest.parse_nonce_query(scope.get("query_string", b""))
        except ValueError:
            await self._reply(send, 400, b'{"detail":{"code":"attest_bad_nonce"}}', json_type)
            log.info("attest status=400 code=attest_bad_nonce")
            return
        rd = attest.reportdata(nonce, self.key.public_key)
        try:
            quote = await asyncio.to_thread(self.quoter.quote, rd)
            attest.check_quote(quote, rd)
        except attest.TsmBusy:
            await self._reply(send, 503, b'{"detail":{"code":"attest_busy"}}', json_type)
            return
        except Exception:  # noqa: BLE001 - any other failure is unavailable
            await self._reply(send, 503, b'{"detail":{"code":"attest_unavailable"}}', json_type)
            return
        await self._reply(send, 200, attest.answer(quote, self.key.public_key), json_type)
        log.info("attest status=200")

    async def _health(self, scope, send):
        if scope["method"] != "GET":
            await self._reply(send, 405, headers=[(b"allow", b"GET")])
            return
        status = 503
        if self._identity.known and await self._app_healthy():
            status = 200
        await self._reply(send, status)
        log.info("health status=%d", status)

    async def _app_healthy(self) -> bool:
        call = _AppCall(self.app, "GET", self.config.app_health_path, b"")
        try:
            message = await call.next(HEALTH_APP_TIMEOUT)
            return isinstance(message, dict) and message.get("type") == "http.response.start" and 200 <= message["status"] <= 299
        except asyncio.TimeoutError:
            return False
        finally:
            await call.close()

    async def _refuse(self, send, ref: Refusal, route: str = "-"):
        headers = [(b"content-type", b"application/json")]
        if ref.code == "e2e_v2_busy":
            headers.append((b"retry-after", str(ref.retry_after).encode("ascii")))
        await self._reply(send, ref.status, ref.body(), headers)
        log.info("e2e route=%s status=%d code=%s", route, ref.status, ref.code)

    async def _read_body(self, receive, limit: int, lease) -> Optional[bytes]:
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return None
            chunk = message.get("body", b"")
            lease.charge(3 * len(chunk))  # the bytearray's growth and the final copy
            body.extend(chunk)
            if len(body) > limit:
                return None
            if not message.get("more_body", False):
                return bytes(body)

    async def _e2e(self, scope, receive, send):
        with self._lock:
            if self._inflight >= self.config.limits.max_inflight:
                full = True
            else:
                full = False
                self._inflight += 1
        if full:
            await self._refuse(send, busy(1))
            return
        lease = self.budget.lease()
        try:
            try:
                # A stream's buffers, reserved before the nonce is used: busy is answered only
                # before the application sees anything.
                lease.charge(STREAM_RESERVE)
                blob = await self._read_body(receive, self.config.limits.max_request_bytes, lease)
                if blob is None:
                    await self._refuse(send, refusal("e2e_v2_malformed"))
                    return
                # Decrypting, inflating and parsing run in a worker thread, off the event loop.
                opened = await asyncio.to_thread(
                    open_request, self.key, blob, presented_path=scope["path"], method=scope["method"],
                    routes=self.routes, identity=self._identity, cache=self.cache, now_ms=self._clock(),
                    max_plaintext=self.config.limits.max_plaintext_bytes, lease=lease)
            except Refusal as ref:
                await self._refuse(send, ref)
                return
            await self._forward(send, opened, lease)
        finally:
            lease.release()
            with self._lock:
                self._inflight -= 1

    async def _forward(self, send, opened, lease):
        route = opened.route.path
        timeout = float(self.config.app_timeout_s)
        try:
            body = await asyncio.to_thread(opened.body_bytes)  # reserved with the parse
        except ValueError:
            await self._refuse(send, refusal("e2e_v2_malformed"), route)
            return
        call = _AppCall(self.app, "POST", opened.route.app_path, body)
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            start = await call.next(timeout)
            # 1xx, 204 and 304 cannot carry a sealed answer (spec section 4.3).
            if (not isinstance(start, dict) or start.get("type") != "http.response.start"
                    or not 200 <= start["status"] <= 599 or start["status"] in (204, 304)):
                await self._refuse(send, refusal("e2e_v2_app_failed"), route)
                return
            status = start["status"]
            if opened.stream and 200 <= status <= 299:
                await self._stream(send, call, opened, status, timeout)  # reserved with the request
                return
            collected = bytearray()
            while True:
                left = deadline - asyncio.get_running_loop().time()
                message = await call.next(max(left, 0.001))
                if message is _DONE or message is _FAILED or message.get("type") != "http.response.body":
                    await self._refuse(send, refusal("e2e_v2_app_failed"), route)
                    return
                chunk = message.get("body", b"")
                if len(collected) + len(chunk) > self.config.limits.max_answer_bytes:
                    await self._refuse(send, refusal("e2e_v2_answer_too_large"), route)
                    return
                lease.charge(2 * len(chunk), answer=True)
                collected.extend(chunk)
                if not message.get("more_body", False):
                    break
            lease.charge(seal_cost(len(collected)), answer=True)
            wire = await asyncio.to_thread(lambda: answer_body(seal_answer(opened, status, bytes(collected))))
            await self._reply(send, status, wire, [(b"content-type", b"application/json")])
            log.info("e2e route=%s status=%d", route, status)
        except Refusal as ref:
            await self._refuse(send, ref, route)
        except asyncio.TimeoutError:
            await self._refuse(send, refusal("e2e_v2_app_failed"), route)
        finally:
            await call.close()

    async def _stream(self, send, call: _AppCall, opened, status: int, timeout: float):
        route = opened.route.path
        sealer = StreamSealer(opened)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]})
        await send({"type": "http.response.body", "body": sealer.init_event() + sealer.head(status), "more_body": True})
        ended = False
        try:
            while True:
                message = await call.next(timeout)
                if message is _DONE or message is _FAILED or message.get("type") != "http.response.body":
                    break  # the app failed or stopped without finishing its body: no sealed end
                data = message.get("body", b"")
                for start in range(0, len(data), MAX_CHUNK_DATA):
                    await send({"type": "http.response.body", "body": sealer.data(data[start:start + MAX_CHUNK_DATA]),
                                "more_body": True})
                if not message.get("more_body", False):
                    await send({"type": "http.response.body", "body": sealer.end(), "more_body": True})
                    ended = True
                    break
        except asyncio.TimeoutError:
            pass
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        log.info("e2e route=%s status=200%s", route, "" if ended else " code=stream_cut")
