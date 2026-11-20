"""The instance (server) side of E2E v2 (spec section 4.3), the SDK's ``cpu_e2e`` v2 and
``endpoint_e2e`` without the v1 paths, with the gate's stricter field rules.

``open_request`` opens a request blob and checks it in the spec's order before the application
sees anything; ``seal_answer`` and :class:`StreamSealer` seal the answer to the caller's one-time
response key, bound to the request blob's SHA-256.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import heapq
import os
import re
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from chutes_tdx_gate import strict_json

MLKEM_CT_SIZE = 1088
PUBLIC_KEY_SIZE = 1184
NONCE_SIZE = 12
TAG_SIZE = 16
MIN_BLOB = MLKEM_CT_SIZE + NONCE_SIZE + TAG_SIZE
INFO_REQ, INFO_RESP, INFO_STREAM = b"e2e-req-v2", b"e2e-resp-v2", b"e2e-stream-v2"
AAD_REQUEST, AAD_ANSWER, AAD_STREAM = b"chutes-e2e-v2 request", b"chutes-e2e-v2 answer", b"chutes-e2e-v2 stream"
CHUNK_HEAD, CHUNK_DATA, CHUNK_END = 1, 2, 3
MAX_CHUNK_DATA = 65536
MAX_AGE_MS, MAX_FUTURE_MS = 120_000, 60_000
REPLAY_CACHE_MAX = 65536
MAX_PLAINTEXT = 64 * 1024 * 1024
#: The in-flight memory budget's default (1 GiB: Python holds about 7 times a request's plaintext
#: while it parses and re-encodes it, up to 15 times for text with escapes or characters above
#: U+00FF; the Go gate's is 512 MiB) and what one parsed value is reserved at.
DEFAULT_BUDGET = 1024 * 1024 * 1024
NODE_COST = 200
FIELDS = frozenset({"v", "endpoint_id", "instance_id", "path", "stream", "nonce", "ts", "e2e_response_pk", "body"})
_NONCE = re.compile(r"[A-Za-z0-9_-]{43}")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")

#: The 15 refusal codes a VM may answer, and their statuses.
CODES = {
    "e2e_v2_undecryptable": 400, "e2e_v2_malformed": 400, "e2e_v2_stream_mismatch": 400,
    "e2e_v2_stale": 400, "e2e_v2_from_the_future": 400,
    "e2e_v2_wrong_endpoint": 403, "e2e_v2_wrong_instance": 403, "e2e_v2_wrong_path": 403,
    "e2e_v2_route_not_served": 404, "e2e_v2_method": 405, "e2e_v2_replayed": 409,
    "e2e_v2_app_failed": 502, "e2e_v2_answer_too_large": 502,
    "e2e_v2_identity_unknown": 503, "e2e_v2_busy": 503,
}


class Refusal(Exception):
    """An unsealed refusal: one of the 15 codes, its status, and a Retry-After (1..180 s) only for
    ``e2e_v2_busy``."""

    def __init__(self, status: int, code: str, retry_after: Optional[int] = None):
        if CODES.get(code) != status:
            raise ValueError(f"refusal {status} {code} is not one of the enumerated 15")
        if retry_after is not None and code != "e2e_v2_busy":
            raise ValueError("Retry-After goes with e2e_v2_busy only")
        if code == "e2e_v2_busy" and retry_after is None:
            retry_after = 1
        self.status, self.code = status, code
        self.retry_after = None if retry_after is None else min(max(int(retry_after), 1), 180)
        super().__init__(f"{status} {code}")

    def body(self) -> bytes:
        """The exact compact body ``{"detail":{"code":"<code>"}}``."""
        return b'{"detail":{"code":"' + self.code.encode("ascii") + b'"}}'


def refusal(code: str) -> Refusal:
    return Refusal(CODES[code], code)


def busy(retry_after: int) -> Refusal:
    return Refusal(503, "e2e_v2_busy", retry_after)


class Budget:
    """The memory every in-flight request holds together. A request reserves (``Lease.charge``)
    what it is about to hold, from estimates that bound Python's objects, before it allocates them;
    ``e2e_v2_busy`` when the budget cannot hold it now, ``e2e_v2_malformed`` when it never could.
    Thread-safe (requests are opened in worker threads)."""

    def __init__(self, max_bytes: int = DEFAULT_BUDGET):
        self.max = int(max_bytes)
        self.used = 0
        self.peak = 0
        self._lock = threading.Lock()

    def lease(self) -> "Lease":
        return Lease(self)


class Lease:
    """One request's share of a :class:`Budget`; ``release()`` gives it all back."""

    def __init__(self, budget: Budget):
        self._budget = budget
        self.held = 0

    def charge(self, n: int, *, answer: bool = False) -> None:
        """Reserve ``n`` more bytes, else raise ``e2e_v2_busy`` (Retry-After 1) when other requests
        hold the budget now, or ``e2e_v2_malformed`` when this request needs more than the whole
        budget (it could never be admitted). An answer's charge (``answer=True``: the application
        has run) raises ``e2e_v2_answer_too_large`` instead: busy is only ever answered before the
        application sees anything, since a caller can resend a busy request."""
        n = int(n)
        if n <= 0:
            return
        b = self._budget
        if self.held + n > b.max:
            raise refusal("e2e_v2_answer_too_large" if answer else "e2e_v2_malformed")
        with b._lock:
            if n > b.max - b.used:
                raise refusal("e2e_v2_answer_too_large") if answer else busy(1)
            b.used += n
            b.peak = max(b.peak, b.used)
        self.held += n

    def refund(self, n: int) -> None:
        n = min(int(n), self.held)
        with self._budget._lock:
            self._budget.used -= n
        self.held -= n

    def release(self) -> None:
        self.refund(self.held)


def _charge(lease: Optional[Lease], n: int) -> None:
    if lease is not None:
        lease.charge(n)


class ServerKey:
    """The per-boot ML-KEM-768 key pair, in memory only (never written)."""

    def __init__(self, private: MLKEM768PrivateKey):
        self._private = private
        self.public_key = private.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> "ServerKey":
        return cls(MLKEM768PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed64: bytes) -> "ServerKey":
        """From the 64-byte seed d || z (the vectors' form; tests only)."""
        return cls(MLKEM768PrivateKey.from_seed_bytes(bytes(seed64)))

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self._private.decapsulate(ciphertext)


@dataclass(frozen=True)
class Identity:
    """The endpoint and instance this gate serves; ``None`` while unknown."""

    endpoint_id: Optional[str] = None
    instance_id: Optional[str] = None

    @property
    def known(self) -> bool:
        return bool(self.endpoint_id) and bool(self.instance_id)


@dataclass(frozen=True)
class Route:
    path: str
    stream: bool
    app_path: str


class Routes:
    """The declared routes by (path, stream)."""

    def __init__(self, routes: Iterable):
        self._table = {}
        for item in routes:
            route = item if isinstance(item, Route) else Route(item["path"], item["stream"], item.get("app_path", item["path"]))
            self._table[(route.path, route.stream)] = route

    def get(self, path: str, stream: bool) -> Optional[Route]:
        return self._table.get((path, stream))

    def __iter__(self):
        return iter(self._table.values())


class ReplayCache:
    """Every admitted nonce until its ts leaves the window (the SDK's ``ReplayCache``): a live
    entry is never evicted; at the bound a new request is refused busy until the oldest leaves; a
    request not newer than a forgotten entry is stale."""

    def __init__(self, max_entries: int = REPLAY_CACHE_MAX):
        self.max_entries = max_entries
        self._seen: dict = {}
        self._heap: list = []
        self.floor = -1
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def _expire(self, now_ms: int) -> None:
        while self._heap and self._heap[0][0] < now_ms - MAX_AGE_MS:
            ts, nonce = heapq.heappop(self._heap)
            del self._seen[nonce]
            self.floor = max(self.floor, ts)

    def admit(self, nonce: str, ts: int, now_ms: int) -> None:
        with self._lock:
            self._expire(now_ms)
            if ts < now_ms - MAX_AGE_MS or ts <= self.floor:
                raise refusal("e2e_v2_stale")
            if ts > now_ms + MAX_FUTURE_MS:
                raise refusal("e2e_v2_from_the_future")
            if nonce in self._seen:
                raise refusal("e2e_v2_replayed")
            if len(self._seen) >= self.max_entries:
                leaves = self._heap[0][0] + MAX_AGE_MS - now_ms
                raise busy(-(-leaves // 1000))
            self._seen[nonce] = ts
            heapq.heappush(self._heap, (ts, nonce))


@dataclass
class Opened:
    """An admitted request: the body the application gets (a dict), its route, and what sealing
    the answer needs."""

    body: dict
    path: str
    stream: bool
    route: Route
    nonce: str
    response_key: bytes = field(repr=False)
    digest: bytes = field(repr=False)

    def body_bytes(self) -> bytes:
        """The JSON encoding of the envelope's body, as the application receives it."""
        return strict_json.dumps(self.body)


def _derive(shared: bytes, ct: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ct[:16], info=info).derive(shared)


def _open_blob(key: ServerKey, blob: bytes) -> bytes:
    if len(blob) < MIN_BLOB:
        raise ValueError("short blob")
    ct, nonce, sealed = blob[:MLKEM_CT_SIZE], blob[MLKEM_CT_SIZE:MLKEM_CT_SIZE + NONCE_SIZE], blob[MLKEM_CT_SIZE + NONCE_SIZE:]
    shared = key.decapsulate(ct)
    return ChaCha20Poly1305(_derive(shared, ct, INFO_REQ)).decrypt(nonce, sealed, AAD_REQUEST)


def _gunzip(data: bytes, limit: int, lease: Optional[Lease] = None) -> bytes:
    """Exactly one gzip member of at most ``limit`` bytes with nothing after it. Its size, the
    member's trailer (ISIZE, which zlib checks), is reserved before a byte is inflated."""
    if len(data) < 18:
        raise refusal("e2e_v2_malformed")
    size = int.from_bytes(data[-4:], "little")
    if size > limit:
        raise refusal("e2e_v2_malformed")
    _charge(lease, size + 1)
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        plain = inflater.decompress(data, size + 1)
    except zlib.error:
        raise refusal("e2e_v2_malformed") from None
    if len(plain) != size or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
        raise refusal("e2e_v2_malformed")
    return plain


_WIDE = re.compile(rb"[\xf0-\xf4]|\\u")
_MEDIUM = re.compile(rb"[\xc4-\xef]")


def parse_cost(plain: bytes, nodes: int) -> int:
    """The most that parsing ``plain`` and re-encoding its body hold at once, in bytes. Python's strings
    take 4 bytes per character after an astral character or any ``\\u`` escape, 2 after one above
    U+00FF, else 1 (``width``); the decoder and the encoder each build their text with room to grow
    and a final copy. Re-encoding holds the plaintext, the parsed strings, the encoder's two texts
    and the encoded bytes: (3 + 3 * width) times the plaintext, plus ``NODE_COST`` per value."""
    width = 4 if _WIDE.search(plain) else 2 if _MEDIUM.search(plain) else 1
    return (3 + 3 * width) * len(plain) + NODE_COST * nodes


def _text(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and value.isprintable()


def _envelope(plain: bytes, lease: Optional[Lease] = None) -> dict:
    malformed = refusal("e2e_v2_malformed")
    if plain.startswith(b"\xef\xbb\xbf"):
        raise malformed
    counting = strict_json.count_cost(plain)
    _charge(lease, counting)  # given back once the count is known
    nodes = strict_json.node_count(plain)
    if lease is not None:
        lease.refund(counting)
    if nodes > strict_json.MAX_NODES:
        raise malformed
    _charge(lease, parse_cost(plain, nodes))
    try:
        value = strict_json.loads(plain, max_nodes=strict_json.MAX_NODES, nodes=nodes)
    except ValueError:
        raise malformed from None
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["v"]) is not int
        or value["v"] != 2
        or not _text(value["endpoint_id"])
        or not _text(value["instance_id"])
        or not _text(value["path"])
        or not value["path"].startswith("/")
        or type(value["stream"]) is not bool
        or not isinstance(value["nonce"], str)
        or _NONCE.fullmatch(value["nonce"]) is None
        or type(value["ts"]) is not int
        # orjson (the SDK runtime) reads an integer literal outside 64 bits as a float, not a ts
        or not -(2 ** 63) <= value["ts"] <= 2 ** 64 - 1
        or not isinstance(value["e2e_response_pk"], str)
        or _B64.fullmatch(value["e2e_response_pk"]) is None
        or not isinstance(value["body"], dict)
    ):
        raise malformed
    try:
        response_pk = base64.b64decode(value["e2e_response_pk"], validate=True)
        # FIPS 203's modulus check: a key that fails it could never be sealed to.
        MLKEM768PublicKey.from_public_bytes(response_pk)
    except ValueError:
        raise malformed from None
    if len(response_pk) != PUBLIC_KEY_SIZE:
        raise malformed
    value["e2e_response_pk"] = response_pk
    return value


def open_request(key: ServerKey, blob: bytes, *, presented_path: str, method: str, routes, identity: Identity,
                 cache: ReplayCache, now_ms: Optional[int] = None, max_plaintext: int = MAX_PLAINTEXT,
                 lease: Optional[Lease] = None) -> Opened:
    """Open, check and admit one request, or raise :class:`Refusal`, in this order: open; gunzip
    and the closed envelope; identity known; endpoint_id; instance_id; method POST; presented path
    = bound path; (path, POST, stream) served; body.stream; ts not stale; not in the future; nonce
    not admitted; cache not full; then the nonce is admitted (consumed last).

    With ``lease`` (a :class:`Budget`'s), the opened plaintext, the inflated envelope, the node
    count and the parse (which covers ``Opened.body_bytes()`` too) are reserved before they are
    made: ``e2e_v2_busy`` when the budget cannot hold one now. Blocking work: call it in a thread."""
    blob = bytes(blob)
    _charge(lease, len(blob))
    try:
        plain = _open_blob(key, blob)
    except (ValueError, InvalidTag):
        raise refusal("e2e_v2_undecryptable") from None
    env = _envelope(_gunzip(plain, max_plaintext, lease), lease)
    if not identity.known:
        raise refusal("e2e_v2_identity_unknown")
    if env["endpoint_id"] != identity.endpoint_id:
        raise refusal("e2e_v2_wrong_endpoint")
    if env["instance_id"] != identity.instance_id:
        raise refusal("e2e_v2_wrong_instance")
    if method.upper() != "POST":
        raise refusal("e2e_v2_method")
    if presented_path != env["path"]:
        raise refusal("e2e_v2_wrong_path")
    table = routes if isinstance(routes, Routes) else Routes(routes)
    route = table.get(env["path"], env["stream"])
    if route is None:
        raise refusal("e2e_v2_route_not_served")
    stated = env["body"].get("stream", False)
    if type(stated) is not bool or stated is not env["stream"]:
        raise refusal("e2e_v2_stream_mismatch")
    cache.admit(env["nonce"], env["ts"], int(time.time() * 1000) if now_ms is None else now_ms)
    return Opened(body=env["body"], path=env["path"], stream=env["stream"], route=route, nonce=env["nonce"],
                  response_key=env["e2e_response_pk"], digest=hashlib.sha256(blob).digest())


def _status_header(status: int) -> bytes:
    return b'{"v":2,"status":' + str(int(status)).encode("ascii") + b"}"


def seal_cost(n: int) -> int:
    """The most that sealing an answer of ``n`` bytes and its wire body hold at once (reserved first)."""
    return 6 * n + (2 << 20)


def seal_answer(opened: Opened, status: int, body: bytes) -> bytes:
    """The sealed answer blob (status 200..599 and the body together)."""
    if type(status) is not int or not 200 <= status <= 599:
        raise ValueError("status outside 200..599")
    plain = gzip.compress(_status_header(status) + b"\n" + bytes(body), mtime=0)
    shared, ct = MLKEM768PublicKey.from_public_bytes(opened.response_key).encapsulate()
    nonce = os.urandom(NONCE_SIZE)
    return ct + nonce + ChaCha20Poly1305(_derive(shared, ct, INFO_RESP)).encrypt(nonce, plain, AAD_ANSWER + opened.digest)


def answer_body(blob: bytes) -> bytes:
    """The sealed answer's wire body ``{"e2e":"<B64>"}``."""
    return b'{"e2e":"' + base64.b64encode(blob) + b'"}'


def _event(name: bytes, raw: bytes) -> bytes:
    return b'data: {"' + name + b'":"' + base64.b64encode(raw) + b'"}\n\n'


class StreamSealer:
    """One stream answer's events: ``init_event()``, ``head(status)``, ``data(chunk)`` (at most
    64 KiB each), and ``end()`` only after the application's body ended normally."""

    def __init__(self, opened: Opened):
        shared, ct = MLKEM768PublicKey.from_public_bytes(opened.response_key).encapsulate()
        self._aead = ChaCha20Poly1305(_derive(shared, ct, INFO_STREAM))
        self._ct = ct
        self._aad = AAD_STREAM + opened.digest
        self._seq = 0
        self._ended = False

    def init_event(self) -> bytes:
        return _event(b"e2e_init", self._ct)

    def _chunk(self, kind: int, payload: bytes) -> bytes:
        if self._ended:
            raise ValueError("the stream already ended")
        nonce = os.urandom(NONCE_SIZE)
        plain = struct.pack(">BQ", kind, self._seq) + bytes(payload)
        self._seq += 1
        return _event(b"e2e", nonce + self._aead.encrypt(nonce, plain, self._aad))

    def head(self, status: int) -> bytes:
        if self._seq != 0:
            raise ValueError("the head is chunk 0")
        return self._chunk(CHUNK_HEAD, _status_header(status))

    def data(self, chunk: bytes) -> bytes:
        if self._seq == 0:
            raise ValueError("data before the head")
        if len(chunk) > MAX_CHUNK_DATA:
            raise ValueError("data chunk over 65536 bytes")
        return self._chunk(CHUNK_DATA, chunk)

    def end(self) -> bytes:
        if self._seq == 0:
            raise ValueError("end before the head")
        event = self._chunk(CHUNK_END, b"")
        self._ended = True
        return event
