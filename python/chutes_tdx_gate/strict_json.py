"""Strict JSON for untrusted input, the same rules as the Go gate's ``pkg/sjson``.

Refused (``ValueError``): invalid UTF-8, a byte-order mark, a duplicate object key at any level,
an escaped lone surrogate, ``NaN`` and ``Infinity``, a number that overflows a float (Python would
read ``1e400`` as ``inf``, and an integer of any length as an int), nesting deeper than
:data:`MAX_DEPTH`, more than ``max_nodes`` values (:func:`node_count`, before anything is built)
and an object key over ``max_key_bytes`` (while parsing).
"""

from __future__ import annotations

import json
import math
import re

MAX_DEPTH = 512
#: The envelope's limits, as the Go gate's: values in one document, bytes of one object key.
MAX_NODES = 1 << 20
MAX_KEY_BYTES = 1 << 16

_STRING = re.compile(rb'"[^"]*"')
_WHITESPACE = b" \t\r\n"


def node_count(raw: bytes) -> int:
    """The number of values in a JSON document, exact when it is valid: with the escapes inside
    strings blanked (``\\\\`` first, then ``\\"``), every string replaced by one byte and the
    whitespace removed, each comma and each opening bracket starts one value more than the first,
    and an empty container holds none. Holds at most two copies of ``raw`` and one small object
    per string (:func:`count_cost`)."""
    flat = raw.replace(b"\\\\", b"__").replace(b'\\"', b"__")
    flat = _STRING.sub(b"0", flat).translate(None, _WHITESPACE)
    return 1 + flat.count(b",") + flat.count(b"[") + flat.count(b"{") - flat.count(b"[]") - flat.count(b"{}")


def count_cost(raw: bytes) -> int:
    """The most that :func:`node_count` holds besides ``raw``: two copies, and the pieces of the string
    substitution (one per quote)."""
    return 2 * len(raw) + 64 * raw.count(b'"')


def _pairs_hook(max_key_bytes: int):
    def pairs(items):
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        for key in keys:
            if len(key) * 4 > max_key_bytes and len(key.encode("utf-8", "surrogatepass")) > max_key_bytes:
                raise ValueError("key too long")
        return dict(items)

    return pairs


def _constant(_name):
    raise ValueError("NaN or Infinity")


def _float(text):
    value = float(text)
    if math.isinf(value):
        raise ValueError("number overflows a float")
    return value


def _int(text):
    # The Go gate's rule for a number without a fraction or an exponent: only one of more than 308
    # digits can overflow a float, and one that does is refused (Python's int would hold it).
    if len(text) - text.startswith("-") > 308 and math.isinf(float(text)):
        raise ValueError("number overflows a float")
    return int(text)


def _check(value) -> None:
    """Depth and lone surrogates, iteratively."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            if depth > MAX_DEPTH:
                raise ValueError("too deep")
            for key, member in item.items():
                key.encode("utf-8")  # a lone surrogate raises UnicodeEncodeError (a ValueError)
                stack.append((member, depth + 1))
        elif isinstance(item, list):
            if depth > MAX_DEPTH:
                raise ValueError("too deep")
            stack.extend((member, depth + 1) for member in item)
        elif isinstance(item, str):
            item.encode("utf-8")


def loads(raw: bytes, *, max_nodes: int | None = None, max_key_bytes: int = MAX_KEY_BYTES, nodes: int | None = None):
    """The value of one strict JSON document, else ``ValueError``. ``max_nodes`` refuses a document
    of more values before it is parsed (``nodes``: its :func:`node_count`, if already known)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("JSON input must be bytes")
    raw = bytes(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("byte-order mark")
    if max_nodes is not None and (node_count(raw) if nodes is None else nodes) > max_nodes:
        raise ValueError("too many values")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs_hook(max_key_bytes), parse_constant=_constant,
                           parse_float=_float, parse_int=_int)
    except RecursionError:
        raise ValueError("too deep") from None
    except UnicodeDecodeError as exc:
        raise ValueError("invalid UTF-8") from exc
    _check(value)
    return value


def dumps(value) -> bytes:
    """Compact UTF-8 JSON, as the gate forwards an envelope body."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
