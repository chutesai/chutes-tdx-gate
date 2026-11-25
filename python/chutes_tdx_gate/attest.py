"""The ``/attest`` route (spec section 4.1): the REPORTDATA rule, the nonce query, the answer,
and TDX quotes through configfs-tsm.

Domain separation: this module is the only code of the library that computes REPORTDATA, and only
as ``reportdata(nonce, the gate's own public key)``. No route returns a quote over caller-chosen
REPORTDATA.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import struct
import threading

TAG = b"chutes-tdx-endpoint-attest-v1"
PUBLIC_KEY_SIZE = 1184
MAX_QUOTE_BYTES = 32768
_QUERY = re.compile(rb"nonce=([0-9a-f]{64})")


def reportdata(nonce: bytes, public_key: bytes) -> bytes:
    """SHA-512(TAG || 0x00 || nonce (32 bytes) || public_key (1184 bytes))."""
    if len(nonce) != 32 or len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError("a 32-byte nonce and a 1184-byte public key")
    return hashlib.sha512(TAG + b"\x00" + bytes(nonce) + bytes(public_key)).digest()


def parse_nonce_query(query_string: bytes) -> bytes:
    """The 32 nonce bytes of exactly ``nonce=<64 lower-case hex>``, else ``ValueError``."""
    match = _QUERY.fullmatch(bytes(query_string))
    if match is None:
        raise ValueError("attest_bad_nonce")
    return bytes.fromhex(match.group(1).decode("ascii"))


def check_quote(raw: bytes, want: bytes) -> None:
    """A TDX quote v4 (version 4, TEE type 0x81) of at most 32 KiB whose REPORTDATA is ``want``."""
    if not 632 <= len(raw) <= MAX_QUOTE_BYTES:
        raise ValueError("quote size")
    version, = struct.unpack_from("<H", raw, 0)
    tee_type, = struct.unpack_from("<I", raw, 4)
    if version != 4 or tee_type != 0x81:
        raise ValueError("not a TDX quote v4")
    if raw[568:632] != want:
        raise ValueError("quote REPORTDATA differs")


def answer(quote: bytes, public_key: bytes) -> bytes:
    """The exact body: compact ``{"quote": B64, "public_key": B64}``, keys in that order."""
    return (b'{"quote":"' + base64.b64encode(quote) + b'","public_key":"' + base64.b64encode(public_key)
            + b'"}')


class TsmBusy(RuntimeError):
    """Another writer changed the report entry while the quote was made, twice."""


class ConfigfsTsm:
    """TDX quotes through configfs-tsm (Documentation/ABI/testing/configfs-tsm-report), one at a
    time: mkdir; provider must be tdx_guest; generation; inblob; outblob; generation again (the
    first plus one, else one retry, then :class:`TsmBusy`); rmdir."""

    def __init__(self, report_dir: str = "/sys/kernel/config/tsm/report"):
        self.report_dir = report_dir
        self._lock = threading.Lock()

    @staticmethod
    def _read(path: str) -> bytes:
        with open(path, "rb") as stream:
            return stream.read()

    def _generation(self, entry: str) -> int:
        return int(self._read(os.path.join(entry, "generation")).strip())

    def _once(self, report_data: bytes):
        entry = os.path.join(self.report_dir, "tdx-gate-" + secrets.token_hex(8))
        os.mkdir(entry)
        try:
            provider = self._read(os.path.join(entry, "provider")).strip()
            if provider != b"tdx_guest":
                raise RuntimeError(f"configfs-tsm provider is {provider!r}, not tdx_guest")
            first = self._generation(entry)
            # The inblob: the only file the library ever writes.
            fd = os.open(os.path.join(entry, "inblob"), os.O_WRONLY)
            try:
                if os.write(fd, report_data) != len(report_data):
                    raise RuntimeError("short inblob write")
            finally:
                os.close(fd)
            quote = self._read(os.path.join(entry, "outblob"))
            if self._generation(entry) != first + 1:
                return None
            return quote
        finally:
            os.rmdir(entry)

    def quote(self, report_data: bytes) -> bytes:
        if len(report_data) != 64:
            raise ValueError("REPORTDATA is 64 bytes")
        with self._lock:
            quote = self._once(report_data)
            if quote is None:
                quote = self._once(report_data)
                if quote is None:
                    raise TsmBusy("configfs-tsm busy")
            return quote
