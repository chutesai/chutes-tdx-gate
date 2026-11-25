"""The instance identity from the GCE metadata server (never from a request)."""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request

from chutes_tdx_gate.config import valid_endpoint_id, valid_instance_id
from chutes_tdx_gate.e2e import Identity

METADATA_BASE = "http://169.254.169.254/computeMetadata/v1/"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _get(base: str, path: str) -> str:
    request = urllib.request.Request(base + path, headers={"Metadata-Flavor": "Google"})
    with _OPENER.open(request, timeout=5) as response:
        if response.status != 200 or response.headers.get("Metadata-Flavor") != "Google":
            raise ValueError("not a 200 from the metadata server")
        raw = response.read(1025)
    if len(raw) > 1024:
        raise ValueError("answer too long")
    return raw.decode("utf-8").strip()


def read_identity(base: str = METADATA_BASE) -> Identity:
    endpoint_id = _get(base, "instance/attributes/chutes-endpoint-id")
    instance_id = _get(base, "instance/id")
    if not valid_endpoint_id(endpoint_id) or not valid_instance_id(instance_id):
        raise ValueError("malformed endpoint or instance id")
    return Identity(endpoint_id, instance_id)


def load_identity_forever(set_identity, base: str = METADATA_BASE, stop: threading.Event | None = None) -> None:
    """Retry every 1 s, doubling to 30 s, until the metadata server answers; then call
    ``set_identity(identity)`` once."""
    delay = 1.0
    while stop is None or not stop.is_set():
        try:
            set_identity(read_identity(base))
            return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        if stop is not None:
            stop.wait(delay)
        else:
            time.sleep(delay)
        delay = min(delay * 2, 30.0)
