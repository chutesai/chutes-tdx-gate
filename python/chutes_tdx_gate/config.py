"""``chutes.tdx-gate-config.v1``, checked by the same rules as the Go gate (``pkg/gate/config.go``).

In the library form the application is the wrapped ASGI app: ``app.base`` is still checked (one
file serves both forms) but not used; ``app.health_path`` and each route's ``app_path`` are paths of
the wrapped app.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlsplit

from chutes_tdx_gate import strict_json
from chutes_tdx_gate.e2e import MIN_BLOB, Route

SCHEMA = "chutes.tdx-gate-config.v1"
SERVICE_PORT = 8080
_ROUTE = re.compile(r"(/[a-z][a-z0-9_-]*)+")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_GCE_ID = re.compile(r"[1-9][0-9]{0,19}")


def valid_route(path) -> bool:
    return isinstance(path, str) and len(path) <= 200 and _ROUTE.fullmatch(path) is not None


def valid_endpoint_id(value) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def valid_instance_id(value) -> bool:
    return isinstance(value, str) and _GCE_ID.fullmatch(value) is not None and int(value) < 2 ** 64


@dataclass
class Limits:
    max_request_bytes: int
    max_plaintext_bytes: int
    max_answer_bytes: int
    max_inflight: int
    replay_cache_entries: int


@dataclass
class GateConfig:
    listen: str
    app_base: str
    app_health_path: str
    app_timeout_s: int
    health_path: str
    routes: List[Route]
    identity_source: str
    static_endpoint_id: Optional[str]
    static_instance_id: Optional[str]
    limits: Limits
    tsm_report_dir: str


class ConfigError(ValueError):
    pass


def _closed(value, keys, name):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ConfigError(f"{name} must be an object with exactly the keys {sorted(keys)}")
    return value


def _int(value, name, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        raise ConfigError(f"{name} must be an integer in {lo}..{hi}")
    return value


def _str(value, name):
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _app_base(base: str) -> None:
    bad = ConfigError("app.base must be http://<loopback IP>:<port> (127.0.0.0/8 or [::1]) with no path, not even /")
    try:
        parts = urlsplit(base)
        port = parts.port
        addr = ipaddress.ip_address(parts.hostname or "")
    except ValueError:
        raise bad from None
    if (parts.scheme != "http" or parts.username or parts.password or parts.query or parts.fragment
            or parts.path != "" or base.endswith("?") or not addr.is_loopback or port is None or not 1 <= port <= 65535
            or port == SERVICE_PORT):
        raise bad


def parse_config(raw: bytes) -> GateConfig:
    try:
        v = strict_json.loads(raw)
    except ValueError:
        raise ConfigError("config: not strict JSON (duplicate key, invalid UTF-8 or syntax)") from None
    _closed(v, {"schema", "listen", "app", "health_path", "routes", "identity", "limits", "tsm_report_dir"}, "config")
    if v["schema"] != SCHEMA:
        raise ConfigError(f"schema must be {SCHEMA}")
    listen = _str(v["listen"], "listen")
    host, sep, port = listen.rpartition(":")
    if not sep or port != str(SERVICE_PORT):
        raise ConfigError(f"listen must be <address>:{SERVICE_PORT}")
    if host:
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            raise ConfigError("listen's address must be an IP literal") from None
    app = _closed(v["app"], {"base", "health_path", "timeout_s"}, "app")
    _app_base(_str(app["base"], "app.base"))
    if not valid_route(app["health_path"]):
        raise ConfigError("app.health_path must be a route path")
    timeout = _int(app["timeout_s"], "app.timeout_s", 1, 3600)
    health = v["health_path"]
    if not valid_route(health) or health == "/attest":
        raise ConfigError("health_path must be a route path other than /attest")
    routes = v["routes"]
    if not isinstance(routes, list) or not 1 <= len(routes) <= 64:
        raise ConfigError("routes must be a list of 1..64 routes")
    out, seen = [], set()
    for i, item in enumerate(routes):
        _closed(item, {"path", "stream", "app_path"}, f"routes[{i}]")
        path = item["path"]
        if not valid_route(path) or path in ("/attest", health) or path in seen:
            raise ConfigError(f"routes[{i}].path must be a new route path other than /attest and the health path")
        seen.add(path)
        if type(item["stream"]) is not bool:
            raise ConfigError(f"routes[{i}].stream must be a boolean")
        if not valid_route(item["app_path"]):
            raise ConfigError(f"routes[{i}].app_path must be a route path")
        out.append(Route(path, item["stream"], item["app_path"]))
    identity = v["identity"]
    if not isinstance(identity, dict):
        raise ConfigError("identity must be an object")
    source = identity.get("source")
    static_endpoint = static_instance = None
    if source == "gce-metadata":
        _closed(identity, {"source"}, "identity")
    elif source == "static":
        _closed(identity, {"source", "endpoint_id", "instance_id"}, "identity")
        static_endpoint, static_instance = identity["endpoint_id"], identity["instance_id"]
        if not valid_endpoint_id(static_endpoint) or not valid_instance_id(static_instance):
            raise ConfigError("a static identity names a lower-case UUID and a GCE instance id")
    else:
        raise ConfigError("identity.source must be gce-metadata (or static for tests)")
    lim = _closed(v["limits"], {"max_request_bytes", "max_plaintext_bytes", "max_answer_bytes", "max_inflight",
                                "replay_cache_entries"}, "limits")
    limits = Limits(
        _int(lim["max_request_bytes"], "limits.max_request_bytes", MIN_BLOB, 64 << 20),
        _int(lim["max_plaintext_bytes"], "limits.max_plaintext_bytes", 1024, 64 << 20),
        _int(lim["max_answer_bytes"], "limits.max_answer_bytes", 1024, 256 << 20),
        _int(lim["max_inflight"], "limits.max_inflight", 1, 4096),
        _int(lim["replay_cache_entries"], "limits.replay_cache_entries", 1, 1 << 20),
    )
    tsm = v["tsm_report_dir"]
    if not isinstance(tsm, str) or not os.path.isabs(tsm) or os.path.normpath(tsm) != tsm:
        raise ConfigError("tsm_report_dir must be a clean absolute path")
    return GateConfig(listen, app["base"], app["health_path"], timeout, health, out, source, static_endpoint,
                      static_instance, limits, tsm)


def load_config(path: str) -> GateConfig:
    with open(path, "rb") as stream:
        return parse_config(stream.read())
