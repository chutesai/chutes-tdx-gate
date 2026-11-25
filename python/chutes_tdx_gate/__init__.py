"""chutes-tdx-gate, the Python library form: the endpoint VM's side of Chutes' bring-your-own TDX VM
endpoints (``/attest``, E2E v2, the health pass-through) for an in-process Python service.

    reportdata(nonce, public_key) -> bytes
    ConfigfsTsm(report_dir).quote(report_data) -> bytes
    ServerKey.generate(), ServerKey.from_seed(seed64)
    open_request(key, blob, *, presented_path, method, routes, identity, cache, now_ms) -> Opened
        (raises Refusal(status, code))
    seal_answer(opened, status, body) -> bytes
    StreamSealer(opened): init_event(), head(status), data(chunk), end()
    asgi.GateMiddleware(app, config, *, memory_budget=1 GiB): one process, one worker

The wire format and the vectors are in ``spec/`` of the repository.
"""

from chutes_tdx_gate.attest import ConfigfsTsm, TsmBusy, check_quote, parse_nonce_query, reportdata
from chutes_tdx_gate.e2e import (
    CODES,
    Budget,
    Identity,
    Opened,
    Refusal,
    ReplayCache,
    Route,
    Routes,
    ServerKey,
    StreamSealer,
    answer_body,
    open_request,
    seal_answer,
)

__version__ = "0.1.0"

__all__ = [
    "Budget", "CODES", "ConfigfsTsm", "Identity", "Opened", "Refusal", "ReplayCache", "Route", "Routes", "ServerKey",
    "StreamSealer", "TsmBusy", "answer_body", "check_quote", "open_request", "parse_nonce_query", "reportdata",
    "seal_answer",
]
