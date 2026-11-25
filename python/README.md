# chutes-tdx-gate (Python library form)

The endpoint VM's side of Chutes' bring-your-own TDX VM endpoints for an in-process Python service:
`/attest` (configfs-tsm, the REPORTDATA rule, a per-boot ML-KEM-768 key), E2E v2 (open, the binding
checks, the replay cache, sealed answers and streams) and the health pass-through, as ASGI
middleware (`chutes_tdx_gate.asgi.GateMiddleware`) or as functions (`open_request`, `seal_answer`,
`StreamSealer`). Same behaviour and the same vectors as the Go `tdx-gate`; see the repository's
`README.md`, `BUILD.md` and `spec/`.

Run it in exactly one process with one worker (no `--workers`, `--reload` or worker recycling):
the per-boot key and the replay cache live in that process (see the repository's `BUILD.md`).

Licence: [PolyForm Shield 1.0.0](https://polyformproject.org/licenses/shield/1.0.0) (the
repository's `LICENSE`): any use, commercial use included, except providing a product that
competes with Chutes.

Required Notice: Copyright Chutes Global Corp (https://chutes.ai)
