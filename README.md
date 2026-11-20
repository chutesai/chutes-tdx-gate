# chutes-tdx-gate

The endpoint VM's side of Chutes' **bring-your-own Intel TDX VM endpoints**: a small program you
build from this source and run in front of your service inside your own TDX VM image. It serves
exactly what Chutes' gateway needs from the VM, on port 8080:

- `GET /attest?nonce=<64 hex>`: a TDX quote (through the kernel's configfs-tsm) whose REPORTDATA
  binds the caller's nonce to an ML-KEM-768 key the gate generates at start and keeps in memory;
- every declared route: E2E v2. It opens the gateway's encrypted request, checks its bindings
  (endpoint, instance, path, streaming flag, a fresh timestamp, a single-use nonce) before your
  service sees anything, forwards the plaintext JSON body to your service on `127.0.0.1`, and seals
  the answer (or each chunk of a stream) to a key only the gateway holds;
- your health path: passed through to your service's health URL (200 once it answers 2xx within
  4 s, else 503).

| Form | Where |
|---|---|
| `tdx-gate`, one static Go binary (`CGO_ENABLED=0`, `-trimpath`, pinned toolchain, vendored dependencies) | `cmd/`, `pkg/` |
| A systemd unit for it | `deploy/systemd/tdx-gate.service`, `deploy/config.example.json` |
| The Python library form, for an in-process Python service (ASGI middleware) | `python/` |
| The wire specification (normative) and the test vectors the gate consumes | `spec/SPEC.md`, `spec/vectors/` |
| An independent check of both forms' sealers | `sealcheck/` |

To implement the formats in your own code, `spec/` is all you need: pass every vector in
`spec/vectors/` and you are interoperable.

## Running it

1. Build: `make build` (needs any Go >= 1.21 and network access to download the pinned toolchain
   once; see `BUILD.md`). Compare `out/tdx-gate.sha256` with the release notes.
2. Install `out/tdx-gate` as `/usr/local/bin/tdx-gate` in your image, with
   `deploy/systemd/tdx-gate.service`.
3. Write `/etc/tdx-gate/config.json` (`chutes.tdx-gate-config.v1`, `deploy/config.example.json`):
   - `listen` on port 8080 (every VM endpoint serves there);
   - `app.base`: your service, `http://127.0.0.1:<port>` (a loopback IP literal only);
   - `health_path` and `routes`: exactly the health path and routes you declare for the endpoint;
     each route's `app_path` is the path on your service;
   - `identity`: `{"source": "gce-metadata"}`. The gate reads `chutes-endpoint-id` and
     `instance/id` from the metadata server (169.254.169.254) once at start; until it has both,
     every route answers `503 e2e_v2_identity_unknown` and the health path 503.
4. `tdx-gate check-config --config /etc/tdx-gate/config.json` checks the file.

Your service receives `POST <app_path>` with only `Host`, `Content-Type: application/json` and
`Content-Length`, and the body the caller sent. Its status and body are sealed together; none of
its headers reach the caller. On a stream route, a 2xx answer is streamed as it arrives (chunks of
at most 64 KiB); a sealed end is sent only after your body ended normally, so a failure mid-stream
is visible to the caller as a cut stream.

Other commands: `tdx-gate reportdata --nonce HEX --public-key-file PATH` prints the REPORTDATA rule's
value; `tdx-gate selftest --vectors spec/vectors` runs every vector; `tdx-gate version` prints the
version, the Go version and the binary's own sha256.

## Tests

`make test` (Go: unit tests, every vector, the HTTP behaviour), `make pytest` (the library form,
every vector), `make sealcheck` (both sealers against independent code), `make crosstest SDK=...` (the SDK's own `EndpointClient` against both forms on
loopback through a stand-in validator relay, and a 5,000-request differential against the SDK
runtime's `endpoint_e2e.open_request`), `make repro` (A = B), `make mutants` (every check removed
in turn must fail a test).
