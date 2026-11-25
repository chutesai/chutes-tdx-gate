# Building chutes-tdx-gate

## The binary

Requirements: Linux on x86_64, any Go 1.21 or later on `PATH` (only to bootstrap), `make`, and
network access to `proxy.golang.org` once (the toolchain download; dependencies are vendored).

```sh
git clone https://github.com/chutesai/chutes-tdx-gate && cd chutes-tdx-gate
git checkout vX.Y.Z            # a signed tag
make build                     # out/tdx-gate and out/tdx-gate.sha256
```

`make build` runs exactly:

```sh
GOTOOLCHAIN=go1.27.4 GOFLAGS=-mod=vendor CGO_ENABLED=0 \
  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o out/tdx-gate ./cmd/tdx-gate
```

- `GOTOOLCHAIN=go1.27.4` makes whatever `go` you have download and use exactly Go 1.27.4,
  verified against the Go checksum database. `go.mod` says `toolchain go1.27.4` and `go 1.26.0`
  (the language level `golang.org/x/crypto` v0.59.0 needs; `crypto/mlkem` and `crypto/hkdf` are in
  the standard library since Go 1.24).
- `vendor/` holds the dependencies, `golang.org/x/crypto/chacha20poly1305` (v0.59.0) and
  `golang.org/x/sys` (v0.50.0: `cpu`, and `unix` for the memfd that keeps the key across a restart),
  matching `go.sum`. `go mod verify` checks them against the checksum database.
- The binary embeds no commit (`-buildvcs=false`), so a build from a source archive is the same
  bytes as one from git: its sha256 (`tdx-gate version` prints it) identifies the build.
- The result is one static binary with no build id, no VCS stamp and no paths of your machine, so
  two builds of the same source give the same bytes. Compare `out/tdx-gate.sha256` with the release
  notes, or with your own second build.

## Reproducibility

```sh
make repro          # two builds with empty build caches, one from a copy of the tree elsewhere
make repro-docker   # two builds in fresh containers of the pinned golang image (by digest)
```

Both end with `cmp` of the two binaries and their sha256.

## Tests

```sh
make test           # go vet, the Go tests, the faketsm build's tests, and selftest over spec/vectors
make vectors        # spec/vectors/SHA256SUMS
make pytest PYTHON=/path/to/python   # the library form; python/requirements.lock pins its dependencies,
                                     # python/requirements-test.lock pytest (both with hashes)
make sealcheck PYTHON=/path/to/python   # both forms' sealers opened by sealcheck/open.py
make crosstest SDK=/path/to/sdk-copy PYTHON=/path/to/python
make mutants PYTHON=/path/to/python
```

`make crosstest` builds `out/tdx-gate-faketsm` with `-tags faketsm`: a **test build** whose
`/attest` returns unsigned synthetic quotes and which refuses to serve without `--test-identity`.
Never put it in an image; `make build` never sets the tag, and `tdx-gate version` names a test build.

## The Python library

```sh
pip install --require-hashes -r python/requirements.lock
pip install ./python
```

```python
from chutes_tdx_gate.asgi import GateMiddleware
app = GateMiddleware(your_asgi_app, "/etc/tdx-gate/config.json")
# serve `app` on 0.0.0.0:8080 with your ASGI server: ONE process, one worker
```

Run exactly **one process with one worker**: no `--workers`, no `--reload`, no worker recycling
(gunicorn's `max_requests`), because the per-boot key and the replay cache live in that process. A
middleware called from a forked process answers `/attest` 503 `attest_unavailable`, the health
path 503 and every route `e2e_v2_busy`. Turn core dumps off for it (`LimitCORE=0` in its unit) and
run without swap, as the Go unit does. The key is per process: if the process restarts, the key
changes and the validator replaces the VM.

The memory budget (`memory_budget=`, 1 GiB by default) and the parse limits work as in the Go gate.
Python holds about 7 times a request's plaintext while it parses and re-encodes it, and up to 15
times for text with `\u` escapes or characters above U+00FF. At the default budget, the Python
form's plaintext limit for such text is therefore about 60 MiB (the budget ÷ 17); a larger request
is `e2e_v2_malformed` where the Go gate admits it. `memory_budget=1536 << 20` admits every request
within the configuration's limits. Opening, parsing and sealing run in worker threads, off the
event loop.

The library uses only `cryptography` (48 or later: ML-KEM-768, HKDF-SHA256, ChaCha20-Poly1305).
`app.base` in the configuration is checked but unused in this form: the routes' `app_path` and
`app.health_path` are paths of the wrapped app.

## In an image

`chutesai/chutes-tdx-image` builds this repository at a pinned commit into its image template
(`/usr/local/bin/tdx-gate`, `deploy/systemd/tdx-gate.service`, `/etc/tdx-gate/config.json`).
