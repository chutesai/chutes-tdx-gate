# chutes-tdx-gate. Every target is documented in BUILD.md.
#
# The toolchain is pinned: any Go >= 1.21 on PATH downloads exactly this release (verified against
# sum.golang.org) and builds with it. Dependencies are vendored (vendor/, go.sum).
GOTOOLCHAIN := go1.27.4
export GOTOOLCHAIN
export GOFLAGS := -mod=vendor
export CGO_ENABLED := 0
GO ?= go
PYTHON ?= python3
OUT := out
BUILD = $(GO) build -trimpath -buildvcs=false -ldflags="-s -w -buildid="
# The pinned image for `make repro-docker` (golang:1.27.4-bookworm, the index digest of 2026-11-16).
GO_IMAGE := golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea

.PHONY: build test vectors pytest sealcheck crosstest repro repro-docker mutants clean

build:
	$(BUILD) -o $(OUT)/tdx-gate ./cmd/tdx-gate
	cd $(OUT) && sha256sum tdx-gate | tee tdx-gate.sha256

test: build
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -tags faketsm ./cmd/...
	$(OUT)/tdx-gate selftest --vectors spec/vectors

vectors:
	cd spec/vectors && sha256sum -c SHA256SUMS

# The Python library form: a Python with cryptography >= 48 and pytest (python/requirements.lock).
pytest:
	cd python && PYTHONPATH=. $(PYTHON) -m pytest -q -p no:cacheprovider tests

# Both forms' sealers (Go: SealAnswer, StreamSealer; Python: seal_answer, StreamSealer) seal
# answers and a stream; sealcheck/open.py opens them with code that shares nothing with either
# (spec/vectors/mlkem768.py, HKDF and ChaCha20-Poly1305 written out in Python) and checks every byte.
sealcheck:
	mkdir -p $(OUT)
	$(GO) run ./sealcheck/emit > $(OUT)/sealed-go.json
	PYTHONPATH=python $(PYTHON) sealcheck/emit.py > $(OUT)/sealed-python.json
	python3 -I sealcheck/open.py $(OUT)/sealed-go.json $(OUT)/sealed-python.json

# Cross-tests against the SDK (SDK= a `git archive` copy of the Chutes SDK source with
# chutes.endpoint; its Python needs pqcrypto, orjson, loguru, requests and uvicorn).
crosstest:
	@test -n "$(SDK)" || (echo "set SDK=<copy of the SDK source>"; exit 2)
	$(GO) build -trimpath -buildvcs=false -tags faketsm -o $(OUT)/tdx-gate-faketsm ./cmd/tdx-gate
	PYTHONPATH=$(SDK):python $(PYTHON) crosstest/differential.py --count 5000 --corpus $(OUT)/diff-corpus.json
	DIFF_CORPUS=$(abspath $(OUT))/diff-corpus.json $(GO) test ./pkg/e2ev2 -run TestDifferentialCorpus -v
	PYTHONPATH=$(SDK):python $(PYTHON) crosstest/crosstest.py --form go --gate-binary $(OUT)/tdx-gate-faketsm
	PYTHONPATH=$(SDK):python $(PYTHON) crosstest/crosstest.py --form python

# Two builds with empty build caches, one from a copy of the tree at another path: the bytes must
# be equal. Compare the sha256 with the release notes (or with a build on another machine).
repro:
	rm -rf $(OUT)/repro && mkdir -p $(OUT)/repro/src-b
	tar --exclude=./out --exclude=./.git -cf - . | tar -xf - -C $(OUT)/repro/src-b
	GOCACHE=$(abspath $(OUT))/repro/cache-a $(BUILD) -o $(OUT)/repro/a/tdx-gate ./cmd/tdx-gate
	cd $(OUT)/repro/src-b && GOCACHE=$(abspath $(OUT))/repro/cache-b $(BUILD) -o $(abspath $(OUT))/repro/b/tdx-gate ./cmd/tdx-gate
	cmp $(OUT)/repro/a/tdx-gate $(OUT)/repro/b/tdx-gate
	sha256sum $(OUT)/repro/a/tdx-gate $(OUT)/repro/b/tdx-gate
	@echo "reproducible: A = B"

# The same twice in clean containers of the pinned image (by digest).
repro-docker:
	rm -rf $(OUT)/repro-docker && mkdir -p $(OUT)/repro-docker/a $(OUT)/repro-docker/b
	for x in a b; do docker run --rm --network=none -v $(CURDIR):/src:ro -v $(abspath $(OUT))/repro-docker/$$x:/out \
	  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=vendor -e CGO_ENABLED=0 -e GOCACHE=/tmp/cache -w /src $(GO_IMAGE) \
	  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/tdx-gate ./cmd/tdx-gate || exit 1; done
	cmp $(OUT)/repro-docker/a/tdx-gate $(OUT)/repro-docker/b/tdx-gate
	sha256sum $(OUT)/repro-docker/a/tdx-gate $(OUT)/repro-docker/b/tdx-gate

# Every mutant of mutants/mutants.json must be killed (one per check).
mutants:
	$(PYTHON) mutants/run.py --python $(PYTHON) --out $(OUT)/mutants.json

clean:
	rm -rf $(OUT)
