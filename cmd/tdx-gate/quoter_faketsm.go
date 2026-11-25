//go:build faketsm

package main

import (
	"errors"

	"github.com/chutesai/chutes-tdx-gate/internal/fakequote"
	"github.com/chutesai/chutes-tdx-gate/pkg/attest"
	"github.com/chutesai/chutes-tdx-gate/pkg/gate"
)

// A TEST BUILD (go build -tags faketsm, the cross-tests only): /attest answers unsigned synthetic
// quotes, and the binary serves only with --test-identity. `make build` never sets the tag.
const buildNote = ", TEST BUILD (faketsm): unsigned synthetic quotes, --test-identity only"

const faketsmBuild = true

func quoter(*gate.Config) attest.Quoter { return &fakequote.Quoter{} }

func testBuildGuard(testIdentity bool) error {
	if !testIdentity {
		return errors.New("this faketsm test build serves only with --test-identity")
	}
	return nil
}
