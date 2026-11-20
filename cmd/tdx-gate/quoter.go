//go:build !faketsm

package main

import (
	"github.com/chutesai/chutes-tdx-gate/pkg/attest"
	"github.com/chutesai/chutes-tdx-gate/pkg/gate"
)

const buildNote = ""

const faketsmBuild = false

// quoter is configfs-tsm in the configured report directory.
func quoter(cfg *gate.Config) attest.Quoter { return &attest.ConfigfsTsm{Dir: cfg.TsmReportDir} }

func testBuildGuard(bool) error { return nil }
