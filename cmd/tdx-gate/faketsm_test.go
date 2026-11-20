//go:build faketsm

package main

import "testing"

// The faketsm test build serves only with --test-identity.
func TestFaketsmGuard(t *testing.T) {
	if testBuildGuard(false) == nil {
		t.Fatal("a faketsm build would serve without --test-identity")
	}
	if testBuildGuard(true) != nil {
		t.Fatal("the guard refuses --test-identity")
	}
}
