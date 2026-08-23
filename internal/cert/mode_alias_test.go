package cert

import (
	"context"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
)

// Regression test for cedar2025/Xboard-Node#1012 (reported on Xboard):
// the admin panel sends cert_mode "self-signed" for the self-signed
// option; the node must accept it as an alias of "self" instead of
// failing with 'unknown cert_mode'.
func TestResolveMode_SelfSignedAlias(t *testing.T) {
	m := &Manager{cfg: config.CertConfig{CertMode: "self-signed"}}
	if got := m.resolveMode(); got != "self" {
		t.Errorf("resolveMode(self-signed) = %q, want %q", got, "self")
	}

	got := resolveModeFor(config.CertConfig{CertMode: "Self-Signed"})
	if got != "self" {
		t.Errorf("resolveModeFor(Self-Signed) = %q, want %q", got, "self")
	}

	// Alias must also start successfully like "self".
	m2 := &Manager{cfg: config.CertConfig{CertMode: "self-signed"}}
	if err := m2.Start(context.Background()); err != nil {
		t.Errorf("Start with self-signed should work as self: %v", err)
	}
}
