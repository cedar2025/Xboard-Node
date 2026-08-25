package config

import (
	"strings"
	"testing"
)

// Regression for cedar2025/Xboard-Node#69: machine mode derives a per-node
// config per bound node. ACME state (certmagic storage) must be shared at
// the machine level so same-domain nodes issue once, while per-node PEM
// persistence stays isolated.
func TestExpandMachineNode_SharedACMEStorage(t *testing.T) {
	base := &Config{Machine: &MachineConfig{MachineID: 1, Token: "t"}}
	base.Kernel.ConfigDir = t.TempDir()
	base.Cert.CertDir = "" // force default derivation

	a := base.ExpandMachineNode(1, "hysteria")
	b := base.ExpandMachineNode(2, "trojan")

	if a.Cert.CertDir == b.Cert.CertDir {
		t.Errorf("per-node CertDir must stay isolated, both = %q", a.Cert.CertDir)
	}
	if !strings.Contains(a.Cert.CertDir, "node-1") || !strings.Contains(b.Cert.CertDir, "node-2") {
		t.Errorf("per-node CertDir not node-scoped: %q / %q", a.Cert.CertDir, b.Cert.CertDir)
	}

	if a.Cert.ACMEStorageDir == "" || b.Cert.ACMEStorageDir == "" {
		t.Fatalf("ACMEStorageDir must be derived, got %q / %q", a.Cert.ACMEStorageDir, b.Cert.ACMEStorageDir)
	}
	if a.Cert.ACMEStorageDir != b.Cert.ACMEStorageDir {
		t.Errorf("ACME storage must be machine-shared for same-domain dedup: %q != %q",
			a.Cert.ACMEStorageDir, b.Cert.ACMEStorageDir)
	}
	if strings.Contains(a.Cert.ACMEStorageDir, "node-1") {
		t.Errorf("ACME storage must not be node-scoped: %q", a.Cert.ACMEStorageDir)
	}
}

func TestExpandMachineNode_ExplicitACMEStoragePreserved(t *testing.T) {
	base := &Config{Machine: &MachineConfig{MachineID: 1, Token: "t"}}
	base.Kernel.ConfigDir = t.TempDir()
	base.Cert.ACMEStorageDir = "/custom/acme"

	a := base.ExpandMachineNode(7, "vless")
	if a.Cert.ACMEStorageDir != "/custom/acme" {
		t.Errorf("explicit ACMEStorageDir must survive expansion, got %q", a.Cert.ACMEStorageDir)
	}
}
