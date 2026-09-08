package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/model"
)

// The certificate policy matrix: who decides (panel / local / default) and
// what the decision is for every TLS requirement.
func TestResolveCertPlanMatrix(t *testing.T) {
	local := config.CertConfig{CertDir: "/tmp/certs", HTTPPort: 80}
	localSelf := config.CertConfig{CertDir: "/tmp/certs", CertMode: "self", Domain: "local.example.test"}
	localFile := config.CertConfig{CertDir: "/tmp/certs", CertFile: "/etc/c.pem", KeyFile: "/etc/k.pem"}
	localAutoTLS := config.CertConfig{CertDir: "/tmp/certs", AutoTLS: true, Domain: "acme.example.test"}

	hy := func(cc *config.CertConfig) *model.NodeSpec {
		return &model.NodeSpec{Protocol: "hysteria", Version: 2, ServerPort: 443, ServerName: "hy.example.test", CertConfig: cc}
	}
	vmess := func(tls int, cc *config.CertConfig) *model.NodeSpec {
		return &model.NodeSpec{Protocol: "vmess", ServerPort: 443, TLS: tls, Network: "ws", CertConfig: cc}
	}

	cases := []struct {
		name        string
		spec        *model.NodeSpec
		requirement model.TLSRequirement
		local       config.CertConfig
		managed     bool
		wantSource  certSource
		wantMode    string
		wantPrepare bool
		wantErr     string
	}{
		// Default policy.
		{"managed hysteria, nothing configured → auto self", hy(nil), model.TLSRequired, local, true, certSourceAuto, "self", true, ""},
		{"standalone hysteria, nothing configured → explicit error", hy(nil), model.TLSRequired, local, false, certSourceNone, "", false, "requires a TLS certificate"},
		{"managed vmess tls=1, nothing configured → auto self", vmess(1, nil), model.TLSRequested, local, true, certSourceAuto, "self", true, ""},
		{"vmess tls=0 ignores certs", vmess(0, &config.CertConfig{CertMode: "self"}), model.TLSOff, local, true, certSourceNone, "none", false, ""},
		{"shadowsocks never prepares", &model.NodeSpec{Protocol: "shadowsocks", CertConfig: &config.CertConfig{CertMode: "http", Domain: "x"}}, model.TLSNotUsed, localAutoTLS, true, certSourceNone, "none", false, ""},

		// Panel explicit configuration wins over local.
		{"panel self over local file", hy(&config.CertConfig{CertMode: "self"}), model.TLSRequired, localFile, true, certSourcePanel, "self", true, ""},
		{"panel file", hy(&config.CertConfig{CertMode: "file", CertFile: "/a", KeyFile: "/b"}), model.TLSRequired, local, true, certSourcePanel, "file", true, ""},
		{"panel content", hy(&config.CertConfig{CertMode: "content", CertContent: "c", KeyContent: "k"}), model.TLSRequired, local, true, certSourcePanel, "content", true, ""},
		{"panel http", hy(&config.CertConfig{CertMode: "http", Domain: "d.example.test"}), model.TLSRequired, local, true, certSourcePanel, "http", true, ""},
		{"panel http without domain", hy(&config.CertConfig{CertMode: "http"}), model.TLSRequired, local, true, "", "", false, "requires cert_config.domain"},
		{"panel dns", hy(&config.CertConfig{CertMode: "dns", Domain: "d.example.test", DNSProvider: "cloudflare"}), model.TLSRequired, local, true, certSourcePanel, "dns", true, ""},
		{"panel dns unknown provider", hy(&config.CertConfig{CertMode: "dns", Domain: "d", DNSProvider: "3123123"}), model.TLSRequired, local, true, "", "", false, `unsupported cert_config.dns_provider "3123123"`},
		{"panel dns missing provider", hy(&config.CertConfig{CertMode: "dns", Domain: "d"}), model.TLSRequired, local, true, "", "", false, "requires cert_config.dns_provider"},
		{"panel unknown mode is an error, not self", hy(&config.CertConfig{CertMode: "magic"}), model.TLSRequired, local, true, "", "", false, "unknown cert_mode"},
		{"panel explicit none conflicts with required TLS", hy(&config.CertConfig{CertMode: "none"}), model.TLSRequired, local, true, "", "", false, "cert_mode none"},
		{"panel explicit none conflicts with requested TLS", vmess(1, &config.CertConfig{CertMode: "none"}), model.TLSRequested, localSelf, true, "", "", false, "cert_mode none"},
		{"panel implicit content", hy(&config.CertConfig{CertContent: "c", KeyContent: "k"}), model.TLSRequired, local, true, certSourcePanel, "content", true, ""},
		{"panel empty cert_config counts as none", hy(&config.CertConfig{}), model.TLSRequired, localSelf, true, "", "", false, "cert_mode none"},

		// Deprecated panel fields.
		{"panel auto_tls means ACME http, never self", &model.NodeSpec{Protocol: "hysteria", Version: 2, AutoTLS: true, Domain: "acme.example.test"}, model.TLSRequired, local, true, certSourcePanel, "http", true, ""},

		// Local explicit configuration when the panel sends none.
		{"local self", hy(nil), model.TLSRequired, localSelf, true, certSourceLocal, "self", true, ""},
		{"local file", hy(nil), model.TLSRequired, localFile, true, certSourceLocal, "file", true, ""},
		{"local auto_tls", hy(nil), model.TLSRequired, localAutoTLS, true, certSourceLocal, "http", true, ""},
		{"local self for tls=1 vmess terminates TLS", vmess(1, nil), model.TLSRequested, localSelf, true, certSourceLocal, "self", true, ""},
		{"local explicit none for required TLS is a conflict", hy(nil), model.TLSRequired, config.CertConfig{CertMode: "none"}, true, "", "", false, "cert_mode none"},
		{"standalone local self", hy(nil), model.TLSRequired, localSelf, false, certSourceLocal, "self", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := resolveCertPlan(tc.spec, tc.requirement, tc.local, tc.managed)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if plan.Source != tc.wantSource || plan.Mode != tc.wantMode || plan.Prepare != tc.wantPrepare {
				t.Fatalf("plan = %+v, want source=%s mode=%s prepare=%v", plan, tc.wantSource, tc.wantMode, tc.wantPrepare)
			}
			if plan.Prepare && plan.Config.CertDir != tc.local.CertDir {
				t.Fatalf("cert dir must come from the local config, got %q", plan.Config.CertDir)
			}
		})
	}
}

func TestResolveCertPlanNeverInheritsRevokedRuntimeOverride(t *testing.T) {
	local := config.CertConfig{CertDir: "/tmp/certs"}
	withPanel := &model.NodeSpec{Protocol: "hysteria", Version: 2, CertConfig: &config.CertConfig{CertMode: "file", CertFile: "/a", KeyFile: "/b"}}
	first, err := resolveCertPlan(withPanel, model.TLSRequired, local, true)
	if err != nil || first.Source != certSourcePanel || first.Mode != "file" {
		t.Fatalf("first = %+v %v", first, err)
	}
	// The panel stops sending cert_config: the decision is recomputed from
	// the original local config, which has nothing, so the default applies.
	withoutPanel := &model.NodeSpec{Protocol: "hysteria", Version: 2}
	second, err := resolveCertPlan(withoutPanel, model.TLSRequired, local, true)
	if err != nil || second.Source != certSourceAuto || second.Mode != "self" {
		t.Fatalf("second = %+v %v", second, err)
	}
}

func TestIdentityNamesFollowTheServedName(t *testing.T) {
	spec := &model.NodeSpec{
		Protocol:    "hysteria",
		Host:        "203.0.113.10",
		ServerName:  "Edge.Example.Test:443",
		TLSSettings: map[string]any{"server_name": "sni.example.test"},
	}
	got := identityNames(spec)
	want := []string{"sni.example.test", "edge.example.test", "203.0.113.10"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", got, want)
	}
	if got := identityNames(&model.NodeSpec{Protocol: "hysteria"}); len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("fallback names = %v", got)
	}
	if got := identityNames(&model.NodeSpec{Protocol: "hysteria", Host: "[2001:db8::1]:443"}); got[0] != "2001:db8::1" {
		t.Fatalf("ipv6 host = %v", got)
	}
}

func TestPrepareTargetAutoSelfSignedIsPersistedReusedAndRotatedByName(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	spec := hysteria2Spec(54433)

	first, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if first.plan.Source != certSourceAuto || !first.tls.HasCert() || first.kernelType != model.KernelSingbox {
		t.Fatalf("prepared = %+v", first)
	}
	s.cert.Commit(first.cert)

	keyPath := filepath.Join(autoCertificateDir(s.cfg), "self-signed", "key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key not persisted: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key perm = %o, want 600", info.Mode().Perm())
	}
	leaf := parseLeaf(t, first.tls.CertPEM)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "hy.example.test" {
		t.Fatalf("SANs = %v", leaf.DNSNames)
	}

	// Same names: material is reused, so a restart never rotates the cert.
	second, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA})
	if err != nil {
		t.Fatalf("prepare again: %v", err)
	}
	if string(second.tls.CertPEM) != string(first.tls.CertPEM) {
		t.Fatal("unchanged identity must reuse the persisted certificate")
	}

	// A new served name regenerates.
	renamed := hysteria2Spec(54433)
	renamed.ServerName = "other.example.test"
	renamed.Host = "other.example.test"
	third, err := s.prepareTarget(context.Background(), renamed, []model.UserSpec{userA})
	if err != nil {
		t.Fatalf("prepare renamed: %v", err)
	}
	if string(third.tls.CertPEM) == string(first.tls.CertPEM) {
		t.Fatal("a changed identity must regenerate the certificate")
	}
	if leaf := parseLeaf(t, third.tls.CertPEM); len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "other.example.test" {
		t.Fatalf("SANs after rename = %v", leaf.DNSNames)
	}
}

func TestPrepareTargetExplicitCertErrorsAreNotDowngraded(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)

	spec := hysteria2Spec(54433)
	spec.CertConfig = &config.CertConfig{CertMode: "file", CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}
	if _, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA}); err == nil || !strings.Contains(err.Error(), "cert file") {
		t.Fatalf("missing explicit file must fail loudly, got %v", err)
	}
	if s.cert.HasCert() {
		t.Fatal("a failed explicit preparation must not leave material behind")
	}

	spec.CertConfig = &config.CertConfig{CertMode: "content", CertContent: "not pem", KeyContent: "not pem"}
	if _, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA}); err == nil || !strings.Contains(err.Error(), "invalid certificate content") {
		t.Fatalf("broken explicit content must fail loudly, got %v", err)
	}

	spec.CertConfig = &config.CertConfig{CertMode: "none"}
	if _, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA}); err == nil || !strings.Contains(err.Error(), "cert_mode none") {
		t.Fatalf("explicit none for hysteria must be a clear conflict, got %v", err)
	}
}

func TestPrepareTargetKernelRejectionDiscardsPreparedMaterial(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	tk.singbox.validateErr = errString("unknown inbound type: hysteria2 (built without with_quic)")

	_, err := s.prepareTarget(context.Background(), hysteria2Spec(54433), []model.UserSpec{userA})
	if err == nil || !strings.Contains(err.Error(), "kernel singbox rejected") {
		t.Fatalf("err = %v", err)
	}
	if s.cert.HasCert() {
		t.Fatal("material of a rejected target must not become active")
	}
}

func TestPrepareTargetDoesNotMutateTheDesiredSnapshot(t *testing.T) {
	tk := newTestKernels()
	s := newTestService(t, tk)
	spec := &model.NodeSpec{Protocol: "trojan", ServerPort: 443, ServerName: "t.example.test"}
	before := computeConfigHash(spec)
	if _, err := s.prepareTarget(context.Background(), spec, []model.UserSpec{userA}); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if computeConfigHash(spec) != before || spec.TLS != 0 {
		t.Fatal("prepare must work on a copy of the desired snapshot")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return leaf
}

func TestAutomaticCertificatesAreIsolatedInSharedDirectories(t *testing.T) {
	for _, differentPanel := range []bool{false, true} {
		name := "different nodes"
		if differentPanel {
			name = "different panels"
		}
		t.Run(name, func(t *testing.T) {
			first := newTestService(t, newTestKernels())
			second := newTestService(t, newTestKernels())
			second.cfg.Cert.CertDir = first.cfg.Cert.CertDir
			if differentPanel {
				second.cfg.Panel.URL = "https://another-panel.test"
			} else {
				second.cfg.Panel.NodeID++
			}
			a := hysteria2Spec(12345)
			a.Host = "first-node.test"
			b := hysteria2Spec(12346)
			b.Host = "second-node.test"
			one, err := first.prepareTarget(context.Background(), a, []model.UserSpec{userA})
			if err != nil {
				t.Fatal(err)
			}
			defer first.cert.Discard(one.cert)
			two, err := second.prepareTarget(context.Background(), b, []model.UserSpec{userA})
			if err != nil {
				t.Fatal(err)
			}
			defer second.cert.Discard(two.cert)
			if one.plan.Config.CertDir == two.plan.Config.CertDir {
				t.Fatal("automatic certificates share a cache namespace")
			}
			again, err := first.prepareTarget(context.Background(), a, []model.UserSpec{userA})
			if err != nil {
				t.Fatal(err)
			}
			defer first.cert.Discard(again.cert)
			if again.cert.Generated() || string(again.tls.CertPEM) != string(one.tls.CertPEM) {
				t.Fatal("another node overwrote the first node's cached certificate")
			}
		})
	}
}
