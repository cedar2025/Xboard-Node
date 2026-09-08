package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cedar2025/xboard-node/internal/config"
)

func writePair(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// generatePairWithValidity mints a self-signed pair for names with the given
// lifetime so expiry handling can be tested without waiting.
func generatePairWithValidity(t *testing.T, names []string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestSelfSignedPrepareGeneratesPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(config.CertConfig{CertDir: dir})
	cfg := config.CertConfig{CertMode: "self", CertDir: dir}

	first, err := m.Prepare(context.Background(), cfg, Identity{Names: []string{"a.example.test", "203.0.113.5"}})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !first.Generated() || !first.TLSCert().HasCert() {
		t.Fatalf("expected generated material, got %+v", first)
	}
	if m.HasCert() {
		t.Fatal("Prepare must not activate material")
	}

	keyInfo, err := os.Stat(filepath.Join(dir, "self-signed", "key.pem"))
	if err != nil {
		t.Fatalf("key not persisted: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key perm = %o", keyInfo.Mode().Perm())
	}
	dirInfo, _ := os.Stat(filepath.Join(dir, "self-signed"))
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm = %o", dirInfo.Mode().Perm())
	}

	block, _ := pem.Decode(first.TLSCert().CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "a.example.test" || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "203.0.113.5" {
		t.Fatalf("SANs dns=%v ip=%v", leaf.DNSNames, leaf.IPAddresses)
	}

	second, err := m.Prepare(context.Background(), cfg, Identity{Names: []string{"a.example.test", "203.0.113.5"}})
	if err != nil {
		t.Fatalf("prepare again: %v", err)
	}
	if second.Generated() || string(second.TLSCert().CertPEM) != string(first.TLSCert().CertPEM) {
		t.Fatal("unchanged identity must reuse the persisted pair")
	}

	// A subset of the names is still covered.
	third, err := m.Prepare(context.Background(), cfg, Identity{Names: []string{"a.example.test"}})
	if err != nil || third.Generated() {
		t.Fatalf("subset must reuse: gen=%v err=%v", third.Generated(), err)
	}

	// A name outside the SANs regenerates.
	fourth, err := m.Prepare(context.Background(), cfg, Identity{Names: []string{"b.example.test"}})
	if err != nil || !fourth.Generated() {
		t.Fatalf("new name must regenerate: gen=%v err=%v", fourth.Generated(), err)
	}
}

func TestSelfSignedExplicitDomainComesFirst(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(config.CertConfig{CertDir: dir})
	p, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "self", CertDir: dir, Domain: "Explicit.Example.Test"}, Identity{Names: []string{"sni.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(p.TLSCert().CertPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if leaf.Subject.CommonName != "explicit.example.test" || len(leaf.DNSNames) != 2 || leaf.DNSNames[1] != "sni.example.test" {
		t.Fatalf("CN=%s SANs=%v", leaf.Subject.CommonName, leaf.DNSNames)
	}
}

func TestSelfSignedExpiringMaterialIsRegenerated(t *testing.T) {
	dir := t.TempDir()
	selfDir := filepath.Join(dir, "self-signed")
	certPEM, keyPEM := generatePairWithValidity(t, []string{"a.example.test"}, time.Now().Add(24*time.Hour))
	writePair(t, selfDir, certPEM, keyPEM)

	m := NewManager(config.CertConfig{CertDir: dir})
	p, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "self", CertDir: dir}, Identity{Names: []string{"a.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Generated() || string(p.TLSCert().CertPEM) == string(certPEM) {
		t.Fatal("material expiring within the renewal window must be regenerated")
	}

	expired, expiredKey := generatePairWithValidity(t, []string{"a.example.test"}, time.Now().Add(-time.Hour))
	writePair(t, selfDir, expired, expiredKey)
	p, err = m.Prepare(context.Background(), config.CertConfig{CertMode: "self", CertDir: dir}, Identity{Names: []string{"a.example.test"}})
	if err != nil || !p.Generated() {
		t.Fatalf("expired material must be regenerated: gen=%v err=%v", p.Generated(), err)
	}
}

func TestSelfSignedCorruptMaterialIsRegenerated(t *testing.T) {
	dir := t.TempDir()
	writePair(t, filepath.Join(dir, "self-signed"), []byte("garbage"), []byte("garbage"))
	m := NewManager(config.CertConfig{CertDir: dir})
	p, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "self", CertDir: dir}, Identity{Names: []string{"a.example.test"}})
	if err != nil || !p.Generated() {
		t.Fatalf("corrupt material must be regenerated: gen=%v err=%v", p.Generated(), err)
	}
}

func TestSelfSignedLegacyLocationIsMigrated(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generatePairWithValidity(t, []string{"legacy.example.test"}, time.Now().Add(365*24*time.Hour))
	writePair(t, dir, certPEM, keyPEM) // older versions persisted explicit self material here

	m := NewManager(config.CertConfig{CertDir: dir})
	p, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "self", CertDir: dir}, Identity{Names: []string{"legacy.example.test"}})
	if err != nil || p.Generated() || string(p.TLSCert().CertPEM) != string(certPEM) {
		t.Fatalf("legacy material must be reused: gen=%v err=%v", p.Generated(), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "self-signed", "cert.pem")); err != nil {
		t.Fatalf("legacy material must be migrated: %v", err)
	}
}

func TestSelfSignedMaterialNeverLeaksIntoContentFallback(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(config.CertConfig{CertDir: dir})
	if _, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "self", CertDir: dir}, Identity{Names: []string{"a.example.test"}}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "content", CertDir: dir}, Identity{})
	if err == nil || !strings.Contains(err.Error(), "requires both cert_content and key_content") {
		t.Fatalf("content mode must not pick up self-signed material, got %v", err)
	}
}

func TestPrepareFailureLeavesActiveMaterialUntouched(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generatePairWithValidity(t, []string{"explicit.example.test"}, time.Now().Add(365*24*time.Hour))
	m := NewManager(config.CertConfig{CertDir: dir})
	active, err := m.Prepare(context.Background(), config.CertConfig{CertMode: "content", CertDir: dir, CertContent: string(certPEM), KeyContent: string(keyPEM)}, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	m.Commit(active)
	if !m.HasCert() || string(m.TLSCert().CertPEM) != string(certPEM) {
		t.Fatal("commit did not activate the explicit material")
	}

	_, err = m.Prepare(context.Background(), config.CertConfig{CertMode: "file", CertDir: dir, CertFile: filepath.Join(dir, "missing.pem"), KeyFile: filepath.Join(dir, "missing.key")}, Identity{})
	if err == nil {
		t.Fatal("expected error")
	}
	if string(m.TLSCert().CertPEM) != string(certPEM) || m.Config().CertMode != "content" {
		t.Fatal("a failed preparation must not disturb the active certificate")
	}

	_, err = m.Prepare(context.Background(), config.CertConfig{CertMode: "bogus", CertDir: dir}, Identity{})
	if err == nil || !strings.Contains(err.Error(), "unknown cert_mode") {
		t.Fatalf("unknown mode must error, got %v", err)
	}
	if string(m.TLSCert().CertPEM) != string(certPEM) {
		t.Fatal("unknown mode must not touch the active certificate")
	}
}

func TestReconfigureReportsMaterialChange(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(config.CertConfig{CertDir: dir})
	changed, err := m.Reconfigure(context.Background(), config.CertConfig{CertMode: "self", Domain: "a.example.test"})
	if err != nil || !changed || !m.HasCert() {
		t.Fatalf("changed=%v err=%v has=%v", changed, err, m.HasCert())
	}
	changed, err = m.Reconfigure(context.Background(), config.CertConfig{CertMode: "self", Domain: "a.example.test"})
	if err != nil || changed {
		t.Fatalf("same config must not report a change: changed=%v err=%v", changed, err)
	}
	changed, err = m.Reconfigure(context.Background(), config.CertConfig{CertMode: "none"})
	if err != nil || !changed || m.HasCert() {
		t.Fatalf("switching to none: changed=%v err=%v has=%v", changed, err, m.HasCert())
	}
}

func TestResolveModeAndIsExplicit(t *testing.T) {
	if ResolveMode(config.CertConfig{}) != "none" || IsExplicit(config.CertConfig{}) {
		t.Fatal("zero config must be implicit none")
	}
	if ResolveMode(config.CertConfig{AutoTLS: true}) != "http" || !IsExplicit(config.CertConfig{AutoTLS: true}) {
		t.Fatal("auto_tls must resolve to http")
	}
	if ResolveMode(config.CertConfig{CertMode: "None"}) != "none" || !IsExplicit(config.CertConfig{CertMode: "None"}) {
		t.Fatal("explicit none is explicit")
	}
	if ResolveMode(config.CertConfig{CertFile: "a", KeyFile: "b"}) != "file" {
		t.Fatal("file pair must resolve to file")
	}
	if ResolveMode(config.CertConfig{CertContent: "a", KeyContent: "b"}) != "content" {
		t.Fatal("content pair must resolve to content")
	}
}
