package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/cedar2025/xboard-node/internal/cert/dnsproviders"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/nlog"
)

// Manager handles TLS certificate lifecycle.
//
// Supported modes (CertConfig.CertMode):
//   - "http"    — ACME HTTP-01 challenge via certmagic (needs port 80).
//   - "dns"     — ACME DNS-01 challenge via certmagic + libdns provider.
//   - "self"    — Self-signed certificate generated in memory.
//   - "file"    — User-provided certificate and key file paths (CertFile/KeyFile).
//   - "content" — Certificate and key PEM content pushed from the panel.
//   - "none"    — No TLS. The node will handle plain connections.
//
// All modes normalise to in-memory PEM. Kernels never see file paths —
// they always receive PEM bytes via TLSCert().
//
// Priority Logic (when CertMode is empty):
//
//	1. "http" (if auto_tls is true)
//	2. "content" (if both CertContent and KeyContent are provided)
//	3. "file" (if both CertFile and KeyFile paths are provided)
//	4. "none" (default)
type Manager struct {
	cfg config.CertConfig

	// Cert material stored atomically so the ACME renewal goroutine can
	// swap it without racing with TLSCert() readers.
	mat atomic.Pointer[certMaterial]

	magic       *certmagic.Config
	renewed     atomic.Bool
	acmeStarted bool
}

// certMaterial is an immutable snapshot of PEM-encoded cert + key.
type certMaterial struct {
	certPEM []byte
	keyPEM  []byte
}

// NewManager creates a certificate manager.
func NewManager(cfg config.CertConfig) *Manager {
	return &Manager{cfg: cfg}
}

// storePEM atomically swaps the in-memory cert material and persists to disk
// so that restarts can reload without re-generating or re-requesting.
func (m *Manager) storePEM(cert, key []byte) {
	m.mat.Store(&certMaterial{certPEM: cert, keyPEM: key})
	m.persistPEM(cert, key)
}

// persistPEM writes cert/key to cert_dir for restart recovery.
// Errors are logged but not returned — persistence is best-effort.
func (m *Manager) persistPEM(cert, key []byte) {
	dir := m.cfg.CertDir
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		nlog.Core().Warn("cert: failed to create cert_dir", "dir", dir, "error", err)
		return
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := atomicWriteFile(certPath, cert, 0o644); err != nil {
		nlog.Core().Warn("cert: failed to persist cert", "path", certPath, "error", err)
	}
	if err := atomicWriteFile(keyPath, key, 0o600); err != nil {
		nlog.Core().Warn("cert: failed to persist key", "path", keyPath, "error", err)
	}
}

// atomicWriteFile writes data to a temp file and renames, preventing partial reads.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadPersistedPEM loads previously persisted cert material from cert_dir.
// Returns true if valid material was loaded.
func (m *Manager) loadPersistedPEM() bool {
	dir := m.cfg.CertDir
	if dir == "" {
		return false
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return false
	}
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		nlog.Core().Warn("cert: persisted cert invalid, will regenerate", "error", err)
		return false
	}
	// Store in memory only (don't re-persist what we just read).
	m.mat.Store(&certMaterial{certPEM: certPEM, keyPEM: keyPEM})
	nlog.Core().Info("cert: loaded persisted certificate from disk", "dir", dir)
	return true
}

// Reconfigure applies a new cert configuration at runtime (e.g. from panel push).
// For ACME modes that are already running this is a no-op — a process restart
// is required to change ACME settings.
// Returns true when the PEM material changed (caller should restart kernel).
func (m *Manager) Reconfigure(ctx context.Context, newCfg config.CertConfig) (bool, error) {
	if newCfg.CertDir == "" {
		newCfg.CertDir = m.cfg.CertDir
	}

	oldTLS := m.TLSCert()
	m.cfg = newCfg

	if err := m.Start(ctx); err != nil {
		return false, fmt.Errorf("cert reconfigure: %w", err)
	}

	newTLS := m.TLSCert()
	return !pemEqual(oldTLS, newTLS), nil
}

// resolveMode returns the effective cert mode, handling backward compat for auto_tls.
func (m *Manager) resolveMode() string {
	mode := strings.ToLower(strings.TrimSpace(m.cfg.CertMode))
	if mode != "" {
		return mode
	}
	// Backward compat: auto_tls: true → "http"
	if m.cfg.AutoTLS {
		return "http"
	}
	// Inline PEM content provided → "content"
	if m.cfg.CertContent != "" && m.cfg.KeyContent != "" {
		return "content"
	}
	// If cert/key file paths are provided → "file"
	if m.cfg.CertFile != "" && m.cfg.KeyFile != "" {
		return "file"
	}
	return "none"
}

func (m *Manager) HasCert() bool {
	mat := m.mat.Load()
	return mat != nil && len(mat.certPEM) > 0 && len(mat.keyPEM) > 0
}
func (m *Manager) CertRenewed() bool { return m.renewed.Swap(false) }

// TLSCert returns the current PEM material as a kernel.TLSCert.
func (m *Manager) TLSCert() kernel.TLSCert {
	mat := m.mat.Load()
	if mat == nil {
		return kernel.TLSCert{}
	}
	return kernel.TLSCert{CertPEM: mat.certPEM, KeyPEM: mat.keyPEM}
}

// pemEqual reports whether two TLSCert values carry identical PEM content.
func pemEqual(a, b kernel.TLSCert) bool {
	return string(a.CertPEM) == string(b.CertPEM) && string(a.KeyPEM) == string(b.KeyPEM)
}

// Start initializes the cert manager based on the resolved mode.
func (m *Manager) Start(ctx context.Context) error {
	mode := m.resolveMode()

	switch mode {
	case "none", "":
		return nil
	case "file":
		return m.startFile()
	case "self":
		return m.startSelfSigned()
	case "content":
		return m.startContent()
	case "http":
		return m.startACME(ctx, nil)
	case "dns":
		solver, err := m.buildDNSSolver()
		if err != nil {
			return fmt.Errorf("build dns solver: %w", err)
		}
		return m.startACME(ctx, solver)
	default:
		return fmt.Errorf("unknown cert_mode: %q (supported: http, dns, self, file, content, none)", mode)
	}
}

// Stop is a no-op: certmagic's background goroutine is cancelled via the
// context passed to ManageAsync.
func (m *Manager) Stop() {}

// ─── Mode: file ────────────────────────────────────────────────────────────

func (m *Manager) startFile() error {
	certPEM, err := os.ReadFile(m.cfg.CertFile)
	if err != nil {
		return fmt.Errorf("cert file: %w", err)
	}
	keyPEM, err := os.ReadFile(m.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("invalid certificate pair: %w", err)
	}
	m.storePEM(certPEM, keyPEM)
	nlog.Core().Debug("TLS certificate loaded from files", "cert", m.cfg.CertFile, "key", m.cfg.KeyFile)
	return nil
}

// ─── Mode: self ────────────────────────────────────────────────────────────

func (m *Manager) startSelfSigned() error {
	// Reuse persisted self-signed cert if available and valid.
	if m.loadPersistedPEM() {
		return nil
	}

	domain := m.cfg.Domain
	if domain == "" {
		domain = "localhost"
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Add SANs
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	m.storePEM(certPEM, keyPEM)
	nlog.Core().Info("self-signed certificate generated (in-memory)", "domain", domain, "valid_years", 10)
	return nil
}

// ─── Mode: content ────────────────────────────────────────────────────────

// startContent stores panel-supplied PEM strings in memory for inline use.
func (m *Manager) startContent() error {
	if m.cfg.CertContent == "" || m.cfg.KeyContent == "" {
		// No fresh content from panel — try previously persisted material.
		if m.loadPersistedPEM() {
			return nil
		}
		return fmt.Errorf("cert_mode 'content' requires both cert_content and key_content")
	}
	certPEM := []byte(m.cfg.CertContent)
	keyPEM := []byte(m.cfg.KeyContent)
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("invalid certificate content: %w", err)
	}
	m.storePEM(certPEM, keyPEM)
	nlog.Core().Info("TLS certificate loaded from panel content (in-memory)")
	return nil
}

// ─── Mode: http / dns (ACME) ──────────────────────────────────────────────

func (m *Manager) startACME(ctx context.Context, dnsSolver *certmagic.DNS01Solver) error {
	// Guard: certmagic's background goroutines must only be started once.
	// A process restart is required to change ACME settings at runtime.
	if m.acmeStarted {
		nlog.Core().Info("cert: ACME already active, skipping re-init (restart to change ACME settings)")
		return nil
	}

	if m.cfg.Domain == "" {
		return fmt.Errorf("cert.domain is required for ACME modes (http/dns)")
	}

	if err := os.MkdirAll(m.cfg.CertDir, 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	storage := &certmagic.FileStorage{Path: m.cfg.CertDir}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(_ certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	magic = certmagic.New(cache, certmagic.Config{
		Storage: storage,
		OnEvent: func(evtCtx context.Context, event string, data map[string]any) error {
			if event == "cert_obtained" {
				m.loadCertFromStorage(evtCtx, storage, data)
			}
			return nil
		},
	})

	issuer := certmagic.ACMEIssuer{
		CA:    certmagic.LetsEncryptProductionCA,
		Email: m.cfg.Email,
	}

	if dnsSolver != nil {
		// DNS-01 mode: no HTTP port needed, supports wildcards.
		issuer.DNS01Solver = dnsSolver
		issuer.DisableHTTPChallenge = true
		issuer.DisableTLSALPNChallenge = true
	} else {
		// HTTP-01 mode.
		httpPort := m.cfg.HTTPPort
		if httpPort == 0 {
			httpPort = 80
		}
		issuer.AltHTTPPort = httpPort
		issuer.DisableTLSALPNChallenge = true
	}

	magic.Issuers = []certmagic.Issuer{
		certmagic.NewACMEIssuer(magic, issuer),
	}
	m.magic = magic

	if err := magic.ObtainCertSync(ctx, m.cfg.Domain); err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	// The cert_obtained event callback should have loaded PEM. Verify.
	if !m.HasCert() {
		return fmt.Errorf("ACME obtained certificate but PEM was not loaded; check storage")
	}

	if err := magic.ManageAsync(ctx, []string{m.cfg.Domain}); err != nil {
		return fmt.Errorf("start cert manager: %w", err)
	}

	m.acmeStarted = true
	return nil
}

func validateKeyPair(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return err
	}
	return nil
}

// ─── DNS Provider Factory ──────────────────────────────────────────────────

// buildDNSSolver builds a certmagic DNS01Solver from the configured provider.
func (m *Manager) buildDNSSolver() (*certmagic.DNS01Solver, error) {
	provider, err := m.newDNSProvider()
	if err != nil {
		return nil, err
	}
	return &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: provider}}, nil
}

func (m *Manager) newDNSProvider() (certmagic.DNSProvider, error) {
	name := strings.TrimSpace(m.cfg.DNSProvider)
	if name == "" {
		return nil, fmt.Errorf("dns_provider is required for cert_mode=dns")
	}
	env := m.cfg.DNSEnv
	if env == nil {
		env = map[string]string{}
	}
	p, ok := dnsproviders.Get(name)
	if !ok {
		return nil, fmt.Errorf("unsupported dns_provider: %q (supported: %s)",
			name, strings.Join(dnsproviders.CanonicalNames(), ", "))
	}
	return p.Build(env)
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// loadCertFromStorage reads ACME cert/key from certmagic's storage into memory.
func (m *Manager) loadCertFromStorage(ctx context.Context, storage certmagic.Storage, data map[string]any) {
	certKey, _ := data["certificate_path"].(string)
	keyKey, _ := data["private_key_path"].(string)
	if certKey == "" || keyKey == "" {
		nlog.Core().Warn("cert_obtained event missing storage paths", "data", data)
		return
	}

	certPEM, err := storage.Load(ctx, certKey)
	if err != nil {
		nlog.Core().Error("failed to load cert from ACME storage", "error", err)
		return
	}
	keyPEM, err := storage.Load(ctx, keyKey)
	if err != nil {
		nlog.Core().Error("failed to load key from ACME storage", "error", err)
		return
	}

	m.storePEM(certPEM, keyPEM)

	renewal, _ := data["renewal"].(bool)
	nlog.Core().Info("TLS certificate loaded from ACME storage", "domain", m.cfg.Domain, "renewal", renewal)
	if renewal {
		m.renewed.Store(true)
	}
}
