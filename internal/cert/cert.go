package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
//   - "self"    — Self-signed certificate, generated once and reused from disk.
//   - "file"    — User-provided certificate and key file paths (CertFile/KeyFile).
//   - "content" — Certificate and key PEM content pushed from the panel.
//   - "none"    — No TLS. The node will handle plain connections.
//
// All modes normalise to in-memory PEM. Kernels never see file paths —
// they always receive PEM bytes via TLSCert().
//
// Priority Logic (when CertMode is empty):
//
//  1. "http" (if auto_tls is true)
//  2. "content" (if both CertContent and KeyContent are provided)
//  3. "file" (if both CertFile and KeyFile paths are provided)
//  4. "none" (default)
//
// The manager separates preparing material for a target (Prepare) from
// putting it into use (Commit). Preparing never touches the material that is
// currently in use, so a failed ACME order or a broken file path leaves a
// running node on its existing certificate.
type Manager struct {
	mu  sync.Mutex
	cfg config.CertConfig

	// Atomic so the ACME renewal goroutine can swap without racing readers.
	mat atomic.Pointer[certMaterial]

	renewed atomic.Bool
	acme    *acmeInstance
}

// certMaterial is an immutable snapshot of PEM-encoded cert + key.
type certMaterial struct {
	certPEM []byte
	keyPEM  []byte
}

// acmeInstance is one running certmagic configuration.
type acmeInstance struct {
	magic       *certmagic.Config
	storage     certmagic.Storage
	issuerKey   string
	domain      string
	fingerprint string
	cancel      context.CancelFunc
}

// Identity is the set of names a self-signed certificate must cover. It is
// derived from the target node (SNI, host, explicit domain) so the material
// matches what the kernel actually serves.
type Identity struct {
	Names []string
}

// Prepared is certificate material resolved for a target but not yet in use.
type Prepared struct {
	cfg  config.CertConfig
	mode string
	mat  *certMaterial
	// acme is a freshly created ACME instance owned by this Prepared until it
	// is committed or discarded. reuseACME marks material taken from the
	// instance the manager is already running.
	acme      *acmeInstance
	reuseACME bool
	// generated reports that self-signed material was (re)generated.
	generated bool
}

// Mode returns the resolved certificate mode of the prepared material.
func (p *Prepared) Mode() string { return p.mode }

// Generated reports whether self-signed material was newly generated rather
// than reused from disk.
func (p *Prepared) Generated() bool { return p.generated }

// TLSCert returns the prepared PEM material as a kernel.TLSCert.
func (p *Prepared) TLSCert() kernel.TLSCert {
	if p == nil || p.mat == nil {
		return kernel.TLSCert{}
	}
	return kernel.TLSCert{CertPEM: p.mat.certPEM, KeyPEM: p.mat.keyPEM}
}

// selfSignedRenewBefore is how long before expiry self-signed material is
// regenerated instead of reused.
const selfSignedRenewBefore = 30 * 24 * time.Hour

// selfSignedValidity is the lifetime of generated self-signed material.
const selfSignedValidity = 10 * 365 * 24 * time.Hour

// NewManager creates a certificate manager.
func NewManager(cfg config.CertConfig) *Manager {
	return &Manager{cfg: cfg}
}

// Config returns the configuration currently in use.
func (m *Manager) Config() config.CertConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// storePEM atomically swaps the in-memory cert material and persists to disk
// so that restarts can reload without re-generating or re-requesting.
func (m *Manager) storePEM(cert, key []byte) {
	m.mat.Store(&certMaterial{certPEM: cert, keyPEM: key})
	m.persistPEM(m.Config().CertDir, cert, key)
}

// persistPEM writes cert/key to dir for restart recovery.
// Errors are logged but not returned — persistence is best-effort.
func (m *Manager) persistPEM(dir string, cert, key []byte) {
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
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// loadPersistedPEM loads previously persisted cert material from dir.
func loadPersistedPEM(dir string) (*certMaterial, error) {
	if dir == "" {
		return nil, os.ErrNotExist
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("persisted certificate invalid: %w", err)
	}
	return &certMaterial{certPEM: certPEM, keyPEM: keyPEM}, nil
}

// Reconfigure applies a new cert configuration at runtime (e.g. from panel push).
// Returns true when the PEM material changed (caller should restart kernel).
// A failed preparation leaves the running configuration and material untouched.
func (m *Manager) Reconfigure(ctx context.Context, newCfg config.CertConfig) (bool, error) {
	if newCfg.CertDir == "" {
		newCfg.CertDir = m.Config().CertDir
	}
	prepared, err := m.Prepare(ctx, newCfg, Identity{})
	if err != nil {
		return false, fmt.Errorf("cert reconfigure: %w", err)
	}
	oldTLS := m.TLSCert()
	m.Commit(prepared)
	return !pemEqual(oldTLS, m.TLSCert()), nil
}

// Prepare resolves the certificate material a configuration asks for without
// putting it into use. identity supplies the names a self-signed certificate
// must cover; explicit configuration (cfg.Domain) always comes first.
//
// Errors are returned verbatim for the caller to surface: a missing file,
// invalid PEM content, a failed ACME order or an unknown mode never degrade
// into another mode.
func (m *Manager) Prepare(ctx context.Context, cfg config.CertConfig, identity Identity) (*Prepared, error) {
	if cfg.CertDir == "" {
		cfg.CertDir = m.Config().CertDir
	}
	mode := resolveModeFor(cfg)
	p := &Prepared{cfg: cfg, mode: mode}

	switch mode {
	case "none", "":
		p.mode = "none"
		return p, nil
	case "file":
		mat, err := loadFilePair(cfg)
		if err != nil {
			return nil, err
		}
		p.mat = mat
		return p, nil
	case "content":
		mat, err := loadContentPair(cfg)
		if err != nil {
			return nil, err
		}
		p.mat = mat
		return p, nil
	case "self":
		names := selfSignedNames(cfg, identity)
		mat, generated, err := loadOrGenerateSelfSigned(selfSignedDir(cfg.CertDir), cfg.CertDir, names)
		if err != nil {
			return nil, err
		}
		p.mat = mat
		p.generated = generated
		return p, nil
	case "http":
		return m.prepareACME(ctx, p, nil)
	case "dns":
		solver, err := buildDNSSolver(cfg)
		if err != nil {
			return nil, fmt.Errorf("build dns solver: %w", err)
		}
		return m.prepareACME(ctx, p, solver)
	default:
		return nil, fmt.Errorf("unknown cert_mode: %q (supported: http, dns, self, file, content, none)", mode)
	}
}

// Commit puts prepared material into use. A previously running ACME instance
// is torn down when the prepared material does not come from it.
func (m *Manager) Commit(p *Prepared) {
	if p == nil {
		return
	}
	m.mu.Lock()
	old := m.acme
	switch {
	case p.acme != nil:
		m.acme = p.acme
	case p.reuseACME:
		old = nil
	default:
		m.acme = nil
	}
	m.cfg = p.cfg
	m.mu.Unlock()

	if old != nil && old.cancel != nil {
		old.cancel()
	}
	if p.mat == nil {
		m.mat.Store(nil)
		return
	}
	m.mat.Store(p.mat)
	switch p.mode {
	case "content", "file", "http", "dns":
		// Self-signed material already lives in its own directory.
		m.persistPEM(p.cfg.CertDir, p.mat.certPEM, p.mat.keyPEM)
	}
}

// Discard releases resources held by prepared material that will not be used.
func (m *Manager) Discard(p *Prepared) {
	if p == nil || p.acme == nil || p.acme.cancel == nil {
		return
	}
	p.acme.cancel()
	p.acme = nil
}

// acmeFingerprint produces a stable string capturing every config field that
// requires re-running ACME when changed.
func acmeFingerprint(cfg config.CertConfig) string {
	keys := make([]string, 0, len(cfg.DNSEnv))
	for k := range cfg.DNSEnv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(resolveModeFor(cfg))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(cfg.Domain))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(cfg.Email))
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(cfg.DNSProvider))
	b.WriteByte('|')
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cfg.DNSEnv[k])
		b.WriteByte(';')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// resolveModeFor returns the effective cert mode of cfg, handling backward
// compat for auto_tls and the implicit content / file detection.
func resolveModeFor(cfg config.CertConfig) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.CertMode))
	if mode != "" {
		return mode
	}
	if cfg.AutoTLS {
		return "http"
	}
	if cfg.CertContent != "" && cfg.KeyContent != "" {
		return "content"
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return "file"
	}
	return "none"
}

// ResolveMode returns the effective certificate mode of a configuration.
func ResolveMode(cfg config.CertConfig) string { return resolveModeFor(cfg) }

// IsExplicit reports whether cfg carries any certificate strategy of its own.
// A zero configuration (mode empty, no auto_tls, no files, no content) is not
// explicit and lets the caller apply its default policy.
func IsExplicit(cfg config.CertConfig) bool {
	if strings.TrimSpace(cfg.CertMode) != "" {
		return true
	}
	if cfg.AutoTLS {
		return true
	}
	if cfg.CertContent != "" && cfg.KeyContent != "" {
		return true
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		return true
	}
	return false
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

// Start initializes the cert manager from its own configuration.
func (m *Manager) Start(ctx context.Context) error {
	prepared, err := m.Prepare(ctx, m.Config(), Identity{})
	if err != nil {
		return err
	}
	m.Commit(prepared)
	return nil
}

// Stop cancels a running ACME instance.
func (m *Manager) Stop() {
	m.mu.Lock()
	inst := m.acme
	m.acme = nil
	m.mu.Unlock()
	if inst != nil && inst.cancel != nil {
		inst.cancel()
	}
}

// ─── Mode: file ────────────────────────────────────────────────────────────

func loadFilePair(cfg config.CertConfig) (*certMaterial, error) {
	if strings.TrimSpace(cfg.CertFile) == "" || strings.TrimSpace(cfg.KeyFile) == "" {
		return nil, fmt.Errorf("cert_mode 'file' requires both cert_file and key_file")
	}
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("cert file: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("invalid certificate pair: %w", err)
	}
	nlog.Core().Debug("TLS certificate loaded from files", "cert", cfg.CertFile, "key", cfg.KeyFile)
	return &certMaterial{certPEM: certPEM, keyPEM: keyPEM}, nil
}

// ─── Mode: content ────────────────────────────────────────────────────────

func loadContentPair(cfg config.CertConfig) (*certMaterial, error) {
	if cfg.CertContent == "" || cfg.KeyContent == "" {
		// No fresh content from panel — try previously persisted material.
		if mat, err := loadPersistedPEM(cfg.CertDir); err == nil {
			nlog.Core().Info("cert: loaded persisted certificate from disk", "dir", cfg.CertDir)
			return mat, nil
		}
		return nil, fmt.Errorf("cert_mode 'content' requires both cert_content and key_content")
	}
	certPEM := []byte(cfg.CertContent)
	keyPEM := []byte(cfg.KeyContent)
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("invalid certificate content: %w", err)
	}
	nlog.Core().Info("TLS certificate loaded from panel content (in-memory)")
	return &certMaterial{certPEM: certPEM, keyPEM: keyPEM}, nil
}

// ─── Mode: self ────────────────────────────────────────────────────────────

// selfSignedDir is where generated material lives. It is separate from the
// directory ACME / content material is persisted to so that a fallback load of
// another mode can never pick up a self-signed pair by accident.
func selfSignedDir(certDir string) string {
	if certDir == "" {
		return ""
	}
	return filepath.Join(certDir, "self-signed")
}

// selfSignedNames merges the explicit domain with the target identity, keeping
// order and dropping duplicates and empty values. It never returns an empty
// list.
func selfSignedNames(cfg config.CertConfig, identity Identity) []string {
	var names []string
	seen := map[string]bool{}
	add := func(raw string) {
		name := normalizeName(raw)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	add(cfg.Domain)
	for _, n := range identity.Names {
		add(n)
	}
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	return names
}

func normalizeName(raw string) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(name); err == nil && host != "" {
		name = host
	}
	name = strings.Trim(name, "[]")
	if strings.ContainsAny(name, " \t/\\") {
		return ""
	}
	return name
}

// loadOrGenerateSelfSigned reuses persisted material when it still pairs, is
// not close to expiry and covers every name; otherwise it generates a fresh
// pair and persists it. legacyDir is checked for material written by earlier
// versions (cert.pem beside the ACME storage) so an upgrade does not rotate a
// certificate for nothing.
func loadOrGenerateSelfSigned(dir, legacyDir string, names []string) (*certMaterial, bool, error) {
	for _, candidate := range []string{dir, legacyDir} {
		if candidate == "" {
			continue
		}
		mat, err := loadPersistedPEM(candidate)
		if err != nil {
			continue
		}
		if reason := selfSignedReusable(mat, names); reason != "" {
			nlog.Core().Info("cert: self-signed certificate will be regenerated", "dir", candidate, "reason", reason)
			continue
		}
		if candidate != dir && dir != "" {
			// Migrate legacy material into the dedicated directory.
			persistSelfSigned(dir, mat)
		}
		nlog.Core().Info("cert: reusing persisted self-signed certificate", "dir", candidate, "names", strings.Join(names, ","))
		return mat, false, nil
	}

	mat, err := generateSelfSigned(names)
	if err != nil {
		return nil, false, err
	}
	if dir != "" {
		if err := persistSelfSigned(dir, mat); err != nil {
			return nil, false, err
		}
	}
	nlog.Core().Info("self-signed certificate generated", "names", strings.Join(names, ","), "valid_years", 10)
	return mat, true, nil
}

func persistSelfSigned(dir string, mat *certMaterial) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create self-signed dir: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(dir, "key.pem"), mat.keyPEM, 0o600); err != nil {
		return fmt.Errorf("persist self-signed key: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(dir, "cert.pem"), mat.certPEM, 0o644); err != nil {
		return fmt.Errorf("persist self-signed cert: %w", err)
	}
	return nil
}

// selfSignedReusable returns an empty string when mat can keep serving names,
// otherwise the reason it cannot.
func selfSignedReusable(mat *certMaterial, names []string) string {
	block, _ := pem.Decode(mat.certPEM)
	if block == nil {
		return "certificate is not PEM"
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "certificate does not parse"
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return "certificate is not yet valid"
	}
	if now.Add(selfSignedRenewBefore).After(leaf.NotAfter) {
		return "certificate is expired or expires soon"
	}
	for _, name := range names {
		if !certificateCovers(leaf, name) {
			return fmt.Sprintf("certificate does not cover %q", name)
		}
	}
	return ""
}

func certificateCovers(leaf *x509.Certificate, name string) bool {
	if ip := net.ParseIP(name); ip != nil {
		for _, candidate := range leaf.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, dns := range leaf.DNSNames {
		if strings.EqualFold(dns, name) {
			return true
		}
	}
	return false
}

func generateSelfSigned(names []string) (*certMaterial, error) {
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(selfSignedValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &certMaterial{certPEM: certPEM, keyPEM: keyPEM}, nil
}

// ─── Mode: http / dns (ACME) ──────────────────────────────────────────────

// prepareACME reuses the running ACME instance when the configuration is
// unchanged and material is loaded; otherwise it orders a certificate into a
// new certmagic instance that the caller commits or discards.
func (m *Manager) prepareACME(ctx context.Context, p *Prepared, dnsSolver *certmagic.DNS01Solver) (*Prepared, error) {
	cfg := p.cfg
	if cfg.Domain == "" {
		return nil, fmt.Errorf("cert.domain is required for ACME modes (http/dns)")
	}
	fingerprint := acmeFingerprint(cfg)

	m.mu.Lock()
	current := m.acme
	m.mu.Unlock()
	if current != nil && current.fingerprint == fingerprint {
		if mat := m.mat.Load(); mat != nil {
			p.mat = mat
			p.reuseACME = true
			return p, nil
		}
	}

	if err := os.MkdirAll(cfg.CertDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	storage := &certmagic.FileStorage{Path: cfg.CertDir}

	inst := &acmeInstance{storage: storage, domain: cfg.Domain, fingerprint: fingerprint}

	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(_ certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	magic = certmagic.New(cache, certmagic.Config{
		Storage: storage,
		OnEvent: func(evtCtx context.Context, event string, data map[string]any) error {
			// Only react to renewals; initial load happens explicitly after ObtainCertSync.
			if event != "cert_obtained" {
				return nil
			}
			if renewed, _ := data["renewal"].(bool); !renewed {
				return nil
			}
			issuerKey, _ := data["issuer"].(string)
			if issuerKey == "" {
				return nil
			}
			m.onACMERenewal(evtCtx, inst, issuerKey)
			return nil
		},
	})

	issuer := certmagic.ACMEIssuer{
		CA:    certmagic.LetsEncryptProductionCA,
		Email: cfg.Email,
	}
	if dnsSolver != nil {
		// DNS-01 mode: no HTTP port needed, supports wildcards.
		issuer.DNS01Solver = dnsSolver
		issuer.DisableHTTPChallenge = true
		issuer.DisableTLSALPNChallenge = true
	} else {
		// HTTP-01 mode.
		httpPort := cfg.HTTPPort
		if httpPort == 0 {
			httpPort = 80
		}
		issuer.AltHTTPPort = httpPort
		issuer.DisableTLSALPNChallenge = true
	}
	magic.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(magic, issuer)}
	inst.magic = magic
	inst.issuerKey = magic.Issuers[0].IssuerKey()

	// Derived ctx so Commit / Discard can cancel ACME background goroutines.
	acmeCtx, acmeCancel := context.WithCancel(ctx)
	inst.cancel = acmeCancel

	if err := magic.ObtainCertSync(acmeCtx, cfg.Domain); err != nil {
		acmeCancel()
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}
	mat, err := loadPEMFromStorage(acmeCtx, storage, inst.issuerKey, cfg.Domain)
	if err != nil {
		acmeCancel()
		return nil, fmt.Errorf("load cert from storage: %w", err)
	}
	if err := magic.ManageAsync(acmeCtx, []string{cfg.Domain}); err != nil {
		acmeCancel()
		return nil, fmt.Errorf("start cert manager: %w", err)
	}
	p.mat = mat
	p.acme = inst
	return p, nil
}

// onACMERenewal reloads renewed material, but only for the instance that is
// still in use: a renewal fired by a torn-down instance must not overwrite
// the material of its successor.
func (m *Manager) onACMERenewal(ctx context.Context, inst *acmeInstance, issuerKey string) {
	m.mu.Lock()
	active := m.acme == inst
	dir := m.cfg.CertDir
	m.mu.Unlock()
	if !active {
		return
	}
	mat, err := loadPEMFromStorage(ctx, inst.storage, issuerKey, inst.domain)
	if err != nil {
		nlog.Core().Error("failed to reload cert after renewal", "error", err)
		return
	}
	m.mat.Store(mat)
	m.persistPEM(dir, mat.certPEM, mat.keyPEM)
	m.renewed.Store(true)
	nlog.Core().Info("TLS certificate reloaded after renewal", "domain", inst.domain)
}

func validateKeyPair(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return err
	}
	return nil
}

// ─── DNS Provider Factory ──────────────────────────────────────────────────

// buildDNSSolver builds a certmagic DNS01Solver from the configured provider.
func buildDNSSolver(cfg config.CertConfig) (*certmagic.DNS01Solver, error) {
	provider, err := newDNSProvider(cfg)
	if err != nil {
		return nil, err
	}
	return &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: provider}}, nil
}

func newDNSProvider(cfg config.CertConfig) (certmagic.DNSProvider, error) {
	name := strings.TrimSpace(cfg.DNSProvider)
	if name == "" {
		return nil, fmt.Errorf("dns_provider is required for cert_mode=dns")
	}
	env := cfg.DNSEnv
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

// loadPEMFromStorage reads cert + key for domain from certmagic storage.
func loadPEMFromStorage(ctx context.Context, storage certmagic.Storage, issuerKey, domain string) (*certMaterial, error) {
	if issuerKey == "" || domain == "" {
		return nil, fmt.Errorf("loadPEMFromStorage: issuerKey and domain are required")
	}
	certKey := certmagic.StorageKeys.SiteCert(issuerKey, domain)
	keyKey := certmagic.StorageKeys.SitePrivateKey(issuerKey, domain)

	certPEM, err := storage.Load(ctx, certKey)
	if err != nil {
		return nil, fmt.Errorf("load cert %q: %w", certKey, err)
	}
	keyPEM, err := storage.Load(ctx, keyKey)
	if err != nil {
		return nil, fmt.Errorf("load key %q: %w", keyKey, err)
	}
	if err := validateKeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("invalid cert/key pair on disk: %w", err)
	}
	return &certMaterial{certPEM: certPEM, keyPEM: keyPEM}, nil
}

// loadPEMFromStorage loads storage material into the manager. It is the single
// entry point tests use for the warm-restart and renewal-refresh scenarios.
func (m *Manager) loadPEMFromStorage(ctx context.Context, storage certmagic.Storage, issuerKey, domain string) error {
	mat, err := loadPEMFromStorage(ctx, storage, issuerKey, domain)
	if err != nil {
		return err
	}
	m.storePEM(mat.certPEM, mat.keyPEM)
	return nil
}
