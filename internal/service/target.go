package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cedar2025/xboard-node/internal/cert"
	"github.com/cedar2025/xboard-node/internal/cert/dnsproviders"
	"github.com/cedar2025/xboard-node/internal/config"
	"github.com/cedar2025/xboard-node/internal/kernel"
	"github.com/cedar2025/xboard-node/internal/model"
)

// certSource says where the certificate strategy of a target came from.
type certSource string

const (
	// certSourceNone: the target does not use a certificate.
	certSourceNone certSource = "none"
	// certSourcePanel: the panel sent an explicit cert_config (or the
	// deprecated auto_tls flag).
	certSourcePanel certSource = "panel"
	// certSourceLocal: config.yml carries an explicit cert section and the
	// panel sent none.
	certSourceLocal certSource = "local"
	// certSourceAuto: nobody configured a certificate, the protocol cannot run
	// without one, and the node is panel managed, so a self-signed certificate
	// is prepared automatically.
	certSourceAuto certSource = "auto-self"
)

// certPlan is the certificate decision for one target.
type certPlan struct {
	Source      certSource
	Requirement model.TLSRequirement
	// Config is the configuration handed to the certificate manager when
	// Prepare is true.
	Config config.CertConfig
	Mode   string
	// Names is the identity a self-signed certificate must cover.
	Names []string
	// Prepare is true when the certificate manager must be consulted.
	Prepare bool
}

// preparedTarget is a target that passed every check and whose certificate
// material is ready, but that has not been applied yet.
type preparedTarget struct {
	spec         *model.NodeSpec
	users        []model.UserSpec
	kernelType   string
	kernelReason string
	plan         certPlan
	cert         *cert.Prepared
	tls          kernel.TLSCert
	configHash   string
	warnings     []string
}

// prepareTarget runs the kernel-independent part of the apply pipeline:
//
//	clone snapshot → validate shape → select kernel → resolve cert policy
//	→ prepare certificate → validate the complete runtime config.
//
// Nothing here touches a running instance or the certificate in use, so a
// failure leaves the node exactly as it was.
func (s *Service) prepareTarget(ctx context.Context, spec *model.NodeSpec, users []model.UserSpec) (*preparedTarget, error) {
	if spec == nil {
		return nil, fmt.Errorf("node config is nil")
	}
	snapshot := model.CloneNodeSpec(spec)
	kcfg := s.cfg.Kernel
	if err := model.ValidateNodeSpecShape(snapshot, kcfg); err != nil {
		return nil, fmt.Errorf("invalid node config: %w", err)
	}

	selection, err := model.SelectKernel(snapshot, s.preferredKernel, kcfg)
	if err != nil {
		return nil, err
	}

	plan, err := resolveCertPlan(snapshot, selection.TLS, s.cfg.Cert, s.managed())
	if err != nil {
		return nil, err
	}
	if plan.Source == certSourceAuto {
		// Legacy nodes: entries can inherit a shared cert_dir. Automatic
		// material must not overwrite another node/panel's certificate.
		plan.Config.CertDir = autoCertificateDir(s.cfg)
	}

	target := &preparedTarget{
		spec:         snapshot,
		users:        model.CloneUserSpecs(users),
		kernelType:   selection.Kernel,
		kernelReason: selection.Reason,
		plan:         plan,
		// The hash describes the snapshot that is validated, applied and
		// recorded as the applied state, never the caller's object.
		configHash: computeConfigHash(snapshot),
	}
	if selection.Reason != "" {
		target.warnings = append(target.warnings, fmt.Sprintf("kernel %s selected instead of preferred %s: %s", selection.Kernel, s.preferredKernel, selection.Reason))
	}

	if plan.Prepare {
		prepared, err := s.cert.Prepare(ctx, plan.Config, cert.Identity{Names: plan.Names})
		if err != nil {
			return nil, fmt.Errorf("certificate (%s, mode %s): %w", plan.Source, plan.Mode, err)
		}
		target.cert = prepared
		target.tls = prepared.TLSCert()
		if plan.Requirement.NeedsCertificate() && !target.tls.HasCert() {
			s.cert.Discard(prepared)
			return nil, fmt.Errorf("certificate (%s, mode %s) produced no material for protocol %q", plan.Source, plan.Mode, snapshot.Protocol)
		}
	} else {
		// Commit an explicit inactive certificate state after a successful
		// switch to plaintext/REALITY, so an old ACME task is cancelled too.
		prepared, err := s.cert.Prepare(ctx, config.CertConfig{CertMode: "none", CertDir: s.cfg.Cert.CertDir}, cert.Identity{})
		if err != nil {
			return nil, err
		}
		target.cert = prepared
	}

	k := s.kernelFor(selection.Kernel)
	if err := k.Validate(snapshot, target.users, target.tls); err != nil {
		s.cert.Discard(target.cert)
		return nil, fmt.Errorf("kernel %s rejected the target config: %w", selection.Kernel, err)
	}
	return target, nil
}

// managed reports whether the panel owns this node's configuration. Only
// managed nodes get the default certificate policy; a standalone node keeps
// the explicit contract of its config file.
func (s *Service) managed() bool {
	return s.cfg != nil && !s.cfg.IsStandalone()
}

func autoCertificateDir(cfg *config.Config) string {
	base := cfg.Cert.CertDir
	if base == "" {
		base = filepath.Join(cfg.Kernel.ConfigDir, "certs")
	}
	identity := fmt.Sprintf("%s\n%d", strings.TrimRight(cfg.Panel.URL, "/"), cfg.Panel.NodeID)
	digest := sha256.Sum256([]byte(identity))
	return filepath.Join(base, fmt.Sprintf("managed-%x", digest[:16]))
}

// resolveCertPlan decides how the certificate for a target is obtained.
//
// Priority:
//  1. an explicit panel cert_config (any mode, including "none");
//  2. an explicit local cert section in config.yml;
//  3. the default policy: a self-signed certificate whenever the managed
//     target requires TLS; an explicit-configuration error for standalone nodes.
//
// An explicit configuration is never downgraded: a broken file, missing
// content, a failed ACME order or an unknown mode is returned as an error.
func resolveCertPlan(spec *model.NodeSpec, requirement model.TLSRequirement, local config.CertConfig, managed bool) (certPlan, error) {
	plan := certPlan{Source: certSourceNone, Requirement: requirement, Mode: "none"}
	switch requirement {
	case model.TLSNotUsed, model.TLSOff:
		// No TLS layer on the wire: certificate configuration, explicit or
		// not, is irrelevant and no issuance is started.
		return plan, nil
	case model.TLSReality:
		if err := model.ValidateRealitySettings(spec); err != nil {
			return plan, err
		}
		plan.Mode = "reality"
		return plan, nil
	case model.TLSRequired, model.TLSRequested:
	default:
		return plan, fmt.Errorf("unknown tls requirement %q", requirement)
	}

	effective, source := effectiveCertConfig(spec, local)
	if source != certSourceNone {
		mode := cert.ResolveMode(effective)
		switch mode {
		case "none":
			return plan, fmt.Errorf("protocol %q requires a TLS certificate but the %s cert config disables certificate management (cert_mode none); choose self, file, content, http or dns", spec.Protocol, source)
		case "self":
			plan.Names = identityNames(spec)
		case "file", "content":
		case "http", "dns":
			if strings.TrimSpace(effective.Domain) == "" {
				return plan, fmt.Errorf("%s cert config mode %s requires cert_config.domain", source, mode)
			}
			if mode == "dns" {
				if err := validateDNSProvider(effective); err != nil {
					return plan, err
				}
			}
		default:
			return plan, fmt.Errorf("%s cert config has unknown cert_mode %q (supported: http, dns, self, file, content, none)", source, mode)
		}
		plan.Source = source
		plan.Config = effective
		plan.Mode = mode
		plan.Prepare = true
		return plan, nil
	}

	if !managed {
		return plan, fmt.Errorf("protocol %q requires a TLS certificate; set cert.cert_mode (self, file, content, http or dns) in config.yml", spec.Protocol)
	}
	plan.Source = certSourceAuto
	plan.Mode = "self"
	plan.Config = config.CertConfig{CertMode: "self", CertDir: local.CertDir}
	plan.Names = identityNames(spec)
	plan.Prepare = true
	return plan, nil
}

// effectiveCertConfig merges the panel's explicit certificate configuration
// with the local one and reports which of them is in charge. The local
// configuration is the original config.yml section: a previous runtime
// override is never inherited once the panel stops sending it.
func effectiveCertConfig(spec *model.NodeSpec, local config.CertConfig) (config.CertConfig, certSource) {
	if spec.CertConfig != nil {
		effective := *spec.CertConfig
		effective.CertDir = local.CertDir
		if effective.HTTPPort == 0 {
			effective.HTTPPort = local.HTTPPort
		}
		return effective, certSourcePanel
	}
	derived := local
	source := certSourceLocal
	if spec.AutoTLS {
		// Deprecated panel field: auto_tls has always meant ACME HTTP-01.
		derived.AutoTLS = true
		source = certSourcePanel
	}
	if strings.TrimSpace(spec.Domain) != "" {
		derived.Domain = spec.Domain
	}
	if cert.IsExplicit(derived) {
		return derived, source
	}
	return config.CertConfig{CertDir: local.CertDir, HTTPPort: local.HTTPPort}, certSourceNone
}

func validateDNSProvider(cfg config.CertConfig) error {
	provider := strings.TrimSpace(cfg.DNSProvider)
	if provider == "" {
		return fmt.Errorf("dns cert mode requires cert_config.dns_provider")
	}
	if _, ok := dnsproviders.Get(provider); !ok {
		return fmt.Errorf("unsupported cert_config.dns_provider %q (supported: %s)", provider, strings.Join(dnsproviders.CanonicalNames(), ", "))
	}
	return nil
}

// identityNames lists the names a certificate for spec must cover, in the
// order the kernel resolves the served name: tls_settings.server_name, the
// server_name field, then host. Names are host names or IP literals; ports
// and blanks are stripped.
func identityNames(spec *model.NodeSpec) []string {
	var names []string
	seen := map[string]bool{}
	add := func(raw string) {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			return
		}
		if host, _, err := splitHostPortLenient(name); err == nil && host != "" {
			name = host
		}
		name = strings.Trim(name, "[]")
		if name == "" || strings.ContainsAny(name, " \t/\\") || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	if spec.TLSSettings != nil {
		if v, ok := spec.TLSSettings["server_name"].(string); ok {
			add(v)
		}
	}
	add(spec.ServerName)
	add(spec.Host)
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	return names
}

// splitHostPortLenient splits host:port but leaves bare IPv6 literals and
// plain host names untouched.
func splitHostPortLenient(value string) (string, string, error) {
	if strings.Count(value, ":") > 1 && !strings.HasPrefix(value, "[") {
		return value, "", nil
	}
	if !strings.Contains(value, ":") {
		return value, "", nil
	}
	idx := strings.LastIndex(value, ":")
	return value[:idx], value[idx+1:], nil
}
