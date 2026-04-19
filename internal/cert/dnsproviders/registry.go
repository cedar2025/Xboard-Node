// Package dnsproviders is a registry of DNS providers usable for ACME DNS-01
// challenges. Each provider is implemented as a separate file that registers
// itself in init(); to add a new provider, drop a file in this package — no
// changes are needed elsewhere.
//
// All providers wrap the libdns ecosystem (https://github.com/libdns) so they
// plug directly into certmagic's DNSManager.
package dnsproviders

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
)

// Builder constructs a certmagic.DNSProvider from a flat env-style map.
// The map mirrors the cert_config.dns_env block from config.yml.
type Builder func(env map[string]string) (certmagic.DNSProvider, error)

// Provider describes a single DNS provider entry in the registry.
type Provider struct {
	// Names is the list of accepted dns_provider values; the first is canonical,
	// the rest are aliases (case-insensitive match).
	Names []string
	// EnvVars lists the environment variable names this provider may consume.
	// Used for documentation and error messages only.
	EnvVars []string
	// Build constructs the underlying libdns provider.
	Build Builder
}

var (
	mu       sync.RWMutex
	registry = map[string]*Provider{}
	ordered  []*Provider
)

// Register adds a provider to the global registry. It panics on duplicate
// names so that registration errors surface at process start.
func Register(p *Provider) {
	if p == nil || len(p.Names) == 0 || p.Build == nil {
		panic("dnsproviders: invalid provider registration")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, n := range p.Names {
		key := strings.ToLower(strings.TrimSpace(n))
		if key == "" {
			panic("dnsproviders: empty provider name")
		}
		if _, exists := registry[key]; exists {
			panic(fmt.Sprintf("dnsproviders: duplicate name %q", key))
		}
		registry[key] = p
	}
	ordered = append(ordered, p)
}

// Get returns the provider registered under the given (case-insensitive) name
// or alias.
func Get(name string) (*Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// CanonicalNames returns the canonical (first-listed) name of every registered
// provider, sorted alphabetically. Useful for error messages.
func CanonicalNames() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(ordered))
	for _, p := range ordered {
		names = append(names, p.Names[0])
	}
	sort.Strings(names)
	return names
}

// List returns all registered providers (canonical entries only), sorted by
// canonical name.
func List() []*Provider {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]*Provider, len(ordered))
	copy(out, ordered)
	sort.Slice(out, func(i, j int) bool { return out[i].Names[0] < out[j].Names[0] })
	return out
}
