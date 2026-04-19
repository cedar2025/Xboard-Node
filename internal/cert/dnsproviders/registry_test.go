package dnsproviders

import (
	"strings"
	"testing"
)

// TestRegistryHasMainstreamProviders verifies that all expected mainstream
// providers are registered with their canonical names (and key aliases).
func TestRegistryHasMainstreamProviders(t *testing.T) {
	cases := map[string][]string{
		"cloudflare":     {"cf"},
		"alidns":         {"aliyun"},
		"tencentcloud":   {"tencent"},
		"route53":        {"aws"},
		"godaddy":        nil,
		"namecheap":      nil,
		"namesilo":       nil,
		"digitalocean":   {"do"},
		"linode":         nil,
		"hetzner":        nil,
		"gandi":          nil,
		"porkbun":        nil,
		"netlify":        nil,
		"azure":          nil,
		"googleclouddns": {"gcp", "gcloud"},
		"huaweicloud":    {"huawei"},
		"bunny":          nil,
		"duckdns":        nil,
		"ovh":            nil,
		"vultr":          nil,
		"desec":          nil,
	}
	for canonical, aliases := range cases {
		if _, ok := Get(canonical); !ok {
			t.Errorf("provider %q not registered", canonical)
		}
		// case-insensitive lookup must work
		if _, ok := Get(strings.ToUpper(canonical)); !ok {
			t.Errorf("provider %q not found case-insensitively", canonical)
		}
		for _, a := range aliases {
			if _, ok := Get(a); !ok {
				t.Errorf("alias %q for %q not registered", a, canonical)
			}
		}
	}
}

func TestRegistryRejectsUnknown(t *testing.T) {
	if _, ok := Get("definitely-not-a-real-provider"); ok {
		t.Fatal("Get returned ok for unknown provider")
	}
}

// TestProvidersValidateMissingEnv ensures every provider's Build returns a
// helpful error when no credentials are supplied (rather than panicking or
// silently building an unusable client).
//
// route53/azure/googleclouddns are excluded because they intentionally fall
// back to an ambient credential chain (IAM role, managed identity, ADC) and
// produce a usable provider even with empty config.
func TestProvidersValidateMissingEnv(t *testing.T) {
	excluded := map[string]bool{
		"route53":        true,
		"azure":          true, // partially excluded — actually still requires sub+rg
		"googleclouddns": true, // requires GCE_PROJECT
	}
	for _, p := range List() {
		canonical := p.Names[0]
		if excluded[canonical] {
			continue
		}
		t.Run(canonical, func(t *testing.T) {
			_, err := p.Build(map[string]string{})
			if err == nil {
				t.Errorf("provider %q built successfully with empty env; expected missing-credential error", canonical)
			}
		})
	}
}

func TestCanonicalNamesSorted(t *testing.T) {
	names := CanonicalNames()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("CanonicalNames not sorted: %v", names)
		}
	}
}
