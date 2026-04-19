package dnsproviders

import (
	"fmt"
	"strings"
)

// firstOf returns the value of the first non-empty env key from candidates.
// Lookup is case-sensitive (env keys are conventionally upper-case).
func firstOf(env map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(env[k]); v != "" {
			return v
		}
	}
	return ""
}

// missingEnvErr formats a "missing required env" error consistently.
func missingEnvErr(provider string, keys ...string) error {
	return fmt.Errorf("dns provider %q requires one of %s in dns_env", provider, strings.Join(keys, ", "))
}
