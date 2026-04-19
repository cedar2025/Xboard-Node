package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/hetzner"
)

func init() {
	Register(&Provider{
		Names:   []string{"hetzner"},
		EnvVars: []string{"HETZNER_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "HETZNER_API_TOKEN", "HETZNER_DNS_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("hetzner", "HETZNER_API_TOKEN")
			}
			return &hetzner.Provider{AuthAPIToken: token}, nil
		},
	})
}
