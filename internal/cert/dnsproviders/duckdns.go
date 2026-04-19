package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
)

func init() {
	Register(&Provider{
		Names:   []string{"duckdns"},
		EnvVars: []string{"DUCKDNS_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "DUCKDNS_TOKEN", "DUCKDNS_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("duckdns", "DUCKDNS_TOKEN")
			}
			return &duckdns.Provider{
				APIToken:       token,
				OverrideDomain: firstOf(env, "DUCKDNS_OVERRIDE_DOMAIN"),
			}, nil
		},
	})
}
