package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/digitalocean"
)

func init() {
	Register(&Provider{
		Names:   []string{"digitalocean", "do"},
		EnvVars: []string{"DO_AUTH_TOKEN", "DIGITALOCEAN_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "DO_AUTH_TOKEN", "DIGITALOCEAN_TOKEN", "DIGITALOCEAN_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("digitalocean", "DO_AUTH_TOKEN")
			}
			return &digitalocean.Provider{APIToken: token}, nil
		},
	})
}
