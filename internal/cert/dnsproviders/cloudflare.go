package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

func init() {
	Register(&Provider{
		Names:   []string{"cloudflare", "cf"},
		EnvVars: []string{"CLOUDFLARE_DNS_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "CLOUDFLARE_DNS_API_TOKEN", "CF_API_TOKEN", "CLOUDFLARE_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("cloudflare", "CLOUDFLARE_DNS_API_TOKEN", "CF_API_TOKEN")
			}
			return &cloudflare.Provider{APIToken: token}, nil
		},
	})
}
