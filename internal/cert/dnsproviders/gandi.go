package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/gandi"
)

func init() {
	Register(&Provider{
		Names:   []string{"gandi"},
		EnvVars: []string{"GANDI_BEARER_TOKEN", "GANDI_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "GANDI_BEARER_TOKEN", "GANDI_API_TOKEN", "GANDI_PERSONAL_ACCESS_TOKEN")
			if token == "" {
				return nil, missingEnvErr("gandi", "GANDI_BEARER_TOKEN")
			}
			return &gandi.Provider{BearerToken: token}, nil
		},
	})
}
