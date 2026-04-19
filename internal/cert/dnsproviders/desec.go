package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/desec"
)

func init() {
	Register(&Provider{
		Names:   []string{"desec"},
		EnvVars: []string{"DESEC_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "DESEC_TOKEN", "DESEC_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("desec", "DESEC_TOKEN")
			}
			return &desec.Provider{Token: token}, nil
		},
	})
}
