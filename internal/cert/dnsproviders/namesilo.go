package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/namesilo"
)

func init() {
	Register(&Provider{
		Names:   []string{"namesilo"},
		EnvVars: []string{"NAMESILO_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "NAMESILO_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("namesilo", "NAMESILO_API_TOKEN")
			}
			return &namesilo.Provider{APIToken: token}, nil
		},
	})
}
