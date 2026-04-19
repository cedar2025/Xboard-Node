package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/vultr/v2"
)

func init() {
	Register(&Provider{
		Names:   []string{"vultr"},
		EnvVars: []string{"VULTR_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "VULTR_API_TOKEN", "VULTR_API_KEY")
			if token == "" {
				return nil, missingEnvErr("vultr", "VULTR_API_TOKEN")
			}
			return &vultr.Provider{APIToken: token}, nil
		},
	})
}
