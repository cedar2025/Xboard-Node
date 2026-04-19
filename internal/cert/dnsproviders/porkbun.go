package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/porkbun"
)

func init() {
	Register(&Provider{
		Names:   []string{"porkbun"},
		EnvVars: []string{"PORKBUN_API_KEY", "PORKBUN_API_SECRET_KEY"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			key := firstOf(env, "PORKBUN_API_KEY")
			secret := firstOf(env, "PORKBUN_API_SECRET_KEY", "PORKBUN_SECRET_API_KEY")
			if key == "" || secret == "" {
				return nil, missingEnvErr("porkbun", "PORKBUN_API_KEY", "PORKBUN_API_SECRET_KEY")
			}
			return &porkbun.Provider{APIKey: key, APISecretKey: secret}, nil
		},
	})
}
