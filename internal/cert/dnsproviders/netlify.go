package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/netlify"
)

func init() {
	Register(&Provider{
		Names:   []string{"netlify"},
		EnvVars: []string{"NETLIFY_PERSONAL_ACCESS_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "NETLIFY_PERSONAL_ACCESS_TOKEN", "NETLIFY_AUTH_TOKEN", "NETLIFY_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("netlify", "NETLIFY_PERSONAL_ACCESS_TOKEN")
			}
			return &netlify.Provider{PersonalAccessToken: token}, nil
		},
	})
}
