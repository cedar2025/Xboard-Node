package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/godaddy"
)

func init() {
	Register(&Provider{
		Names:   []string{"godaddy"},
		EnvVars: []string{"GODADDY_API_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			// GoDaddy auth header format: "sso-key KEY:SECRET"
			// Pass the full "KEY:SECRET" pair via GODADDY_API_TOKEN, OR set
			// GODADDY_API_KEY + GODADDY_API_SECRET and we'll join them.
			token := firstOf(env, "GODADDY_API_TOKEN")
			if token == "" {
				key := firstOf(env, "GODADDY_API_KEY")
				secret := firstOf(env, "GODADDY_API_SECRET")
				if key != "" && secret != "" {
					token = key + ":" + secret
				}
			}
			if token == "" {
				return nil, missingEnvErr("godaddy", "GODADDY_API_TOKEN", "GODADDY_API_KEY+GODADDY_API_SECRET")
			}
			return &godaddy.Provider{APIToken: token}, nil
		},
	})
}
