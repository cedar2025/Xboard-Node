package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/namecheap"
)

func init() {
	Register(&Provider{
		Names:   []string{"namecheap"},
		EnvVars: []string{"NAMECHEAP_API_KEY", "NAMECHEAP_API_USER", "NAMECHEAP_CLIENT_IP"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			apiKey := firstOf(env, "NAMECHEAP_API_KEY")
			user := firstOf(env, "NAMECHEAP_API_USER", "NAMECHEAP_USER")
			if apiKey == "" || user == "" {
				return nil, missingEnvErr("namecheap", "NAMECHEAP_API_KEY", "NAMECHEAP_API_USER")
			}
			return &namecheap.Provider{
				APIKey:      apiKey,
				User:        user,
				APIEndpoint: firstOf(env, "NAMECHEAP_API_ENDPOINT"),
				ClientIP:    firstOf(env, "NAMECHEAP_CLIENT_IP"),
			}, nil
		},
	})
}
