package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/bunny"
)

func init() {
	Register(&Provider{
		Names:   []string{"bunny"},
		EnvVars: []string{"BUNNY_ACCESS_KEY"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			key := firstOf(env, "BUNNY_ACCESS_KEY", "BUNNY_API_KEY")
			if key == "" {
				return nil, missingEnvErr("bunny", "BUNNY_ACCESS_KEY")
			}
			return &bunny.Provider{AccessKey: key}, nil
		},
	})
}
