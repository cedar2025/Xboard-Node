package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/linode"
)

func init() {
	Register(&Provider{
		Names:   []string{"linode"},
		EnvVars: []string{"LINODE_TOKEN"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			token := firstOf(env, "LINODE_TOKEN", "LINODE_API_TOKEN")
			if token == "" {
				return nil, missingEnvErr("linode", "LINODE_TOKEN")
			}
			return &linode.Provider{APIToken: token}, nil
		},
	})
}
