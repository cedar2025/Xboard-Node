package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/ovh"
)

func init() {
	Register(&Provider{
		Names: []string{"ovh"},
		EnvVars: []string{
			"OVH_ENDPOINT", "OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY",
		},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			appKey := firstOf(env, "OVH_APPLICATION_KEY")
			appSecret := firstOf(env, "OVH_APPLICATION_SECRET")
			consumerKey := firstOf(env, "OVH_CONSUMER_KEY")
			if appKey == "" || appSecret == "" || consumerKey == "" {
				return nil, missingEnvErr("ovh", "OVH_APPLICATION_KEY", "OVH_APPLICATION_SECRET", "OVH_CONSUMER_KEY")
			}
			return &ovh.Provider{
				Endpoint:          firstOf(env, "OVH_ENDPOINT"),
				ApplicationKey:    appKey,
				ApplicationSecret: appSecret,
				ConsumerKey:       consumerKey,
			}, nil
		},
	})
}
