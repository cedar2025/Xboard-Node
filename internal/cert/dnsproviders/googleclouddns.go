package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/googleclouddns"
)

func init() {
	Register(&Provider{
		Names:   []string{"googleclouddns", "gcp", "gcloud"},
		EnvVars: []string{"GCE_PROJECT", "GCE_SERVICE_ACCOUNT_FILE"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			project := firstOf(env, "GCE_PROJECT", "GOOGLE_PROJECT_ID", "GCP_PROJECT")
			if project == "" {
				return nil, missingEnvErr("googleclouddns", "GCE_PROJECT")
			}
			// ServiceAccountJSON may be a file path OR a raw JSON blob; when
			// empty, the default Google credential chain is used.
			return &googleclouddns.Provider{
				Project:            project,
				ServiceAccountJSON: firstOf(env, "GCE_SERVICE_ACCOUNT_FILE", "GOOGLE_APPLICATION_CREDENTIALS"),
			}, nil
		},
	})
}
