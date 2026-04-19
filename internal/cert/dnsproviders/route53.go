package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/route53"
)

func init() {
	Register(&Provider{
		Names:   []string{"route53", "aws"},
		EnvVars: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "AWS_SESSION_TOKEN", "AWS_HOSTED_ZONE_ID", "AWS_PROFILE"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			// route53 supports the full AWS credential chain (env, IAM role, profile,
			// shared credentials file). We deliberately do not require any field —
			// users running on EC2/EKS may rely entirely on the instance role.
			return &route53.Provider{
				AccessKeyId:     firstOf(env, "AWS_ACCESS_KEY_ID"),
				SecretAccessKey: firstOf(env, "AWS_SECRET_ACCESS_KEY"),
				SessionToken:    firstOf(env, "AWS_SESSION_TOKEN"),
				Region:          firstOf(env, "AWS_REGION", "AWS_DEFAULT_REGION"),
				Profile:         firstOf(env, "AWS_PROFILE"),
				HostedZoneID:    firstOf(env, "AWS_HOSTED_ZONE_ID"),
			}, nil
		},
	})
}
