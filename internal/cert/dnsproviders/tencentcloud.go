package dnsproviders

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/tencentcloud"
)

func init() {
	Register(&Provider{
		Names:   []string{"tencentcloud", "tencent"},
		EnvVars: []string{"TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_REGION"},
		Build: func(env map[string]string) (certmagic.DNSProvider, error) {
			id := firstOf(env, "TENCENTCLOUD_SECRET_ID", "TENCENT_SECRET_ID")
			key := firstOf(env, "TENCENTCLOUD_SECRET_KEY", "TENCENT_SECRET_KEY")
			if id == "" || key == "" {
				return nil, missingEnvErr("tencentcloud", "TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY")
			}
			return &tencentcloud.Provider{
				SecretId:  id,
				SecretKey: key,
				Region:    firstOf(env, "TENCENTCLOUD_REGION"),
			}, nil
		},
	})
}
